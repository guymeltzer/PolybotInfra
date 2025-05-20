#!/bin/bash

# Define log file
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Add error handling
set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> ${LOGFILE}; exit 1' ERR

# Set up SSH access (using your existing key).
echo "$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp
EOF
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Set non-interactive frontend
export DEBIAN_FRONTEND=noninteractive

# Update package lists
echo "$(date) - Updating package lists"
apt-get update
echo "$(date) - Fixing package manager state"
apt-get install -f -y
dpkg --configure -a

# Install necessary packages
echo "$(date) - Installing base packages"
apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg jq unzip

# Validate unzip installation
command -v unzip

# Configure kernel modules for Kubernetes
echo "$(date) - Configuring kernel modules"
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

# Set up required sysctl parameters
echo "$(date) - Setting sysctl parameters"
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system

# Install containerd
echo "$(date) - Installing containerd"
apt-get update
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# Install Kubernetes packages
echo "$(date) - Installing Kubernetes packages"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y kubeadm kubelet kubectl
apt-mark hold kubeadm kubelet kubectl

# Disable swap
echo "$(date) - Disabling swap"
swapoff -a
sed -i '/swap/d' /etc/fstab

# Set up hostname
HOSTNAME="guy-control-plane"
hostnamectl set-hostname $HOSTNAME
echo "127.0.0.1 $HOSTNAME" >> /etc/hosts

# Initialize Kubernetes cluster
echo "$(date) - Initializing Kubernetes cluster"
kubeadm init --pod-network-cidr=192.168.0.0/16 --node-name $HOSTNAME

# Set up kubeconfig
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

# Set up kubeconfig for ubuntu user
mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
export KUBECONFIG=/etc/kubernetes/admin.conf

# Install Calico networking
echo "$(date) - Installing Calico CNI"
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/custom-resources.yaml

# Wait for the API server to be fully available
echo "$(date) - Waiting for Kubernetes API server to be ready"
until kubectl get nodes; do
  echo "Waiting for API server to be available..."
  sleep 10
done

# Create the join command and store it in AWS Secrets Manager
echo "$(date) - Creating cluster join command"
JOIN_COMMAND=$(kubeadm token create --print-join-command)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# Generate a random string to add to the secret name
RANDOM_STRING=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
SECRET_NAME="kubernetes-join-command-${TIMESTAMP}-${RANDOM_STRING}"

# Create the secret with a timestamp in the name
echo "$(date) - Storing join command in AWS Secrets Manager as ${SECRET_NAME}"
MAX_SECRET_ATTEMPTS=5
SECRET_SUCCESS=false

for ((SECRET_ATTEMPT=1; SECRET_ATTEMPT<=MAX_SECRET_ATTEMPTS; SECRET_ATTEMPT++)); do
  echo "$(date) - Secret creation attempt $SECRET_ATTEMPT/$MAX_SECRET_ATTEMPTS"
  
  # Create the secret with timestamped name
  if aws secretsmanager create-secret --name ${SECRET_NAME} --region $REGION --secret-string "$JOIN_COMMAND" 2>/dev/null; then
    echo "$(date) - Successfully created secret: ${SECRET_NAME}"
    SECRET_SUCCESS=true
    
    # Clean up old secrets, keeping the 2 newest ones
    echo "$(date) - Cleaning up older join command secrets"
    OLD_SECRETS=$(aws secretsmanager list-secrets --region $REGION --filters Key=name,Values="kubernetes-join-command-*" \
      --query "sort_by(SecretList, &CreatedDate)[:-2].Name" --output text 2>/dev/null || echo "")
    
    for OLD_SECRET in $OLD_SECRETS; do
      echo "$(date) - Deleting old secret: $OLD_SECRET"
      aws secretsmanager delete-secret --secret-id $OLD_SECRET --force-delete-without-recovery --region $REGION 2>/dev/null || true
    done
    
    break
  else
    echo "$(date) - Failed to create secret. Waiting to retry..."
    # Try with a different timestamp
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    SECRET_NAME="kubernetes-join-command-${TIMESTAMP}"
    sleep 5
  fi
done

if [ "$SECRET_SUCCESS" != "true" ]; then
  echo "$(date) - Failed to store join command in AWS Secrets Manager after $MAX_SECRET_ATTEMPTS attempts" >> $LOGFILE
  # Continue anyway, as this is not fatal to the control plane startup
fi

echo "$(date) - Kubernetes control plane setup complete!"