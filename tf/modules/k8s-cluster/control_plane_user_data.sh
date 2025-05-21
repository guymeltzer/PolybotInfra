#!/bin/bash

# Define log file
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Add error handling
set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> ${LOGFILE}; exit 1' ERR

# Set non-interactive frontend
export DEBIAN_FRONTEND=noninteractive

# Update package lists
echo "$(date) - Updating package lists"
apt-get update
echo "$(date) - Fixing package manager state"
apt-get install -f -y
dpkg --configure -a

# Install necessary packages first
echo "$(date) - Installing base packages"
apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg jq unzip

# Install AWS CLI early in the process
echo "$(date) - Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
export PATH=$PATH:/usr/local/bin
rm -rf awscliv2.zip aws/

# Verify AWS CLI installation
echo "$(date) - Verifying AWS CLI installation"
aws --version

# Set up SSH access (using your existing key).
echo "$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp
EOF
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

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
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y kubeadm=1.28.3-1.1 kubelet=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubeadm kubelet kubectl

# Disable swap
echo "$(date) - Disabling swap"
swapoff -a
sed -i '/swap/d' /etc/fstab

# Retrieve instance metadata
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

echo "$(date) - Retrieving instance metadata"
echo "Instance ID: $INSTANCE_ID"
echo "Private IP: $PRIVATE_IP"
echo "Public IP: $PUBLIC_IP"
echo "Hostname: $(hostname -f)"

# Set up hostname
hostnamectl set-hostname "ip-${PRIVATE_IP//./-}.ec2.internal"
echo "127.0.0.1 $(hostname -f)" >> /etc/hosts

# Initialize Kubernetes cluster
echo "$(date) - Initializing Kubernetes control plane with kubeadm"
cat > /tmp/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
nodeRegistration:
  kubeletExtraArgs:
    cloud-provider: "external"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
networking:
  podSubnet: "192.168.0.0/16"
apiServer:
  certSANs:
  - "${PRIVATE_IP}"
  - "${PUBLIC_IP}"
  - "127.0.0.1"
  - "localhost"
controllerManager:
  extraArgs:
    cloud-provider: "external"
EOF

kubeadm init --config=/tmp/kubeadm-config.yaml --v=5

# Set up kubeconfig
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
export KUBECONFIG=/etc/kubernetes/admin.conf

# Untaint the control plane if we have a single-node cluster
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Install Calico networking
echo "$(date) - Installing Calico CNI"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml

# Wait for calico pods to be ready
echo "$(date) - Waiting for Calico pods to become ready"
kubectl get pods -n kube-system | grep calico
for i in {1..10}; do
  echo "$(date) - Waiting for Calico to be ready (attempt $i/10)"
  if kubectl get pods -n kube-system -l k8s-app=calico-node --no-headers | grep -v 'Running'; then
    sleep 15
  else
    echo "$(date) - Calico is ready"
    break
  fi
done

# Generate join command
TOKEN=$(kubeadm token create)
DISCOVERY_HASH=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //')
JOIN_COMMAND="kubeadm join ${PRIVATE_IP}:6443 --token ${TOKEN} --discovery-token-ca-cert-hash sha256:${DISCOVERY_HASH}"

echo "$(date) - Generated join command with private IP: $JOIN_COMMAND"

# Store join command in AWS Secrets Manager with a consistent naming pattern
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
SECRET_NAME="kubernetes-join-command-${TIMESTAMP}"

echo "$(date) - Creating Secret Manager secret $SECRET_NAME"
aws secretsmanager create-secret --name "$SECRET_NAME" --secret-string "$JOIN_COMMAND" --description "Kubernetes join command for worker nodes" --region "$REGION" || {
  echo "$(date) - Failed to create new secret, trying to update existing one"
  # If creation fails, try to find an existing secret to update
  EXISTING_SECRET=$(aws secretsmanager list-secrets \
    --region "$REGION" \
    --query "sort_by(SecretList[?contains(Name, 'kubernetes-join-command')], &CreatedDate)[-1].Name" \
    --output text)
  
  if [ -n "$EXISTING_SECRET" ] && [ "$EXISTING_SECRET" != "None" ]; then
    echo "$(date) - Updating existing secret $EXISTING_SECRET"
    aws secretsmanager update-secret --secret-id "$EXISTING_SECRET" --secret-string "$JOIN_COMMAND" --region "$REGION"
  fi
}

# Also create a fixed-name secret that's easier to find
FIXED_SECRET_NAME="kubernetes-join-command-latest"
echo "$(date) - Creating/updating fixed name secret $FIXED_SECRET_NAME"
aws secretsmanager describe-secret --secret-id "$FIXED_SECRET_NAME" --region "$REGION" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  # Secret exists, update it
  aws secretsmanager update-secret --secret-id "$FIXED_SECRET_NAME" --secret-string "$JOIN_COMMAND" --region "$REGION"
else
  # Secret doesn't exist, create it
  aws secretsmanager create-secret --name "$FIXED_SECRET_NAME" --secret-string "$JOIN_COMMAND" --description "Latest Kubernetes join command" --region "$REGION"
fi

# Verify the secret was created correctly and is accessible
echo "$(date) - Verifying secret is accessible"
sleep 5  # Give AWS some time to propagate the secret
aws secretsmanager get-secret-value --secret-id "$FIXED_SECRET_NAME" --region "$REGION" || {
  echo "$(date) - WARNING: Secret verification failed, attempting to fix permissions"
  aws secretsmanager update-secret-version-stage \
    --secret-id "$FIXED_SECRET_NAME" \
    --version-stage AWSCURRENT \
    --move-to-version-id $(aws secretsmanager describe-secret --secret-id "$FIXED_SECRET_NAME" --query "VersionIdsToStages" --output text | awk '{print $1}') \
    --region "$REGION"
}

# Update admin kubeconfig to use public IP
echo "$(date) - Configuring kubeconfig with public IP"
sed -i "s#server: https://.*:6443#server: https://${PUBLIC_IP}:6443#" /etc/kubernetes/admin.conf
cp -f /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config

# Secure the Kubernetes certificates
echo "$(date) - Setting secure permissions on Kubernetes certificates"
chmod 600 /etc/kubernetes/admin.conf
chmod -R 600 /etc/kubernetes/pki/

# Verify kubectl works
echo "$(date) - Verifying kubectl works with updated kubeconfig"
kubectl get nodes

# Install and configure AWS SSM agent
echo "$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic

# Verify autoscaling group and SNS
echo "$(date) - Verifying ASG and SNS service integration"
aws autoscaling describe-auto-scaling-groups --region "$REGION"
aws sns list-topics --region "$REGION"

# Publish a message to SNS to notify of control plane readiness
TOPIC_ARN=$(aws sns list-topics --region "$REGION" --query 'Topics[0].TopicArn' --output text)
if [ -n "$TOPIC_ARN" ]; then
  echo "$(date) - Sending notification to SNS topic: $TOPIC_ARN"
  aws sns publish --topic-arn "$TOPIC_ARN" --message "Kubernetes control plane is ready at $PUBLIC_IP" --region "$REGION"
fi

echo "$(date) - Kubernetes control plane initialization completed successfully"
echo "$(date) - You can check the cluster status using: kubectl get nodes"

# Verify connection again
echo "$(date) - Verifying kubectl works with updated kubeconfig"
kubectl get nodes

# Install AWS CLI for managing resources
echo "$(date) - Installing AWS CLI"
apt-get update
apt-get install -y unzip