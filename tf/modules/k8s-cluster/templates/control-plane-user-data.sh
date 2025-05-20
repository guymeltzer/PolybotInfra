#!/bin/bash
# Script generated at: ${timestamp}
set -ex

# Log file for debugging
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a $${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Debug: Verify script integrity
echo "$(date) - Verifying script integrity"
cat $0 > /tmp/script-copy.sh
sha256sum $0 /tmp/script-copy.sh
echo "$(date) - Script hash: ${script_hash}" >> $${LOGFILE}

# Add SSH key for direct access
echo "$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
cat <<EOF >> /home/ubuntu/.ssh/authorized_keys
${ssh_pub_key}
EOF
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp" >> /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Trap errors but make it more forgiving
trap 'echo "Warning at line $${LINENO}. Command: $${BASH_COMMAND}"; echo "$(date) - WARNING at line $${LINENO}: $${BASH_COMMAND}" >> $${LOGFILE}' ERR

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Update packages and ensure package manager consistency
echo "$(date) - Updating package lists"
apt-get update || {
  echo "$(date) - ERROR: Failed to update package lists"
  exit 1
}
echo "$(date) - Fixing package manager state"
apt-get install -f -y
dpkg --configure -a

# Install unzip explicitly (needed for AWS CLI) - with improved error handling
echo "$(date) - Installing unzip"
apt-get install -y unzip 2>&1 | tee -a $${LOGFILE}
if command -v unzip &>/dev/null; then
  echo "$(date) - Unzip is available at $(command -v unzip)"
  # Just check binary exists, don't fail on output
  unzip -v &>/dev/null || true
  echo "$(date) - Unzip is installed and working"
else
  echo "$(date) - ERROR: Cannot find unzip binary"
  exit 1
fi

# Upgrade packages
echo "$(date) - Upgrading installed packages"
apt-get upgrade -y || {
  echo "$(date) - ERROR: Failed to upgrade packages"
  exit 1
}

# Install AWS CLI
echo "$(date) - Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" || {
  echo "$(date) - ERROR: Failed to download AWS CLI"
  exit 1
}
unzip -q awscliv2.zip || {
  echo "$(date) - ERROR: Failed to unzip AWS CLI"
  exit 1
}
./aws/install --update || {
  echo "$(date) - ERROR: Failed to install AWS CLI"
  exit 1
}
rm -rf awscliv2.zip aws/
export PATH=$${PATH}:/usr/local/bin
aws --version || {
  echo "$(date) - ERROR: AWS CLI not installed correctly"
  exit 1
}

# Install initial dependencies
echo "$(date) - Installing initial dependencies"
apt-get install -y \
  jq ebtables ethtool apt-transport-https \
  ca-certificates curl gnupg lsb-release \
  tcpdump net-tools telnet dnsutils \
  || {
    echo "$(date) - ERROR: Failed to install initial dependencies"
    exit 1
  }

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab
echo "@reboot /sbin/swapoff -a" | crontab -

# Load necessary modules
modprobe overlay
modprobe br_netfilter

# Configure network settings
cat > /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
EOF

cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system

# Get the public and private IPs with better error handling
echo "$(date) - Getting instance network details"
for i in {1..5}; do
  PUBLIC_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  PRIVATE_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
  HOSTNAME=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/hostname || echo "")
  
  # If we got the private IP, we can proceed
  if [ -n "$${PRIVATE_IP}" ]; then
    break
  fi
  echo "$(date) - Retry $i/5: Failed to get instance metadata, waiting 5 seconds..."
  sleep 5
done

# Fallback if metadata service fails
if [ -z "$${PRIVATE_IP}" ]; then
  echo "$(date) - WARNING: Could not get instance metadata from AWS, using fallback methods"
  PRIVATE_IP=$(hostname -I | awk '{print $1}')
  HOSTNAME=$(hostname)
fi

if [ -z "$${PUBLIC_IP}" ]; then
  echo "$(date) - No public IP found, will use private IP for API server"
  API_ADVERTISE_IP="$${PRIVATE_IP}"
else
  echo "$(date) - Using public IP for API server: $${PUBLIC_IP}"
  API_ADVERTISE_IP="$${PRIVATE_IP}"  # Still use private IP for kubeadm
fi

echo "Public IP: $${PUBLIC_IP}"
echo "Private IP: $${PRIVATE_IP}"
echo "Hostname: $${HOSTNAME}"

# Add a host entry for API server
echo "$${PRIVATE_IP} $${HOSTNAME}" >> /etc/hosts

# Install containerd
echo "$(date) - Installing containerd"
apt-get update
apt-get install -y containerd || {
  echo "$(date) - ERROR: Failed to install containerd"
  exit 1
}
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd
systemctl status containerd || { echo "Containerd failed to start"; journalctl -xeu containerd; exit 1; }

# Set up Kubernetes repositories
echo "$(date) - Setting up Kubernetes repositories"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components
echo "$(date) - Installing Kubernetes components"
apt-get update
apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1 || {
  echo "$(date) - ERROR: Failed to install Kubernetes components"
  exit 1
}
apt-mark hold kubelet kubeadm kubectl

# Start the kubelet
echo "$(date) - Starting kubelet service"
systemctl enable --now kubelet
systemctl status kubelet || { echo "Kubelet service failed to start"; journalctl -xeu kubelet || true; }

# Use the pre-formatted token from Terraform
echo "$(date) - Using bootstrap token: ${token_formatted}"

# Create kubeadm config file - with token built in
echo "$(date) - Creating kubeadm configuration"
cat <<EOF > /tmp/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
nodeRegistration:
  name: $${HOSTNAME}
  kubeletExtraArgs:
    cloud-provider: external
localAPIEndpoint:
  advertiseAddress: $${PRIVATE_IP}
  bindPort: 6443
bootstrapTokens:
- token: "${token_formatted}"
  description: "default bootstrap token"
  ttl: "0s"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v1.28.3
apiServer:
  certSANs:
  - $${PUBLIC_IP}
  - $${PRIVATE_IP}
  - $${HOSTNAME}
  - localhost
  - 127.0.0.1
  extraArgs:
    bind-address: 0.0.0.0
networking:
  podSubnet: 192.168.0.0/16
  serviceSubnet: 10.96.0.0/12
controllerManager:
  extraArgs:
    cloud-provider: external
EOF

cat /tmp/kubeadm-config.yaml

# Configure firewall rules
echo "$(date) - Configuring firewall rules"
iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
iptables -A INPUT -p tcp --dport 179 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Create systemd service to restore iptables rules at boot
cat <<EOF > /etc/systemd/system/iptables-restore.service
[Unit]
Description=Restore iptables rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iptables-restore.service || {
  echo "$(date) - ERROR: Failed to enable iptables-restore.service"
  exit 1
}

# Initialize Kubernetes control plane - no need for --token or --token-ttl here
echo "$(date) - Starting kubeadm init with config"
kubeadm init --config=/tmp/kubeadm-config.yaml --v=5 || {
  echo "$(date) - kubeadm init failed, checking errors"
  journalctl -xeu kubelet || true
  exit 1
}

echo "$(date) - Kubernetes control plane initialized with kubeadm"

# Setup kubeconfig
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

# Verify initial cluster status
kubectl get nodes -o wide
kubectl get pods -A

# Install Calico CNI
echo "$(date) - Installing Calico CNI networking..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/calico.yaml

# Wait for Calico pods to be ready
echo "$(date) - Waiting for Calico pods to start..."
for i in {1..30}; do
  echo "$(date) - Calico status check attempt $i/30"
  RUNNING_PODS=$(kubectl get pods -n kube-system -l k8s-app=calico-node --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)

  if [ "$${RUNNING_PODS}" -gt 0 ]; then
    echo "$(date) - Calico node pod(s) are running"
    break
  fi

  if [ $i -eq 30 ]; then
    echo "$(date) - Calico pods failed to start in time. Checking pods status:"
    kubectl get pods -n kube-system -o wide
    echo "$(date) - Checking Calico pod logs:"
    kubectl logs -n kube-system -l k8s-app=calico-node --tail=50
  fi

  sleep 10
done

# Check API server is running properly
echo "$(date) - Checking API server status"
for attempt in {1..10}; do
  if netstat -tlpn | grep -q 6443; then
    echo "$(date) - API server is listening on port 6443"
    break
  fi

  if [ $attempt -eq 10 ]; then
    echo "$(date) - WARNING: API server is not listening on port 6443"
    echo "$(date) - Checking API server pod logs:"
    kubectl logs -n kube-system -l component=kube-apiserver --tail=50
  fi

  echo "$(date) - Attempt $attempt: API server not yet listening, waiting..."
  sleep 10
done

# Install AWS SSM agent
echo "$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

# Allow control plane to run pods
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Make certificates accessible for Terraform
chmod 644 /etc/kubernetes/pki/ca.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.key

# Configure kubeconfig with public IP
echo "$(date) - Configuring kubeconfig for remote access"
cp /etc/kubernetes/admin.conf /etc/kubernetes/admin.conf.bak
if [ -n "$${PUBLIC_IP}" ]; then
  sed -i "s/server: https:\/\/.*:6443/server: https:\/\/$${PUBLIC_IP}:6443/g" /etc/kubernetes/admin.conf
else
  sed -i "s/server: https:\/\/.*:6443/server: https:\/\/$${PRIVATE_IP}:6443/g" /etc/kubernetes/admin.conf
fi

# Store join command in AWS Secrets Manager
JOIN_COMMAND=$(kubeadm token create --print-join-command)
echo "$(date) - Generated join command: $${JOIN_COMMAND}"
aws secretsmanager put-secret-value \
  --secret-id kubernetes-join-command-${token_formatted} \
  --secret-string "$${JOIN_COMMAND}" \
  --region us-east-1 \
  --version-stage AWSCURRENT

# Set up socat port forwarding
echo "$(date) - Setting up socat port forwarding for API server"
apt-get install -y socat
cat <<EOF > /etc/systemd/system/apiserver-proxy.service
[Unit]
Description=Kubernetes API Server Proxy
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:6443,fork,reuseaddr TCP:127.0.0.1:6443
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable apiserver-proxy.service
systemctl start apiserver-proxy.service
systemctl status apiserver-proxy.service

# Final verification
echo "$(date) - Final verification of Kubernetes cluster"
kubectl get nodes -o wide
kubectl get pods -A -o wide
echo "$(date) - Network ports:"
netstat -tulpn | grep 6443

echo "$(date) - Control plane initialization completed successfully"
echo "$(date) - You can access the cluster using: kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes"