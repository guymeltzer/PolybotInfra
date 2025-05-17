#!/bin/bash
set -e

# Log file for debugging
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a $LOGFILE) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Trap errors and exit the script with an error message
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; exit 1' ERR

# Update packages
apt-get update

# Install required packages as per course instructions
apt-get install -y jq unzip ebtables ethtool
apt-get install -y software-properties-common apt-transport-https ca-certificates curl gpg

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install --update
rm -rf awscliv2.zip aws/

# Add AWS CLI to PATH
export PATH=$PATH:/usr/local/bin

# Enable IPv4 packet forwarding. sysctl params required by setup, params persist across reboots
cat <<EOF | tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

# Apply sysctl params without reboot
sysctl --system

# Set Kubernetes version
KUBERNETES_VERSION="v1.32"

# Install CRI-O, kubelet, kubeadm, kubectl using modern repository approach
curl -fsSL https://pkgs.k8s.io/core:/stable:/$KUBERNETES_VERSION/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$KUBERNETES_VERSION/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update
apt-get install -y cri-o kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

# Start the CRI-O container runtime and kubelet
systemctl start crio.service
systemctl enable --now crio.service
systemctl enable --now kubelet

# Disable swap memory
swapoff -a
# Add the command to crontab to make it persistent across reboots
(crontab -l 2>/dev/null || echo "") | grep -v "@reboot /sbin/swapoff -a" | { cat; echo "@reboot /sbin/swapoff -a"; } | crontab -

# Get the public and private IPs
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/hostname)

# Create kubeadm config file
cat > /tmp/kubeadm-config.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
nodeRegistration:
  name: ${HOSTNAME}
  kubeletExtraArgs:
    cloud-provider: external
localAPIEndpoint:
  advertiseAddress: ${PRIVATE_IP}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: stable
apiServer:
  certSANs:
  - ${PUBLIC_IP}
  - ${PRIVATE_IP}
  - ${HOSTNAME}
  - localhost
  - 127.0.0.1
  extraArgs:
    bind-address: 0.0.0.0
networking:
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/12
controllerManager:
  extraArgs:
    cloud-provider: external
EOF

# Initialize Kubernetes control plane with the config file
kubeadm init --config=/tmp/kubeadm-config.yaml --token ${token} --token-ttl 0 --v=5

echo "Kubernetes control plane initialized with kubeadm"

# Setup kubeconfig for root user
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

# Install Calico CNI (as per course instructions)
kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml

# Install AWS SSM agent
snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

# Allow control plane to run pods (remove taint)
kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane-

# Make certificates accessible for Terraform
chmod 644 /etc/kubernetes/pki/ca.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.key

# Add a host entry for API server
echo "${PRIVATE_IP} ${HOSTNAME}" >> /etc/hosts

# Configure kubeconfig with public IP for remote access
sed -i "s/server: https:\/\/${PRIVATE_IP}:6443/server: https:\/\/${PUBLIC_IP}:6443/g" /etc/kubernetes/admin.conf
kubectl config set clusters.kubernetes.server https://${PUBLIC_IP}:6443

# Store join command in AWS Secrets Manager for workers to use
JOIN_COMMAND=$(kubeadm token create --print-join-command)
aws secretsmanager put-secret-value \
  --secret-id kubernetes-join-command-${token} \
  --secret-string "$JOIN_COMMAND" \
  --version-stage AWSCURRENT

# Verify the API server is accessible
kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes
kubectl --kubeconfig=/etc/kubernetes/admin.conf cluster-info

echo "$(date) - Control plane initialization completed" | tee -a $LOGFILE 