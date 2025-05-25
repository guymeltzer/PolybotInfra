#!/bin/bash
# Simple, proven control plane initialization

# Basic setup
set -e
export DEBIAN_FRONTEND=noninteractive

# Log everything
exec > >(tee -a /var/log/k8s-init.log) 2>&1

echo "Starting control plane initialization at $(date)"

# 1. Install essential packages
apt-get update
apt-get install -y apt-transport-https ca-certificates curl unzip jq awscli

# 2. SSH setup
mkdir -p /home/ubuntu/.ssh /root/.ssh
echo "${ssh_public_key}" > /home/ubuntu/.ssh/authorized_keys
echo "${ssh_public_key}" > /root/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# 3. Kubernetes prerequisites
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF

modprobe overlay
modprobe br_netfilter

cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab

# 4. Install containerd
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# 5. Install Kubernetes
mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y kubeadm=1.28.3-1.1 kubelet=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubeadm kubelet kubectl

# 6. Get instance metadata
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# 7. Initialize Kubernetes
cat > /tmp/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${token_formatted}"
  description: "initial token for worker join"
  ttl: "24h"
nodeRegistration:
  kubeletExtraArgs:
    cloud-provider: external
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
networking:
  podSubnet: "${POD_CIDR}"
apiServer:
  certSANs:
  - "$PRIVATE_IP"
  - "$PUBLIC_IP"
  - "127.0.0.1"
  - "localhost"
controllerManager:
  extraArgs:
    cloud-provider: external
EOF

# Initialize cluster
kubeadm init --config=/tmp/kubeadm-config.yaml --skip-phases=addon/kube-proxy

# Setup kubeconfig
mkdir -p /root/.kube /home/ubuntu/.kube
cp /etc/kubernetes/admin.conf /root/.kube/config
cp /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

# Install Calico
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl apply -f https://docs.projectcalico.org/v3.25/manifests/calico.yaml

# Store join command in secrets manager
JOIN_COMMAND=$(kubeadm token create --print-join-command)
aws secretsmanager put-secret-value --secret-id "${JOIN_COMMAND_SECRET}" --secret-string "$JOIN_COMMAND" --region "${region}" || true
aws secretsmanager put-secret-value --secret-id "${JOIN_COMMAND_LATEST_SECRET}" --secret-string "$JOIN_COMMAND" --region "${region}" || true

echo "Control plane initialization completed at $(date)"