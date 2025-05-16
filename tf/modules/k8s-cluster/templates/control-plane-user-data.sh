#!/bin/bash
set -e

# Update packages
apt-get update && apt-get upgrade -y

# Install required packages
apt-get install -y apt-transport-https ca-certificates curl software-properties-common awscli

# Add Docker repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# Add Kubernetes repository
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
cat > /etc/apt/sources.list.d/kubernetes.list <<EOF
deb https://apt.kubernetes.io/ kubernetes-xenial main
EOF

# Update package lists
apt-get update

# Install Docker and Kubernetes
apt-get install -y docker-ce kubelet kubeadm kubectl

# Configure Docker to use systemd as the cgroup driver
cat > /etc/docker/daemon.json <<EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF

# Restart Docker
mkdir -p /etc/systemd/system/docker.service.d
systemctl daemon-reload
systemctl restart docker

# Initialize Kubernetes control plane
kubeadm init --token ${token} --token-ttl 0 --pod-network-cidr=10.244.0.0/16

# Setup kubeconfig for root user
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

# Install Flannel CNI
kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

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

echo "Control plane initialization completed" 