#!/bin/bash
LOGFILE="/var/log/k8s-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "$(date) - Starting control plane initialization"

apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg

# Install containerd
apt-get update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# Install Kubernetes
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y kubeadm kubelet kubectl
apt-mark hold kubeadm kubelet kubectl

# Initialize cluster
kubeadm init --pod-network-cidr=192.168.0.0/16 --node-name guy-control-plane

# Setup kubectl
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

# Install Calico CNI
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml

# Store join command
JOIN_COMMAND=$(kubeadm token create --print-join-command)
aws secretsmanager put-secret-value --secret-id kubernetes-join-command --secret-string "$JOIN_COMMAND" --region "${var.region}"