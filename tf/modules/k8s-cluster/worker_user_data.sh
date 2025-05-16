#!/bin/bash
set -e

# Update packages
apt-get update && apt-get upgrade -y

# Install required packages
apt-get install -y apt-transport-https ca-certificates curl software-properties-common awscli jq

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

# Install AWS SSM agent
snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

# Get instance metadata
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

# Fetch join command from Secrets Manager
JOIN_COMMAND=$(aws secretsmanager get-secret-value --secret-id kubernetes-join-command --region $REGION --query SecretString --output text)

# If join command exists, join the cluster
if [ ! -z "$JOIN_COMMAND" ]; then
    echo "Joining Kubernetes cluster with command: $JOIN_COMMAND"
    $JOIN_COMMAND
else
    echo "No join command found in Secrets Manager. Unable to join cluster."
    exit 1
fi

# Tag instance with Kubernetes node name
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
NODE_NAME="guy-worker-$(date +%H%M%S)"
aws ec2 create-tags --resources $INSTANCE_ID --tags Key=Name,Value=$NODE_NAME --region $REGION

echo "Worker node initialization completed"