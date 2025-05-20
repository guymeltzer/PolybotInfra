#!/bin/bash
# Script generated with static content (timestamp will update when file changes)

# Log file for debugging - Define directly without using template variable syntax
LOGFILE=/var/log/k8s-worker-init.log
# Use single quotes to prevent Terraform template expansion for variables we don't want to expand
exec > >(tee -a "$LOGFILE") 2>&1
echo "$(date) - Starting Kubernetes worker node initialization"

# Error handling
set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> "$LOGFILE"; exit 1' ERR

# Set up SSH access (using your existing key)
echo "$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp
EOF
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Set non-interactive frontend
export DEBIAN_FRONTEND=noninteractive

# Wait for metadata and network
echo "$(date) - Waiting for metadata service"
until curl -s -m 5 http://169.254.169.254/latest/meta-data/ > /dev/null; do
  echo "Waiting for metadata service..."
  sleep 5
done

# Get metadata token
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
if [ -z "$TOKEN" ]; then
  echo "Failed to retrieve metadata token" >> "$LOGFILE"
  exit 1
fi

# Get region
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
if [ -z "$REGION" ]; then
  echo "Failed to retrieve region from metadata" >> "$LOGFILE"
  exit 1
fi

# Get instance metadata
PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
PROVIDER_ID="aws:///${AZ}/${INSTANCE_ID}"

# Update package lists
echo "$(date) - Updating package lists"
apt-get update
echo "$(date) - Fixing package manager state"
apt-get install -f -y
dpkg --configure -a

# Install base packages
echo "$(date) - Installing base packages"
apt-get install -y apt-transport-https ca-certificates curl gnupg software-properties-common jq unzip

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

# Set sequential hostname
SSM_PARAM_NAME="/k8s/worker-node-counter"
COUNTER=$(aws ssm get-parameter --name "$SSM_PARAM_NAME" --region "$REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "0")
NEXT_COUNTER=$((COUNTER + 1))
aws ssm put-parameter --name "$SSM_PARAM_NAME" --value "$NEXT_COUNTER" --type String --overwrite --region "$REGION" 2>>"$LOGFILE"
NODE_NAME="guy-worker-node-$NEXT_COUNTER"
hostnamectl set-hostname "$NODE_NAME"
echo "127.0.0.1 $NODE_NAME" | tee -a /etc/hosts
echo "$(date) - Set hostname to $NODE_NAME"

# Install containerd
echo "$(date) - Installing containerd"
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# Verify containerd socket
echo "$(date) - Waiting for containerd socket"
timeout 60 bash -c 'until [ -S /run/containerd/containerd.sock ]; do sleep 1; done'

# Install Kubernetes packages
echo "$(date) - Installing Kubernetes packages"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# Configure kubelet
mkdir -p /var/lib/kubelet /etc/kubernetes
cat > /var/lib/kubelet/kubeadm-flags.env << EOF
KUBELET_EXTRA_ARGS=--cgroup-driver=systemd --cloud-provider=external --provider-id=${PROVIDER_ID}
EOF

# Disable swap
echo "$(date) - Disabling swap"
swapoff -a
sed -i '/swap/d' /etc/fstab

# Restart kubelet
systemctl daemon-reload
systemctl restart kubelet

# Fetch join command from Secrets Manager with retry logic
echo "$(date) - Fetching join command from Secrets Manager"
MAX_SECRET_ATTEMPTS=10
JOIN_COMMAND=""

for ((SECRET_ATTEMPT=1; SECRET_ATTEMPT<=MAX_SECRET_ATTEMPTS; SECRET_ATTEMPT++)); do
  echo "$(date) - Secret fetch attempt $SECRET_ATTEMPT/$MAX_SECRET_ATTEMPTS"
  
  JOIN_COMMAND=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id kubernetes-join-command --query SecretString --output text 2>>"$LOGFILE" || echo "")
  
  if [ -n "$JOIN_COMMAND" ]; then
    echo "$(date) - Successfully retrieved join command"
    break
  else
    echo "$(date) - Join command not available yet. Waiting to retry..."
    sleep 30
  fi
done

if [ -z "$JOIN_COMMAND" ]; then
  echo "$(date) - Failed to retrieve join command from Secrets Manager after $MAX_SECRET_ATTEMPTS attempts" >> "$LOGFILE"
  exit 1
fi

echo "$(date) - Join command fetched successfully"

# Join cluster with retry logic
MAX_ATTEMPTS=15
JOIN_SUCCESS=false
RETRY_DELAY=30

for ((ATTEMPT=1; ATTEMPT<=MAX_ATTEMPTS; ATTEMPT++)); do
  echo "$(date) - Attempt $ATTEMPT/$MAX_ATTEMPTS to join cluster"
  
  eval $JOIN_COMMAND --v=5 2>&1 | tee -a "$LOGFILE"
  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    JOIN_SUCCESS=true
    echo "$(date) - Successfully joined cluster" 
    systemctl restart kubelet
    break
  else
    echo "$(date) - Join failed. Retrying in $RETRY_DELAY seconds..."
    sleep $RETRY_DELAY
    RETRY_DELAY=$((RETRY_DELAY * 2))
  fi
done

if [ "$JOIN_SUCCESS" = false ]; then
  echo "$(date) - Failed to join cluster after $MAX_ATTEMPTS attempts"
  exit 1
fi

# After successfully joining the cluster
if [ "$JOIN_SUCCESS" = true ]; then
  echo "$(date) - Setting providerID to $PROVIDER_ID for node $NODE_NAME"
  
  # Wait for kubelet.conf to be created
  KUBELET_CONF="/etc/kubernetes/kubelet.conf"
  for i in {1..30}; do
    if [ -f "$KUBELET_CONF" ]; then
      break
    fi
    echo "$(date) - Waiting for kubelet.conf to be created (attempt $i/30)"
    sleep 10
  done
  
  if [ ! -f "$KUBELET_CONF" ]; then
    echo "$(date) - kubelet.conf not found after waiting. This is unexpected but not fatal."
  else
    kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" --kubeconfig=$KUBELET_CONF 2>>"$LOGFILE"
    if [ $? -eq 0 ]; then
      echo "$(date) - providerID set successfully"
    else
      echo "$(date) - Failed to set providerID"
    fi
  fi

  # Signal lifecycle hook completion
  aws autoscaling complete-lifecycle-action \
    --lifecycle-hook-name "guy-scale-up-hook" \
    --auto-scaling-group-name "guy-polybot-asg" \
    --lifecycle-action-result "CONTINUE" \
    --instance-id "$INSTANCE_ID" \
    --region "$REGION" 2>>"$LOGFILE" || {
      echo "$(date) - Failed to signal lifecycle hook"
      aws autoscaling complete-lifecycle-action \
        --lifecycle-hook-name "guy-scale-up-hook" \
        --auto-scaling-group-name "guy-polybot-asg" \
        --lifecycle-action-result "ABANDON" \
        --instance-id "$INSTANCE_ID" \
        --region "$REGION" 2>>"$LOGFILE"
    }
fi

# Set EC2 tags
aws ec2 create-tags --region "$REGION" --resources "$INSTANCE_ID" \
  --tags Key=node-role.kubernetes.io/worker,Value=true Key=k8s.io/autoscaled-node,Value=true Key=Name,Value="$NODE_NAME" 2>>"$LOGFILE"

echo "$(date) - Worker node setup complete"