#!/bin/bash
# Simple bootstrap script for worker nodes
# Establishes basic connectivity and joins the cluster

# Set up logging
LOGFILE="/var/log/k8s-bootstrap.log"
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"
mkdir -p /var/log
touch $LOGFILE
chmod 644 $LOGFILE

# Redirect output to log files
exec > >(tee -a $LOGFILE $CLOUD_INIT_LOG) 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting Kubernetes worker node bootstrap"

# Error handling with clear error messages
set -e
trap 'echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Error at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Initialize progress tracking
mark_progress() {
  local stage="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $stage"
  echo "$stage" > /var/log/worker-bootstrap-progress
}

# 1. Configure SSH first for emergency access
mark_progress "Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh

# Write SSH key
cat > /home/ubuntu/.ssh/authorized_keys << 'EOF'
${SSH_PUBLIC_KEY}
EOF

chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Also set up for root user
mkdir -p /root/.ssh
cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# 2. Install essential packages
mark_progress "Installing essential packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apt-transport-https ca-certificates curl unzip jq

# 3. Install AWS CLI for metadata access
mark_progress "Installing AWS CLI"
if ! command -v aws &> /dev/null; then
  curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip
  ./aws/install
  rm -rf awscliv2.zip aws/
fi

# 4. Get instance metadata with robust retry
mark_progress "Retrieving instance metadata"
get_metadata() {
  local max_attempts=5
  local attempt=1
  local wait_time=5
  local key=$1
  local value=""
  
  # First try IMDSv2
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || echo "")
  
  while [ $attempt -le $max_attempts ]; do
    if [ -n "$TOKEN" ]; then
      value=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$key" || echo "")
    else
      value=$(curl -s "http://169.254.169.254/latest/meta-data/$key" || echo "")
    fi
    
    if [ -n "$value" ]; then
      echo "$value"
      return 0
    fi
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to get metadata: $key (attempt $attempt/$max_attempts)"
    sleep $wait_time
    attempt=$((attempt + 1))
    wait_time=$((wait_time * 2))
  done
  
  echo ""
}

# Collect metadata
REGION=$(get_metadata "placement/region")
INSTANCE_ID=$(get_metadata "instance-id")
PRIVATE_IP=$(get_metadata "local-ipv4")
AZ=$(get_metadata "placement/availability-zone")

# Use defaults if metadata unavailable
REGION=$${REGION:-"${REGION}"}
INSTANCE_ID=$${INSTANCE_ID:-"unknown-$(hostname)"}
PRIVATE_IP=$${PRIVATE_IP:-$(hostname -I | awk '{print $1}')}
AZ=$${AZ:-"${REGION}a"}
NODE_NAME="worker-$(echo $INSTANCE_ID | cut -d'-' -f2)"

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Instance metadata:"
echo "  Instance ID: $INSTANCE_ID"
echo "  Private IP: $PRIVATE_IP"
echo "  Region: $REGION"
echo "  AZ: $AZ"
echo "  Node name: $NODE_NAME"

# 5. Save metadata for full script
mark_progress "Saving metadata for full initialization"
mkdir -p /etc/kubernetes
cat > /etc/kubernetes/worker-metadata.env << EOF
INSTANCE_ID=$INSTANCE_ID
PRIVATE_IP=$PRIVATE_IP
REGION=$REGION
AZ=$AZ
NODE_NAME=$NODE_NAME
JOIN_COMMAND_SECRET="${JOIN_COMMAND_SECRET}"
JOIN_COMMAND_LATEST_SECRET="${JOIN_COMMAND_LATEST_SECRET}"
EOF

# 6. Configure basic Kubernetes prerequisites
mark_progress "Configuring Kubernetes prerequisites"

# Setup kernel modules
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF

modprobe overlay
modprobe br_netfilter

# Configure sysctl
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab

# 7. Install container runtime
mark_progress "Installing container runtime"
apt-get update
apt-get install -y containerd

# Configure containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

# Start containerd
systemctl restart containerd
systemctl enable containerd

# 8. Install Kubernetes components
mark_progress "Installing Kubernetes components"

# Add Kubernetes repository
mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components
apt-get update
apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# Configure kubelet
mkdir -p /var/lib/kubelet
cat > /var/lib/kubelet/kubeadm-flags.env << EOF
KUBELET_EXTRA_ARGS=--node-ip=$PRIVATE_IP --hostname-override=$NODE_NAME --cloud-provider=external --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --cgroup-driver=systemd
EOF

# Restart kubelet
systemctl daemon-reload
systemctl restart kubelet

# 9. Retrieve and execute join command
mark_progress "Retrieving join command"

MAX_ATTEMPTS=10
for attempt in $(seq 1 $MAX_ATTEMPTS); do
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempt $attempt/$MAX_ATTEMPTS to retrieve join command"
  
  # Try the latest secret first, then fall back to the original secret
  for secret_name in "${JOIN_COMMAND_LATEST_SECRET}" "${JOIN_COMMAND_SECRET}"; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Trying to retrieve secret: $secret_name"
    
    JOIN_COMMAND=$(aws secretsmanager get-secret-value \
      --secret-id "$secret_name" \
      --region "$REGION" \
      --query 'SecretString' \
      --output text 2>/dev/null || echo "")
    
    if [ -n "$JOIN_COMMAND" ] && [[ "$JOIN_COMMAND" == *"kubeadm join"* ]]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Successfully retrieved join command"
      
      # Attempt to join the cluster
      mark_progress "Joining cluster"
      echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Executing join command"
      
      # Reset any previous Kubernetes state
      kubeadm reset -f
      
      # Execute the join command
      if eval "$JOIN_COMMAND"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Successfully joined the cluster!"
        
        # Create a success marker
        touch /var/log/worker-join-success
        mark_progress "Joined successfully"
        
        # Tag the instance with Kubernetes metadata
        aws ec2 create-tags \
          --resources "$INSTANCE_ID" \
          --tags Key=KubernetesNode,Value=Worker Key=Name,Value="$NODE_NAME" \
          --region "$REGION" || true
        
        exit 0
      else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to join cluster with command from $secret_name"
      fi
    fi
  done
  
  # If we get here, either we couldn't get a join command or joining failed
  echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to join cluster on attempt $attempt/$MAX_ATTEMPTS, waiting before retry"
  sleep 30
done

echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to join cluster after $MAX_ATTEMPTS attempts"
mark_progress "Failed to join cluster"
exit 1 
