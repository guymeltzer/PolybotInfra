#!/bin/bash
# Minimal worker node bootstrap script - focuses on downloading the full initialization script
# This script ensures critical components are installed and then downloads the full setup script

# Set up logging
LOGFILE="/var/log/worker-bootstrap.log"
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"
mkdir -p /var/log
touch $${LOGFILE}
chmod 644 $${LOGFILE}

# Redirect output to log files
exec > >(tee -a $${LOGFILE} $${CLOUD_INIT_LOG}) 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting worker node bootstrap (minimal version)"

# Error handling with clear error messages
set -e
trap 'echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Error at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Initialize progress tracking
mark_progress() {
  local stage="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $stage"
  # Create progress marker
  echo "$stage" > /var/log/worker-bootstrap-progress
}

# 1. Configure SSH first for emergency access
mark_progress "Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh

# Write SSH key
cat > /home/ubuntu/.ssh/authorized_keys << 'EOF'
${ssh_public_key}
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

# 3. Install AWS CLI for metadata access and script download
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
  
  # Return empty string or default value as fallback
  echo ""
}

# Collect metadata
REGION=$(get_metadata "placement/region")
INSTANCE_ID=$(get_metadata "instance-id")
PRIVATE_IP=$(get_metadata "local-ipv4")
AZ=$(get_metadata "placement/availability-zone")

# Use defaults if metadata unavailable
REGION=${REGION:-"${region}"}
INSTANCE_ID=${INSTANCE_ID:-"unknown-$(hostname)"}
PRIVATE_IP=${PRIVATE_IP:-$(hostname -I | awk '{print $1}')}
AZ=${AZ:-"${region}a"}
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
JOIN_COMMAND_SECRET=${KUBERNETES_JOIN_COMMAND_SECRET}
JOIN_COMMAND_LATEST_SECRET=${KUBERNETES_JOIN_COMMAND_LATEST_SECRET}
EOF

# 6. Prepare and download full initialization script
mark_progress "Preparing full initialization script"

# Create the full initialization script
cat > /usr/local/bin/worker_full_init.sh << 'FULLSCRIPT'
#!/bin/bash
# Full worker node initialization script for Kubernetes cluster joining

# Set up comprehensive logging
LOGFILE="/var/log/worker-init.log"
touch $LOGFILE
chmod 644 $LOGFILE

# Redirect output
exec > >(tee -a $LOGFILE) 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting full worker node initialization"

# Error handling
set -e
trap 'echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Error at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Load metadata
if [ -f "/etc/kubernetes/worker-metadata.env" ]; then
  source /etc/kubernetes/worker-metadata.env
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Loaded instance metadata from environment file"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Cannot find metadata file"
  exit 1
fi

# Log start with instance info
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting worker node setup:"
echo "  Instance ID: $INSTANCE_ID"
echo "  Private IP: $PRIVATE_IP"
echo "  Region: $REGION"
echo "  Node name: $NODE_NAME"

# Progress tracking
mark_step() {
  local step="$1"
  local status="$2"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [$status] $step"
  echo "$step" > /var/log/worker-init-progress
  
  # Also report to CloudWatch if AWS CLI is available
  if command -v aws &> /dev/null; then
    aws cloudwatch put-metric-data --namespace "KubernetesSetup" \
      --metric-name "WorkerInitProgress" \
      --dimensions "Stage=$step,InstanceID=$INSTANCE_ID" \
      --value 1 \
      --region "$REGION" &>/dev/null || true
  fi
}

# Configure kernel modules for Kubernetes
configure_kernel_modules() {
  mark_step "ConfigureKernel" "INFO"
  
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
  
  mark_step "ConfigureKernel" "DONE"
}

# Install container runtime
install_container_runtime() {
  mark_step "ContainerRuntime" "INFO"
  
  # Install containerd
  apt-get update
  apt-get install -y containerd
  
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
  
  systemctl restart containerd
  systemctl enable containerd
  
  # Verify containerd socket
  timeout 60 bash -c 'until [ -S /run/containerd/containerd.sock ]; do sleep 2; done'
  if [ $? -ne 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Timed out waiting for containerd socket"
    exit 1
  fi
  
  mark_step "ContainerRuntime" "DONE"
}

# Install Kubernetes components
install_kubernetes() {
  mark_step "InstallKubernetes" "INFO"
  
  # Add Kubernetes repository
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list
  
  apt-get update
  apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
  apt-mark hold kubelet kubeadm kubectl
  
  # Configure kubelet
  mkdir -p /var/lib/kubelet
  cat > /var/lib/kubelet/kubeadm-flags.env << EOF
KUBELET_EXTRA_ARGS=--node-ip=$PRIVATE_IP --hostname-override=$NODE_NAME --cloud-provider=external --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --cgroup-driver=systemd
EOF
  
  systemctl daemon-reload
  systemctl restart kubelet
  
  mark_step "InstallKubernetes" "DONE"
}

# Reset any previous Kubernetes configuration
reset_kubernetes() {
  mark_step "ResetKubernetes" "INFO"
  
  # Reset kubeadm
  kubeadm reset -f
  
  # Clean up directories
  rm -rf /etc/kubernetes/bootstrap-kubelet.conf
  rm -rf /etc/kubernetes/kubelet.conf
  rm -rf /etc/kubernetes/pki
  
  # Restart kubelet
  systemctl daemon-reload
  systemctl restart kubelet
  
  mark_step "ResetKubernetes" "DONE"
}

# Retrieve join command from AWS Secrets Manager
get_join_command() {
  mark_step "GetJoinCommand" "INFO"
  local max_attempts=10
  local attempt=1
  local wait_time=10
  local join_command=""
  
  # Try latest secret first, then fallback to original
  local secrets=("$JOIN_COMMAND_LATEST_SECRET" "$JOIN_COMMAND_SECRET")
  
  while [ $attempt -le $max_attempts ]; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempt $attempt/$max_attempts to retrieve join command"
    
    for secret_name in "${secrets[@]}"; do
      echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Trying to retrieve secret: $secret_name"
      
      join_command=$(aws secretsmanager get-secret-value \
        --secret-id "$secret_name" \
        --region "$REGION" \
        --query 'SecretString' \
        --output text 2>/dev/null || echo "")
      
      if [ -n "$join_command" ] && [[ "$join_command" == *"kubeadm join"* ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Successfully retrieved join command from $secret_name"
        echo "$join_command" > /etc/kubernetes/join-command.txt
        chmod 600 /etc/kubernetes/join-command.txt
        mark_step "GetJoinCommand" "DONE"
        return 0
      fi
    done
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to retrieve join command (attempt $attempt/$max_attempts)"
    sleep $wait_time
    attempt=$((attempt + 1))
    wait_time=$((wait_time * 2))
  done
  
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] All attempts to retrieve join command failed"
  return 1
}

# Join the Kubernetes cluster
join_cluster() {
  mark_step "JoinCluster" "INFO"
  
  if [ ! -f "/etc/kubernetes/join-command.txt" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Join command file not found"
    return 1
  fi
  
  local join_command=$(cat /etc/kubernetes/join-command.txt)
  local max_attempts=5
  local attempt=1
  
  while [ $attempt -le $max_attempts ]; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempt $attempt/$max_attempts to join cluster"
    
    if eval "$join_command"; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Successfully joined the cluster!"
      mark_step "JoinCluster" "DONE"
      return 0
    else
      echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to join cluster (attempt $attempt/$max_attempts)"
      
      if [ $attempt -lt $max_attempts ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Resetting Kubernetes and retrying..."
        kubeadm reset -f
        sleep 10
      fi
    fi
    
    attempt=$((attempt + 1))
  done
  
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] All attempts to join cluster failed"
  return 1
}

# Run the initialization sequence
main() {
  # Print a summary of what will be done
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Worker node initialization plan:"
  echo "  1. Configure kernel modules and system parameters"
  echo "  2. Install container runtime (containerd)"
  echo "  3. Install Kubernetes components"
  echo "  4. Reset any previous Kubernetes configuration"
  echo "  5. Retrieve join command from AWS Secrets Manager"
  echo "  6. Join the Kubernetes cluster"
  
  # Execute each step in sequence
  configure_kernel_modules
  install_container_runtime
  install_kubernetes
  reset_kubernetes
  get_join_command || { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to get join command, cannot continue"
    exit 1
  }
  join_cluster || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to join cluster"
    exit 1
  }
  
  # Final success message
  echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Worker node successfully joined the cluster"
  touch /var/log/worker-init-complete
}

# Run the main function
main
FULLSCRIPT

# Make the script executable
chmod +x /usr/local/bin/worker_full_init.sh

# 7. Run the full initialization script in the background with nohup
mark_progress "Launching full initialization"
nohup /usr/local/bin/worker_full_init.sh > /var/log/worker-full-init.log 2>&1 &

# Final message for user-data portion
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Bootstrap complete, full initialization running in background"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Check /var/log/worker-init.log for full initialization progress"