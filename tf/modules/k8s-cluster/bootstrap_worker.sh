#!/bin/bash
# Minimal bootstrap script for worker nodes
# This script will download a more complete initialization script from S3

# Set up minimal logging
LOGFILE="/var/log/worker-init.log"
touch $$LOGFILE
chmod 644 $$LOGFILE
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting minimal worker node bootstrap"
exec > >(tee -a $$LOGFILE) 2>&1

# Critical step 1: SSH access setup (highest priority)
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Setting up SSH access (PRIORITY)"
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh

# Write SSH public key to authorized_keys
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Writing SSH public key"
cat > /home/ubuntu/.ssh/authorized_keys << EOF
${SSH_PUBLIC_KEY}
EOF

chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Copy to root user as well for emergencies
mkdir -p /root/.ssh
cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Configure SSH daemon for key-based auth
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Configuring SSH daemon"
cat > /etc/ssh/sshd_config.d/99-custom.conf << EOF
# Enhanced SSH configuration for security
Port 22
AddressFamily inet
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Restart SSH daemon
systemctl restart ssh || systemctl restart sshd || true

# Critical step 2: Install basic dependencies
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installing essential dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q apt-transport-https ca-certificates curl unzip jq

# Install AWS CLI for downloading full script from S3
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# Get instance metadata for identification
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Fetching instance metadata"
TOKEN=$$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
INSTANCE_ID=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
PRIVATE_IP=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "unknown")
export AWS_DEFAULT_REGION="$$REGION"

# Write instance metadata to file for later use
cat > /tmp/instance_metadata.json << EOF
{
  "instance_id": "$$INSTANCE_ID",
  "private_ip": "$$PRIVATE_IP",
  "region": "$$REGION",
  "join_command_secret": "${JOIN_COMMAND_SECRET}",
  "join_command_latest_secret": "${JOIN_COMMAND_LATEST_SECRET}",
  "worker_logs_bucket": "${WORKER_LOGS_BUCKET}"
}
EOF

echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading full initialization script from S3"

# Generate a file that will contain the full initialization script
cat > /usr/local/bin/worker_full_init.sh << 'EOF'
#!/bin/bash
# Full worker node initialization script downloaded from bootstrap

# Set up extensive logging
LOGFILE="/var/log/worker-init-full.log"
DEBUG_LOG="/var/log/worker-debug.log"
touch $LOGFILE $DEBUG_LOG
chmod 644 $LOGFILE $DEBUG_LOG

# Log with timestamps
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" | tee -a $LOGFILE
}

# Error handling
handle_error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] An error occurred at line $1: $2" | tee -a $LOGFILE $DEBUG_LOG
}

trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

log "Starting full worker initialization script"

# Load instance metadata
METADATA_FILE="/tmp/instance_metadata.json"
if [ -f "$METADATA_FILE" ]; then
  INSTANCE_ID=$(jq -r '.instance_id' $METADATA_FILE)
  PRIVATE_IP=$(jq -r '.private_ip' $METADATA_FILE)
  REGION=$(jq -r '.region' $METADATA_FILE)
  JOIN_COMMAND_SECRET=$(jq -r '.join_command_secret' $METADATA_FILE)
  JOIN_COMMAND_LATEST_SECRET=$(jq -r '.join_command_latest_secret' $METADATA_FILE)
  WORKER_LOGS_BUCKET=$(jq -r '.worker_logs_bucket' $METADATA_FILE)
  log "Loaded metadata: Instance=$INSTANCE_ID, IP=$PRIVATE_IP, Region=$REGION"
else
  log "Metadata file not found, falling back to environment"
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "unknown")
fi

# Configure Kubernetes components
log "Installing Kubernetes components"
mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# Install containerd runtime
log "Installing containerd runtime"
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# Configure kernel modules for Kubernetes
log "Configuring system for Kubernetes"
cat > /etc/modules-load.d/k8s.conf << EOFMODULES
overlay
br_netfilter
EOFMODULES
modprobe overlay
modprobe br_netfilter

# Configure sysctl
cat > /etc/sysctl.d/k8s.conf << EOFSYSCTL
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOFSYSCTL
sysctl --system

# Disable swap
swapoff -a
sed -i '/ swap / s/^/#/' /etc/fstab

# Function to retrieve join command with retries
get_join_command() {
  local max_attempts=10
  local attempt=1
  local delay=10
  local join_cmd=""
  
  log "Retrieving join command from AWS Secrets Manager"
  
  while [ $attempt -le $max_attempts ]; do
    log "Attempt $attempt/$max_attempts to get join command"
    
    # Try the latest secret first
    join_cmd=$(aws secretsmanager get-secret-value \
      --secret-id "$JOIN_COMMAND_LATEST_SECRET" \
      --region "$REGION" \
      --query SecretString \
      --output text 2>/dev/null)
    
    # Validate the join command format
    if [ -n "$join_cmd" ] && [[ "$join_cmd" == *"kubeadm join"* ]] && [[ "$join_cmd" == *"--token"* ]]; then
      log "Successfully retrieved valid join command"
      echo "$join_cmd"
      return 0
    fi
    
    # If latest secret failed, try the main secret
    join_cmd=$(aws secretsmanager get-secret-value \
      --secret-id "$JOIN_COMMAND_SECRET" \
      --region "$REGION" \
      --query SecretString \
      --output text 2>/dev/null)
    
    if [ -n "$join_cmd" ] && [[ "$join_cmd" == *"kubeadm join"* ]] && [[ "$join_cmd" == *"--token"* ]]; then
      log "Successfully retrieved valid join command from main secret"
      echo "$join_cmd"
      return 0
    fi
    
    log "Failed to get valid join command on attempt $attempt, will retry in $delay seconds"
    sleep $delay
    attempt=$((attempt + 1))
    delay=$((delay + 5))  # Gradually increase delay
  done
  
  log "Failed to retrieve join command after $max_attempts attempts"
  return 1
}

# Validate control plane API server is accessible
validate_api_server() {
  local api_ip="$1"
  log "Validating API server at $api_ip:6443"
  
  # Try a simple TCP connection first
  if nc -z -w 5 "$api_ip" 6443; then
    log "API server port is reachable"
    return 0
  else
    log "API server port 6443 is not reachable, joining may fail"
    return 1
  fi
}

# Get join command
JOIN_CMD=$(get_join_command)

if [ -n "$JOIN_CMD" ]; then
  # Extract control plane IP from join command
  CP_IP=$(echo "$JOIN_CMD" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
  
  if [ -n "$CP_IP" ]; then
    log "Control plane IP extracted: $CP_IP"
    validate_api_server "$CP_IP"
  else
    log "Could not extract control plane IP from join command"
  fi
  
  # Execute join command with retry logic
  log "Executing join command"
  echo "$JOIN_CMD" > /tmp/join_command.sh
  chmod +x /tmp/join_command.sh
  
  for i in {1..3}; do
    log "Join attempt $i/3"
    if /tmp/join_command.sh --v=5; then
      log "Successfully joined the Kubernetes cluster!"
      break
    else
      log "Join attempt $i failed, will retry in 30 seconds"
      sleep 30
    fi
  done
else
  log "Failed to get join command, cannot join cluster"
  exit 1
fi

# Configure kubelet with correct parameters
log "Configuring kubelet"
cat > /etc/default/kubelet << EOFKUBELET
KUBELET_EXTRA_ARGS="--node-ip=$PRIVATE_IP --hostname-override=$(hostname) --cloud-provider=external --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --cgroup-driver=systemd"
EOFKUBELET

# Restart kubelet to apply configuration
systemctl daemon-reload
systemctl enable kubelet
systemctl restart kubelet

log "Worker node initialization completed successfully"
exit 0
EOF

chmod +x /usr/local/bin/worker_full_init.sh

# Upload the full script to S3 for reference
if command -v aws &>/dev/null; then
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Uploading full initialization script to S3"
  aws s3 cp /usr/local/bin/worker_full_init.sh s3://${WORKER_LOGS_BUCKET}/scripts/worker_full_init-$$INSTANCE_ID.sh --region $$REGION || true
fi

# Execute the full initialization script
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Executing full initialization script"
nohup bash /usr/local/bin/worker_full_init.sh > /var/log/worker-full-init.log 2>&1 &

# Bootstrap phase completed successfully
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Bootstrap phase completed, full initialization running in background"
exit 0 
