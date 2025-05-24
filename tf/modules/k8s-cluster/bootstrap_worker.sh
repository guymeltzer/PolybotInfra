#!/bin/bash
# Robust bootstrap script for worker nodes with enhanced error handling
# Ensures proper SSH access and reliable Kubernetes cluster joining

# Set up extensive logging
LOGFILE="/var/log/worker-init.log"
DEBUG_LOG="/var/log/worker-debug.log"
TRACE_LOG="/var/log/worker-trace.log"

# Create log files with proper permissions
mkdir -p /var/log
touch $LOGFILE $DEBUG_LOG $TRACE_LOG
chmod 644 $LOGFILE $DEBUG_LOG $TRACE_LOG

# Log everything with timestamps to all logs
exec > >(tee -a $LOGFILE | tee -a $DEBUG_LOG)
exec 2>&1
set -x  # Enable command tracing to TRACE_LOG
SECONDS=0  # Track execution time
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting worker node bootstrap (v2.0.1)"

# Robust error handling
set -eE  # Exit on error with error trapping
trap 'echo "$$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Command failed at line $LINENO: \"$BASH_COMMAND\" with exit code $? after $SECONDS seconds" | tee -a $LOGFILE' ERR

# ------------------------
# 1. SSH ACCESS SETUP - Priority #1
# ------------------------
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Setting up SSH access (PRIORITY)"
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh

# Make sure we have a valid SSH key in the authorized_keys file
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Writing SSH public key to authorized_keys file"
cat > /home/ubuntu/.ssh/authorized_keys << EOF
${SSH_PUBLIC_KEY}
EOF

# Ensure proper permissions
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Copy to root user as well for emergencies
mkdir -p /root/.ssh
cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] SSH key configuration complete - Verification:"
ls -la /home/ubuntu/.ssh/
grep -v "^#" /home/ubuntu/.ssh/authorized_keys | grep -v "^$"

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

# Restart SSH daemon with proper error handling
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Restarting SSH daemon"
if systemctl restart ssh; then
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] SSH daemon restarted successfully (ssh)"
elif systemctl restart sshd; then
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] SSH daemon restarted successfully (sshd)"
else
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [WARN] Could not restart SSH service, trying to proceed anyway"
fi

# ------------------------
# 2. SYSTEM PREPARATION
# ------------------------
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q apt-transport-https ca-certificates curl gnupg lsb-release software-properties-common unzip jq net-tools iputils-ping dnsutils netcat-openbsd

# Get instance metadata with enhanced error handling
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Fetching EC2 instance metadata"
TOKEN=$$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
INSTANCE_ID=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
PRIVATE_IP=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "unknown")
PUBLIC_IP=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "unknown")
AVAILABILITY_ZONE=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone || echo "unknown")
PRIVATE_DNS=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/local-hostname || echo "unknown")
export AWS_DEFAULT_REGION="$$REGION"

echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Instance metadata:"
echo "  Instance ID: $$INSTANCE_ID"
echo "  Private IP: $$PRIVATE_IP"
echo "  Public IP: $$PUBLIC_IP"
echo "  Region: $$REGION"
echo "  AZ: $$AVAILABILITY_ZONE"
echo "  Private DNS: $$PRIVATE_DNS"

# Set hostname correctly for Kubernetes
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Setting proper hostname for Kubernetes"
NODE_NAME=$$(echo "$$PRIVATE_DNS" | sed 's/\./-/g')
hostnamectl set-hostname "$$NODE_NAME"
echo "$$PRIVATE_IP $$NODE_NAME" >> /etc/hosts
echo "127.0.0.1 $$NODE_NAME" >> /etc/hosts
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Hostname set to: $$NODE_NAME"

# ------------------------
# 3. KUBERNETES COMPONENTS
# ------------------------
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installing AWS CLI for secrets access"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installing containerd runtime"
apt-get update
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installing Kubernetes components"
mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# ------------------------
# 4. SYSTEM CONFIGURATION
# ------------------------
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Configuring system for Kubernetes"
# Configure kernel modules
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

# Configure sysctl
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
sysctl --system

# Disable swap
swapoff -a
sed -i '/ swap / s/^/#/' /etc/fstab

# ------------------------
# 5. JOIN KUBERNETES CLUSTER
# ------------------------
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Preparing to join Kubernetes cluster"

# Extremely robust join command retrieval function with enhanced error handling
get_join_command() {
  local secret_name="$1"
  local max_retries=15
  local retry_delay=10
  local attempt=1
  
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Retrieving join command from secret: $$secret_name"
  
  while [ $$attempt -le $$max_retries ]; do
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempt $$attempt/$$max_retries"
    
    # Use full error handling with verbose output
    AWS_CMD_OUTPUT=$(aws secretsmanager get-secret-value \
      --region $$REGION \
      --secret-id "$$secret_name" \
      --query "SecretString" \
      --output text 2>&1)
    local exit_code=$?
    
    if [ $$exit_code -ne 0 ]; then
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [ERROR] AWS CLI error (code $$exit_code): $$AWS_CMD_OUTPUT"
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Will retry in $$retry_delay seconds"
      sleep $$retry_delay
      attempt=$$((attempt + 1))
      continue
    fi
    
    # Validate it looks like a join command
    if [ -n "$$AWS_CMD_OUTPUT" ] && [[ "$$AWS_CMD_OUTPUT" == *"kubeadm join"* ]] && [[ "$$AWS_CMD_OUTPUT" == *"--token"* ]]; then
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Retrieved valid join command"
      echo "$$AWS_CMD_OUTPUT"
      return 0
    else
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [WARN] Retrieved invalid join command: '$$AWS_CMD_OUTPUT'"
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Will retry in $$retry_delay seconds"
      sleep $$retry_delay
      attempt=$$((attempt + 1))
    fi
  done
  
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to get join command after $$max_retries attempts"
  return 1
}

# Try multiple methods to get the join command, using full ARNs when available
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempting to retrieve join command"
JOIN_CMD=""

# Method 1: Try with latest secret ARN
LATEST_SECRET_ARN="${JOIN_COMMAND_LATEST_SECRET}" # This should be the full ARN from terraform
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Trying latest join command secret: $$LATEST_SECRET_ARN"
JOIN_CMD=$$(get_join_command "$$LATEST_SECRET_ARN")

# Method 2: Fall back to main secret
if [ -z "$$JOIN_CMD" ]; then
  MAIN_SECRET_ARN="${JOIN_COMMAND_SECRET}" # This should be the full ARN from terraform
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Trying main join command secret: $$MAIN_SECRET_ARN"
  JOIN_CMD=$$(get_join_command "$$MAIN_SECRET_ARN")
fi

# Method 3: Search for any join command secrets
if [ -z "$$JOIN_CMD" ]; then
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Searching for any join command secrets"
  SECRET_LIST=$$(aws secretsmanager list-secrets --region $$REGION --filters Key=name,Values=kubernetes-join-command --query "SecretList[*].Name" --output text)
  
  for SECRET in $$SECRET_LIST; do
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Trying secret: $$SECRET"
    JOIN_CMD=$$(get_join_command "$$SECRET")
    
    if [ -n "$$JOIN_CMD" ]; then
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Found valid join command in: $$SECRET"
      break
    fi
  done
fi

# Log results to S3 if possible
log_to_s3() {
  local log_content="$1"
  local s3_bucket="${WORKER_LOGS_BUCKET:-guy-polybot-logs}"
  local log_file="worker-init-$$INSTANCE_ID-$$(date +%Y%m%d%H%M%S).log"
  
  if command -v aws &>/dev/null; then
    echo "$$log_content" | aws s3 cp - s3://$$s3_bucket/$$log_file --region $$REGION || true
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Logs uploaded to s3://$$s3_bucket/$$log_file"
  else
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [WARN] AWS CLI not available, couldn't upload logs to S3"
  fi
}

# Handle join command execution with pre-join checks
if [ -n "$$JOIN_CMD" ]; then
  # Extract control plane IP for network diagnostics
  CP_IP=$(echo "$$JOIN_CMD" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
  
  # Pre-join network diagnostics 
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Running pre-join network diagnostics"
  
  if [ -n "$$CP_IP" ]; then
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Testing connection to control plane at $$CP_IP:6443"
    
    # Comprehensive network diagnostics
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [DIAG] Routing table:"
    ip route
    
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [DIAG] DNS resolution:"
    dig +short $(hostname)
    
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [DIAG] Control plane ping test:"
    ping -c 3 $$CP_IP || echo "Ping failed, but proceeding anyway"
    
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [DIAG] Control plane API server port check:"
    if nc -zv $$CP_IP 6443 -w 5 2>&1; then
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Connection to control plane API successful"
    else
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [WARN] Cannot connect to control plane API server, but will try joining anyway"
    fi
  else
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [WARN] Could not extract control plane IP from join command"
  fi

  # Write join command to file for execution and logging
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Preparing to execute join command"
  echo "$$JOIN_CMD" > /tmp/join_command.sh
  chmod +x /tmp/join_command.sh
  
  # Debug - show file for reference
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] Join command script content:"
  cat /tmp/join_command.sh
  
  # Execute join with multiple retries
  JOIN_SUCCESS=false
  for i in {1..5}; do
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Join attempt $$i/5"
    
    # Set a 5-minute timeout for the join command
    timeout 300 /tmp/join_command.sh --v=5 2>&1 | tee /tmp/kubeadm-join-$$i.log
    JOIN_RESULT=$?
    
    if [ $$JOIN_RESULT -eq 0 ]; then
      JOIN_SUCCESS=true
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Successfully joined the Kubernetes cluster!"
      
      # Log success to S3
      log_to_s3 "Worker node $$HOSTNAME ($$INSTANCE_ID) successfully joined the cluster at $$(date)"
      break
    else
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Join attempt $$i failed with exit code $$JOIN_RESULT"
      cat /tmp/kubeadm-join-$$i.log >> $LOGFILE
      
      if [ $$i -eq 5 ]; then
        # Log failure to S3 on last attempt
        log_to_s3 "Worker node $$HOSTNAME ($$INSTANCE_ID) failed to join the cluster after 5 attempts. Last error: $$(tail -10 /tmp/kubeadm-join-$$i.log)"
      fi
      
      echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Will retry in 30 seconds"
      sleep 30
    fi
  done
  
  if [ "$$JOIN_SUCCESS" != "true" ]; then
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [CRITICAL] Failed to join cluster after multiple attempts"
    echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Will continue with setup in case cluster join was actually successful but reported failure"
  fi
else
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [CRITICAL] Could not retrieve join command from any source"
  echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Will continue with setup anyway to prepare node"
  
  # Log failure to S3
  log_to_s3 "Worker node $$HOSTNAME ($$INSTANCE_ID) failed to retrieve join command from Secrets Manager at $$(date)"
fi

# ------------------------
# 6. KUBELET CONFIGURATION
# ------------------------
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Configuring kubelet"

# Configure kubelet with correct parameters
cat > /etc/default/kubelet << EOF
KUBELET_EXTRA_ARGS="--node-ip=$$PRIVATE_IP --hostname-override=$$NODE_NAME --cloud-provider=external --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --cgroup-driver=systemd"
EOF

# Restart kubelet to apply configuration
systemctl daemon-reload
systemctl enable kubelet
systemctl restart kubelet

# Print kubelet status for diagnostics
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Kubelet status:"
systemctl status kubelet --no-pager || true

# Print kubelet logs for diagnostics
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Kubelet logs:"
journalctl -u kubelet --no-pager -n 50 || true

# Check if node appears in the cluster
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Checking if node appears in the cluster"
if [ -f "/etc/kubernetes/kubelet.conf" ]; then
  kubectl --kubeconfig=/etc/kubernetes/kubelet.conf get node "$$NODE_NAME" || echo "Node not yet visible in cluster"
fi

# ------------------------
# 7. FINALIZATION
# ------------------------
# Create summary logs for easy access
mkdir -p /home/ubuntu
cp $LOGFILE /home/ubuntu/worker-init-summary.log
chmod 644 /home/ubuntu/worker-init-summary.log
chown ubuntu:ubuntu /home/ubuntu/worker-init-summary.log

# Report completion
RUNTIME=$SECONDS
echo "$$(date '+%Y-%m-%d %H:%M:%S') [INFO] Worker node bootstrap completed in $$(($RUNTIME / 60)) minutes and $$(($RUNTIME % 60)) seconds"
exit 0 
