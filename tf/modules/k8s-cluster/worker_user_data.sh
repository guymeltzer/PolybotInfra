#!/bin/bash
# Bootstrap script for worker nodes - uses minimal footprint to stay under user-data limit
# This is a minimal bootstrap script that will download and execute the full initialization script

# Initialize logging
LOG_DIR="/var/log"
LOGFILE="$LOG_DIR/worker-init.log"
DEBUG_LOG="/home/ubuntu/bootstrap-debug.log"

# Create directories
mkdir -p /home/ubuntu
touch $LOGFILE $DEBUG_LOG
chmod 644 $LOGFILE $DEBUG_LOG
chown ubuntu:ubuntu $DEBUG_LOG

# Start logging
exec > >(tee -a $LOGFILE $DEBUG_LOG) 2>&1
echo "$(date) - Starting worker node bootstrap (minimal version)"

# Error handling
set -e
trap 'echo "$(date) - CRITICAL ERROR at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Install basic dependencies
echo "$(date) - Installing minimal dependencies..."
apt-get update && apt-get install -y curl unzip jq ca-certificates || {
    echo "WARNING: Basic package install failed, continuing anyway"
}

# Get instance metadata
echo "$(date) - Fetching EC2 instance metadata..."
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
export AWS_DEFAULT_REGION="$REGION"

# Download and run the full script
echo "$(date) - Downloading full worker initialization script..."

# Set S3 bucket and script name 
S3_BUCKET="guy-polybot-scripts"
SCRIPT_NAME="worker_full_init.sh"
LOCAL_SCRIPT="/tmp/$SCRIPT_NAME"

# Create the full initialization script in S3 if it doesn't exist
cat > "$LOCAL_SCRIPT" << 'FULLSCRIPT'
#!/bin/bash
# Enhanced worker initialization script for AWS EC2 with debug support

# Check if arguments were provided
if [ "$#" -eq 3 ]; then
  # Get parameters from command line
  SSH_PUBLIC_KEY="$1"
  JOIN_COMMAND_SECRET="$2"
  JOIN_COMMAND_LATEST_SECRET="$3"
else
  # Default values (template placeholders)
  SSH_PUBLIC_KEY="${ssh_public_key}"
  JOIN_COMMAND_SECRET="${KUBERNETES_JOIN_COMMAND_SECRET}"
  JOIN_COMMAND_LATEST_SECRET="${KUBERNETES_JOIN_COMMAND_LATEST_SECRET}"
fi

LOGFILE="/var/log/worker-init.log"
DEBUG_LOG="/home/ubuntu/bootstrap-debug.log"

# Setup dual logging to both files
exec > >(tee -a $${LOGFILE} $${DEBUG_LOG}) 2>&1

# Better debug information
set -x  # Show commands as they execute

# Error handling
set -e  # Exit on error
trap 'echo "$(date) - CRITICAL ERROR at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?" | tee -a $${LOGFILE} $${DEBUG_LOG}; echo "FAIL POINT: LINE $LINENO" > /home/ubuntu/FAILURE_POINT.txt' ERR

# Print an informational message with timestamps
log_info() {
  echo "$(date) - INFO: $1" | tee -a $${LOGFILE} $${DEBUG_LOG}
}

# Print a debug checkpoint
debug_checkpoint() {
  echo "$(date) - CHECKPOINT $1: Reached this point successfully" | tee -a $${LOGFILE} $${DEBUG_LOG}
  echo "$1" > /home/ubuntu/LAST_CHECKPOINT.txt
}

# Print a major section header
log_section() {
  echo "$(date) - ===== SECTION: $1 =====" | tee -a $${LOGFILE} $${DEBUG_LOG}
}

log_section "Starting worker node bootstrap (full script)"
debug_checkpoint "INIT"

export DEBIAN_FRONTEND=noninteractive

# SSH setup function with verification
setup_ssh() {
  echo "Setting up SSH access..."
  
  # Create .ssh directory with proper permissions
  mkdir -p /home/ubuntu/.ssh
  chmod 700 /home/ubuntu/.ssh
  
  # Add authorized key with explicit newline and hash
  cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
$SSH_PUBLIC_KEY
EOF
  
  # Set correct ownership and permissions
  chmod 600 /home/ubuntu/.ssh/authorized_keys
  chown -R ubuntu:ubuntu /home/ubuntu/.ssh
  
  # Debug
  echo "============= SSH DEBUG INFO ==============="
  ls -la /home/ubuntu/.ssh/
  echo "authorized_keys content:"
  cat /home/ubuntu/.ssh/authorized_keys
  echo "authorized_keys permissions: $(stat -c "%a" /home/ubuntu/.ssh/authorized_keys)"
  echo "SSH directory permissions: $(stat -c "%a" /home/ubuntu/.ssh)"
  echo "============= END SSH DEBUG ==============="
  
  # Ensure sshd is configured properly
  if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
    echo "Configuring sshd to disallow password authentication"
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd || echo "WARNING: Failed to restart SSH service"
  fi
  
  # Verify PubkeyAuthentication is enabled
  if ! grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
    echo "Ensuring PubkeyAuthentication is enabled"
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    # Try both service names for different distros
    systemctl restart ssh || systemctl restart sshd || echo "WARNING: Failed to restart SSH service"
  fi
  
  # Ensure sshd is running - try both service names
  systemctl status ssh || systemctl status sshd || echo "WARNING: SSH service status check failed"
  
  echo "SSH setup completed successfully"
}

# Setup core services
setup_core() {
  log_section "Setting up core services"
  
  log_info "Updating package lists and installing dependencies"
  # Make sure to install unzip first for AWS CLI
  apt-get update && apt-get install -y curl apt-transport-https ca-certificates gnupg || {
    log_info "WARNING: Basic package install failed, attempting individually"
    apt-get install -y curl || log_info "WARNING: Failed to install curl"
    apt-get install -y apt-transport-https || log_info "WARNING: Failed to install apt-transport-https"
    apt-get install -y ca-certificates || log_info "WARNING: Failed to install ca-certificates"
    apt-get install -y gnupg || log_info "WARNING: Failed to install gnupg"
  }
  
  # Install unzip separately (critical for AWS CLI)
  log_info "Installing unzip (required for AWS CLI)"
  apt-get install -y unzip || {
    log_info "ERROR: Failed to install unzip, trying alternative approach"
    # Try to fix package lists and retry
    apt-get update --fix-missing
    apt-get install -y unzip
  }
  
  # Install jq (critical for parsing AWS responses)
  log_info "Installing jq (required for AWS response parsing)"
  apt-get install -y jq || log_info "WARNING: Failed to install jq, some AWS functionality may fail"
  
  # Try to install netcat with correct package name
  log_info "Installing netcat for connectivity tests"
  apt-get install -y netcat-openbsd || {
    log_info "WARNING: Failed to install netcat-openbsd, falling back to netcat-traditional"
    apt-get install -y netcat-traditional || log_info "WARNING: Failed to install netcat, connectivity tests may fail"
  }
  
  log_info "Installing AWS CLI"
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  # Check if unzip is actually available
  if command -v unzip &> /dev/null; then
    unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip aws/
  else
    log_info "ERROR: unzip command not available after attempted install. Using alternative method."
    # Alternative installation method if unzip failed
    apt-get install -y python3-pip
    pip3 install awscli
  fi
  debug_checkpoint "AWS_CLI_INSTALLED"
  
  # Get AWS metadata - using IMDSv2 with fallbacks
  log_info "Fetching EC2 instance metadata..."
  
  # Try IMDSv2 first
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
  AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
  
  # Fallback to IMDSv1 if needed
  if [ -z "$REGION" ]; then
    echo "IMDSv2 failed, falling back to IMDSv1"
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
  fi
  
  # Last resort fallback
  if [ -z "$REGION" ]; then
    echo "Metadata service unavailable, using defaults"
    REGION="us-east-1"
    PRIVATE_IP=$(hostname -I | awk '{print $1}')
    INSTANCE_ID=$(hostname)
    AZ="$${REGION}a"
  fi
  
  PROVIDER_ID="aws:///$${AZ}/$${INSTANCE_ID}"
  export AWS_DEFAULT_REGION="$REGION"
  
  echo "Instance metadata: Region=$REGION, IP=$PRIVATE_IP, ID=$INSTANCE_ID, AZ=$AZ"
  
  # Setup SSH access
  setup_ssh
  
  # Save important vars to a file that can be sourced later
  cat > /etc/profile.d/k8s-vars.sh << EOF
export REGION="$REGION"
export PRIVATE_IP="$PRIVATE_IP"
export INSTANCE_ID="$INSTANCE_ID"
export AZ="$AZ"
export PROVIDER_ID="$PROVIDER_ID"
EOF
  
  # S3 log upload helper
  upload_logs_to_s3() {
    [ -n "$INSTANCE_ID" ] && aws s3 cp "$LOGFILE" "s3://guy-polybot-logs/worker-init-$${INSTANCE_ID}-$1-$(date +%Y%m%d-%H%M%S).log" --region "$REGION" 2>/dev/null || true
  }
  
  # Upload init logs
  upload_logs_to_s3 "INIT"
}

# Install and configure Kubernetes prerequisites
setup_kube() {
  log_section "Setting up Kubernetes prerequisites"
  
  # Setup networking with better error handling
  log_info "Configuring kernel modules for Kubernetes"
  cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
  
  log_info "Loading required kernel modules"
  modprobe overlay || log_info "WARNING: Failed to load overlay module, continuing anyway"
  modprobe br_netfilter || log_info "WARNING: Failed to load br_netfilter module, continuing anyway"
  debug_checkpoint "KERNEL_MODULES_LOADED"
  
  log_info "Setting up network sysctl parameters"
  cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
  
  log_info "Applying sysctl settings"
  sysctl --system
  debug_checkpoint "SYSCTL_CONFIGURED"
  
  # Set hostname
  COUNTER=$(aws ssm get-parameter --name "/k8s/worker-node-counter" --region "$REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "0")
  NEXT_COUNTER=$((COUNTER + 1))
  aws ssm put-parameter --name "/k8s/worker-node-counter" --value "$NEXT_COUNTER" --type String --overwrite --region "$REGION" 2>/dev/null
  NODE_NAME="guy-worker-node-$NEXT_COUNTER"
  hostnamectl set-hostname "$NODE_NAME"
  echo "127.0.0.1 $NODE_NAME" >> /etc/hosts
  
  # Install containerd
  apt-get install -y containerd
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
  systemctl restart containerd && systemctl enable containerd
  
  # Install Kubernetes
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" > /etc/apt/sources.list.d/kubernetes.list
  apt-get update && apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
  apt-mark hold kubelet kubeadm kubectl
  
  # Configure kubelet
  mkdir -p /var/lib/kubelet /etc/kubernetes
  echo "KUBELET_EXTRA_ARGS=--cgroup-driver=systemd --cloud-provider=external --provider-id=$${PROVIDER_ID}" > /var/lib/kubelet/kubeadm-flags.env
  
  # Disable swap
  swapoff -a && sed -i '/swap/d' /etc/fstab
  systemctl daemon-reload && systemctl restart kubelet
}

# Join the Kubernetes cluster
join_cluster() {
  # Define secret names
  KUBERNETES_JOIN_COMMAND_SECRET="$JOIN_COMMAND_SECRET"
  KUBERNETES_JOIN_COMMAND_LATEST_SECRET="$JOIN_COMMAND_LATEST_SECRET"
  SECRET_NAMES=("$${KUBERNETES_JOIN_COMMAND_SECRET}" "$${KUBERNETES_JOIN_COMMAND_LATEST_SECRET}")
  
  echo "Attempting to join Kubernetes cluster..."
  
  # Try to get join command from secrets manager with enhanced retry
  MAX_RETRIES=20
  for ((ATTEMPT=1; ATTEMPT<=MAX_RETRIES; ATTEMPT++)); do
    echo "Join attempt $ATTEMPT/$MAX_RETRIES"
    JOIN_COMMAND=""
    
    # Try known secrets
    for SECRET_NAME in "$${SECRET_NAMES[@]}"; do
      echo "Checking secret: $SECRET_NAME"
      SECRET_VALUE=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_NAME" 2>/dev/null || echo "")
      if [ -n "$SECRET_VALUE" ]; then
        JOIN_COMMAND=$(echo "$SECRET_VALUE" | jq -r '.SecretString' 2>/dev/null || echo "$SECRET_VALUE" | grep -o 'SecretString.*' | cut -d '"' -f 3)
        if [[ -n "$JOIN_COMMAND" && "$JOIN_COMMAND" =~ ^kubeadm\ join ]]; then
          echo "Found join command in $SECRET_NAME: $JOIN_COMMAND"
          break
        else
          echo "Invalid join command format in $SECRET_NAME: $JOIN_COMMAND"
        fi
      else
        echo "Failed to retrieve $SECRET_NAME or secret is empty"
      fi
    done
    
    # If no command found or command contains old IP, try to get current control plane IP
    if [[ -z "$JOIN_COMMAND" || ! "$JOIN_COMMAND" =~ --token ]]; then
      echo "No valid join command found in secrets, querying for control plane IP..."
      
      # Try listing all secrets with kubernetes-join-command prefix
      echo "Listing all kubernetes-join-command secrets..."
      ALL_SECRETS=$(aws secretsmanager list-secrets --region "$REGION" --filters Key=name,Values=kubernetes-join-command --query 'SecretList[*].Name' --output text 2>/dev/null || echo "")
      
      if [ -n "$ALL_SECRETS" ]; then
        echo "Found these secrets: $ALL_SECRETS"
        # Try each secret until we find a valid join command
        for SECRET in $ALL_SECRETS; do
          echo "Trying secret: $SECRET"
          SECRET_VALUE=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" --query SecretString --output text 2>/dev/null || echo "")
          if [ -n "$SECRET_VALUE" ]; then
            if [[ "$SECRET_VALUE" =~ ^kubeadm\ join ]]; then
              JOIN_COMMAND="$SECRET_VALUE"
              echo "Found valid join command in $SECRET: $JOIN_COMMAND"
              break
            fi
          fi
        done
      fi
    fi
    
    if [ -z "$JOIN_COMMAND" ]; then
      echo "Could not find valid join command in any secret, will retry in 30 seconds..."
      sleep 30
      continue
    fi
    
    if [[ ! "$JOIN_COMMAND" =~ --token ]]; then
      echo "Join command does not contain a token, will retry in 30 seconds..."
      sleep 30
      continue
    fi
    
    # Extract control plane IP from join command to verify connectivity
    CP_IP=$(echo "$JOIN_COMMAND" | grep -oP '^\s*kubeadm\s+join\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "")
    if [ -n "$CP_IP" ]; then
      echo "Extracted control plane IP: $CP_IP, testing connectivity..."
      if nc -z -w 5 "$CP_IP" 6443; then
        echo "Connection to control plane API server ($CP_IP:6443) successful!"
      else
        echo "Cannot connect to control plane API server ($CP_IP:6443), will retry in 30 seconds..."
        sleep 30
        continue
      fi
    fi
    
    # Execute join command with additional verbosity for logging
    echo "Executing join command: $JOIN_COMMAND"
    if eval $JOIN_COMMAND --v=5; then
      echo "Successfully joined the cluster!"
      return 0
    else
      echo "Join command failed, will retry in 5 seconds..."
      sleep 5
    fi
  done
  
  echo "Failed to join the cluster after $MAX_RETRIES attempts!"
  return 1
}

# Main script

# Set a maximum retry count for the whole script
TOTAL_MAX_RETRIES=3
TOTAL_RETRY=0

setup_core
setup_kube

# Main init with retry
while [ $TOTAL_RETRY -lt $TOTAL_MAX_RETRIES ]; do
  log_section "Joining Kubernetes cluster (Attempt $((TOTAL_RETRY+1))/$TOTAL_MAX_RETRIES)"
  
  if join_cluster; then
    log_section "Kubernetes worker initialization SUCCESSFUL"
    
    # Signal success after joining
    log_info "Setting provider ID for the node..."
    if [ -f "/etc/kubernetes/kubelet.conf" ]; then
      systemctl restart kubelet
      sleep 5
      kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" --kubeconfig=/etc/kubernetes/kubelet.conf || true
    fi
    
    # Complete lifecycle action
    log_info "Completing lifecycle action..."
    aws autoscaling complete-lifecycle-action \
      --lifecycle-hook-name "guy-scale-up-hook" \
      --auto-scaling-group-name "guy-polybot-asg" \
      --lifecycle-action-result "CONTINUE" \
      --instance-id "$INSTANCE_ID" \
      --region "$REGION" 2>/dev/null || true
    
    # Tag the instance
    log_info "Tagging instance..."
    aws ec2 create-tags \
      --region "$REGION" \
      --resources "$INSTANCE_ID" \
      --tags Key=node-role.kubernetes.io/worker,Value=true \
             Key=k8s.io/autoscaled-node,Value=true \
             Key=Name,Value="$NODE_NAME" 2>/dev/null || true
    
    upload_logs_to_s3 "COMPLETE"
    log_info "Kubernetes worker node initialization completed successfully"
    
    # Verify SSH is properly configured before ending
    setup_ssh
    
    # Final checkpoint
    debug_checkpoint "COMPLETE"
    exit 0
  else
    log_info "Join attempt $((TOTAL_RETRY+1)) failed, waiting before retry..."
    TOTAL_RETRY=$((TOTAL_RETRY+1))
    
    if [ $TOTAL_RETRY -lt $TOTAL_MAX_RETRIES ]; then
      log_info "Waiting 60 seconds before next retry..."
      sleep 60
    else
      log_info "All join attempts failed."
      upload_logs_to_s3 "JOIN_FAILED"
      debug_checkpoint "FAILED"
      exit 1
    fi
  fi
done

# Create a DEBUG version of the logs with easy-to-scan checkpoints
log_section "WORKER NODE INITIALIZATION COMPLETE" 
grep "CHECKPOINT\|SECTION\|CRITICAL ERROR\|FAIL POINT" $${DEBUG_LOG} > /home/ubuntu/init_progress.log || true

# Create summary log file in ubuntu's home directory for easy access
log_info "Creating log summary file for easy access"
cat $${LOGFILE} > /home/ubuntu/init_summary.log
chown ubuntu:ubuntu /home/ubuntu/init_summary.log
chmod 644 /home/ubuntu/init_summary.log
chown ubuntu:ubuntu /home/ubuntu/init_progress.log 2>/dev/null || true
chmod 644 /home/ubuntu/init_progress.log 2>/dev/null || true

# Final log upload with summary status
upload_logs_to_s3 "FINAL"

echo "=================================================="
echo "✅ WORKER NODE INITIALIZATION COMPLETE"
echo "View logs with: cat /home/ubuntu/init_summary.log"
echo "View debug progress: cat /home/ubuntu/init_progress.log"
echo "=================================================="
FULLSCRIPT

# Make the script executable
chmod +x "$LOCAL_SCRIPT"

# Execute the full script, passing in all the required variables
echo "$(date) - Starting full worker initialization..."
$LOCAL_SCRIPT \
  "${SSH_PUBLIC_KEY}" \
  "${JOIN_COMMAND_SECRET}" \
  "${JOIN_COMMAND_LATEST_SECRET}"

# Exit with the exit code of the full script
EXIT_CODE=$?
echo "$(date) - Worker initialization completed with exit code: $EXIT_CODE"
exit $EXIT_CODE