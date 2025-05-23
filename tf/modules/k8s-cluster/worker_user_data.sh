#!/bin/bash
# Enhanced worker initialization script for AWS EC2 with debug support
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

log_section "Starting worker node bootstrap"
debug_checkpoint "INIT"

# Ensure ubuntu user can access the logs
mkdir -p /home/ubuntu
touch $${DEBUG_LOG}
chown ubuntu:ubuntu $${DEBUG_LOG}
chmod 644 $${DEBUG_LOG}

export DEBIAN_FRONTEND=noninteractive

# SSH setup function with verification
setup_ssh() {
  echo "Setting up SSH access..."
  
  # Create .ssh directory with proper permissions
  mkdir -p /home/ubuntu/.ssh
  chmod 700 /home/ubuntu/.ssh
  
  # Add authorized key with explicit newline and hash
  cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
${ssh_public_key}
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
    systemctl restart ssh
  fi
  
  # Verify PubkeyAuthentication is enabled
  if ! grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
    echo "Ensuring PubkeyAuthentication is enabled"
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    systemctl restart sshd
  fi
  
  # Ensure sshd is running
  systemctl status ssh
  
  echo "SSH setup completed successfully"
}

# Setup core services
setup_core() {
  log_section "Setting up core services"
  
  log_info "Updating package lists and installing dependencies"
  apt-get update && apt-get install -y curl unzip jq apt-transport-https ca-certificates gnupg || {
    log_info "WARNING: Some packages may have failed to install, continuing anyway"
  }
  
  log_info "Installing AWS CLI"
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip aws/
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
  KUBERNETES_JOIN_COMMAND_SECRET="${KUBERNETES_JOIN_COMMAND_SECRET}"
  KUBERNETES_JOIN_COMMAND_LATEST_SECRET="${KUBERNETES_JOIN_COMMAND_LATEST_SECRET}"
  SECRET_NAMES=("$KUBERNETES_JOIN_COMMAND_SECRET" "$KUBERNETES_JOIN_COMMAND_LATEST_SECRET")
  
  echo "Attempting to join Kubernetes cluster..."
  
  # Try to get join command from secrets manager with enhanced retry
  MAX_RETRIES=20
  for ((ATTEMPT=1; ATTEMPT<=MAX_RETRIES; ATTEMPT++)); do
    echo "Join attempt $ATTEMPT/$MAX_RETRIES"
    JOIN_COMMAND=""
    
    # Try known secrets
    for SECRET_NAME in "${SECRET_NAMES[@]}"; do
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
      ALL_SECRETS=$(aws secretsmanager list-secrets --region "$REGION" --filters Key=name,Values=kubernetes-join-command --query "SecretList[*].Name" --output text 2>/dev/null || echo "")
      if [ -n "$ALL_SECRETS" ]; then
        echo "Found these secrets: $ALL_SECRETS"
        # Try each secret to find a valid join command
        for SECRET in $ALL_SECRETS; do
          echo "Trying secret: $SECRET"
          SECRET_VALUE=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" --query SecretString --output text 2>/dev/null || echo "")
          if [[ -n "$SECRET_VALUE" && "$SECRET_VALUE" =~ ^kubeadm\ join ]]; then
            JOIN_COMMAND="$SECRET_VALUE"
            echo "Found valid join command in $SECRET: $JOIN_COMMAND"
            break
          fi
        done
      else
        echo "No kubernetes-join-command secrets found"
      fi
      
      # If still no valid join command, query EC2 for control plane IP
      if [[ -z "$JOIN_COMMAND" || ! "$JOIN_COMMAND" =~ --token ]]; then
        CONTROL_PLANE_IP=$(aws ec2 describe-instances --region "$REGION" \
                            --filters "Name=tag:Name,Values=k8s-control-plane" \
                                      "Name=instance-state-name,Values=running" \
                            --query "Reservations[0].Instances[0].PrivateIpAddress" \
                            --output text)
        
        if [[ -n "$CONTROL_PLANE_IP" && "$CONTROL_PLANE_IP" != "None" ]]; then
          echo "Found control plane IP: $CONTROL_PLANE_IP"
          
          # Try to get token from existing join command or generate new one
          TOKEN=""
          DISCOVERY_HASH=""
          
          if [[ -n "$JOIN_COMMAND" ]]; then
            # Extract token and hash from existing command
            TOKEN=$(echo "$JOIN_COMMAND" | grep -oP -- '--token \K[^ ]+' || echo "")
            DISCOVERY_HASH=$(echo "$JOIN_COMMAND" | grep -oP -- '--discovery-token-ca-cert-hash \K[^ ]+' || echo "")
          fi
          
          # Generate token if we couldn't extract it
          if [ -z "$TOKEN" ]; then
            TOKEN=$(kubeadm token generate)
          fi
          
          # Create new join command with current control plane IP
          if [ -n "$DISCOVERY_HASH" ]; then
            JOIN_COMMAND="kubeadm join $${CONTROL_PLANE_IP}:6443 --token $TOKEN --discovery-token-ca-cert-hash $DISCOVERY_HASH"
          else
            JOIN_COMMAND="kubeadm join $${CONTROL_PLANE_IP}:6443 --token $TOKEN --discovery-token-unsafe-skip-ca-verification"
          fi
          
          echo "Created new join command: $JOIN_COMMAND"
        else
          echo "Failed to find control plane IP"
        fi
      fi
    fi
    
    # Exit if we can't get a join command
    if [ -z "$JOIN_COMMAND" ]; then
      echo "Failed to retrieve join command, will retry in $((ATTEMPT * 5)) seconds..."
      sleep $((ATTEMPT * 5))
      continue
    fi
    
    # Try executing the join command
    echo "Executing join command: $JOIN_COMMAND"
    if eval $JOIN_COMMAND --v=5; then
      echo "Successfully joined the cluster!"
      systemctl restart kubelet
      
      # Signal success after joining
      if [ -f "/etc/kubernetes/kubelet.conf" ]; then
        echo "Setting provider ID for the node..."
        kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" --kubeconfig=/etc/kubernetes/kubelet.conf || true
      fi
      
      # Complete lifecycle action
      echo "Completing lifecycle action..."
      aws autoscaling complete-lifecycle-action \
        --lifecycle-hook-name "guy-scale-up-hook" \
        --auto-scaling-group-name "guy-polybot-asg" \
        --lifecycle-action-result "CONTINUE" \
        --instance-id "$INSTANCE_ID" \
        --region "$REGION" 2>/dev/null || true
      
      # Tag the instance
      echo "Tagging instance..."
      aws ec2 create-tags \
        --region "$REGION" \
        --resources "$INSTANCE_ID" \
        --tags Key=node-role.kubernetes.io/worker,Value=true \
               Key=k8s.io/autoscaled-node,Value=true \
               Key=Name,Value="$NODE_NAME" 2>/dev/null || true
      
      upload_logs_to_s3 "COMPLETE"
      echo "Kubernetes worker node initialization completed successfully"
      
      # Verify SSH is properly configured before ending
      setup_ssh
      
      return 0
    else
      echo "Join command failed, will retry in $((ATTEMPT * 5)) seconds..."
      sleep $((ATTEMPT * 5))
    fi
  done
  
  echo "All join attempts failed after $MAX_RETRIES tries."
  upload_logs_to_s3 "JOIN_FAILED"
  exit 1
}

# Main execution with better error handling and debug reporting
log_section "Beginning main execution flow"

# Run each function with debug checkpoints
setup_core || {
  log_info "CRITICAL: Core setup failed - see error details above"
  debug_checkpoint "CORE_SETUP_FAILED"
  exit 1
}
debug_checkpoint "CORE_SETUP_COMPLETE"

setup_kube || {
  log_info "CRITICAL: Kubernetes setup failed - see error details above"
  debug_checkpoint "KUBE_SETUP_FAILED"
  exit 1
}
debug_checkpoint "KUBE_SETUP_COMPLETE"

join_cluster || {
  log_info "CRITICAL: Failed to join cluster - see error details above"
  debug_checkpoint "JOIN_CLUSTER_FAILED"
  exit 1
}
debug_checkpoint "JOIN_CLUSTER_COMPLETE"

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