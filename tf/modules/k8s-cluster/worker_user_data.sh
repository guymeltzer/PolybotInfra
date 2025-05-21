#!/bin/bash
# Compact worker initialization script for AWS EC2
LOGFILE="/var/log/k8s-worker-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
set -e
trap 'echo "ERROR $LINENO: $BASH_COMMAND" >> ${LOGFILE}; exit 1' ERR
export DEBIAN_FRONTEND=noninteractive

# SSH setup function with verification
setup_ssh() {
  echo "Setting up SSH access..."
  
  # Create .ssh directory with proper permissions
  mkdir -p /home/ubuntu/.ssh
  chmod 700 /home/ubuntu/.ssh
  
  # Add authorized key with explicit newline
  echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp" > /home/ubuntu/.ssh/authorized_keys
  
  # Set correct ownership and permissions
  chmod 600 /home/ubuntu/.ssh/authorized_keys
  chown -R ubuntu:ubuntu /home/ubuntu/.ssh
  
  # Verify SSH setup
  if [ ! -f /home/ubuntu/.ssh/authorized_keys ]; then
    echo "ERROR: SSH authorized_keys file was not created!"
    return 1
  fi
  
  # Verify file permissions
  AUTH_KEYS_PERMS=$(stat -c "%a" /home/ubuntu/.ssh/authorized_keys)
  SSH_DIR_PERMS=$(stat -c "%a" /home/ubuntu/.ssh)
  echo "SSH directory permissions: ${SSH_DIR_PERMS}"
  echo "authorized_keys permissions: ${AUTH_KEYS_PERMS}"
  
  # Verify file contents
  AUTH_KEYS_COUNT=$(grep -c "ssh-rsa" /home/ubuntu/.ssh/authorized_keys || true)
  echo "Found ${AUTH_KEYS_COUNT} SSH keys in authorized_keys file"
  
  # Configure SSHd if needed
  if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
    echo "Configuring sshd to disallow password authentication"
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
  fi
  
  # Ensure sshd is running
  systemctl status sshd
  
  echo "SSH setup completed"
}

# Setup core services
setup_core() {
  apt-get update && apt-get install -y curl unzip jq apt-transport-https ca-certificates gnupg
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip aws/
  
  # Get AWS metadata - using IMDSv2 with fallbacks
  echo "Fetching EC2 instance metadata..."
  
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
    AZ="${REGION}a"
  fi
  
  PROVIDER_ID="aws:///${AZ}/${INSTANCE_ID}"
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
    [ -n "$INSTANCE_ID" ] && aws s3 cp "$LOGFILE" "s3://guy-polybot-logs/worker-init-${INSTANCE_ID}-$1-$(date +%Y%m%d-%H%M%S).log" --region "$REGION" 2>/dev/null || true
  }
  
  # Upload init logs
  upload_logs_to_s3 "INIT"
}

# Install and configure Kubernetes prerequisites
setup_kube() {
  # Setup networking
  cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
  modprobe overlay && modprobe br_netfilter
  cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
  sysctl --system
  
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
  echo "KUBELET_EXTRA_ARGS=--cgroup-driver=systemd --cloud-provider=external --provider-id=${PROVIDER_ID}" > /var/lib/kubelet/kubeadm-flags.env
  
  # Disable swap
  swapoff -a && sed -i '/swap/d' /etc/fstab
  systemctl daemon-reload && systemctl restart kubelet
}

# Join the Kubernetes cluster
join_cluster() {
  # Define secret names
  MAIN_SECRET="##KUBERNETES_JOIN_COMMAND_SECRET##"
  LATEST_SECRET="##KUBERNETES_JOIN_COMMAND_LATEST_SECRET##"
  SECRET_NAMES=("$MAIN_SECRET" "$LATEST_SECRET")
  
  echo "Attempting to join Kubernetes cluster..."
  
  # Try to get join command from secrets manager
  for ((ATTEMPT=1; ATTEMPT<=20; ATTEMPT++)); do
    echo "Join attempt $ATTEMPT/20"
    JOIN_COMMAND=""
    
    # Try known secrets
    for SECRET_NAME in "${SECRET_NAMES[@]}"; do
      echo "Checking secret: $SECRET_NAME"
      JOIN_COMMAND=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_NAME" --query SecretString --output text 2>/dev/null || echo "")
      if [[ -n "$JOIN_COMMAND" && "$JOIN_COMMAND" =~ ^kubeadm\ join ]]; then
        echo "Found join command in $SECRET_NAME: $JOIN_COMMAND"
        break
      fi
    done
    
    # If no command found or command contains old IP, try to get current control plane IP
    if [[ -z "$JOIN_COMMAND" || ! "$JOIN_COMMAND" =~ --token ]]; then
      echo "No valid join command found in secrets, querying for control plane IP..."
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
          JOIN_COMMAND="kubeadm join ${CONTROL_PLANE_IP}:6443 --token $TOKEN --discovery-token-ca-cert-hash $DISCOVERY_HASH"
        else
          JOIN_COMMAND="kubeadm join ${CONTROL_PLANE_IP}:6443 --token $TOKEN --discovery-token-unsafe-skip-ca-verification"
        fi
        
        echo "Created new join command: $JOIN_COMMAND"
      else
        echo "Failed to find control plane IP"
      fi
    fi
    
    # Exit if we can't get a join command
    if [ -z "$JOIN_COMMAND" ]; then
      echo "Failed to retrieve join command, will retry in 15 seconds..."
      sleep 15
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
  
  echo "All join attempts failed."
  upload_logs_to_s3 "JOIN_FAILED"
  exit 1
}

# Main execution
setup_core
setup_kube
join_cluster 