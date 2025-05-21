#!/bin/bash
# Script generated with static content (timestamp will update when file changes)

# Log file for debugging - Define directly without using template variable syntax
LOGFILE="/var/log/k8s-worker-init.log"
# Use single quotes to prevent Terraform template expansion for variables we don't want to expand
exec > >(tee -a ${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes worker node initialization"

# Error handling
set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> ${LOGFILE}; exit 1' ERR

# Set non-interactive frontend
export DEBIAN_FRONTEND=noninteractive

# Install AWS CLI early before doing anything else
echo "$(date) - Installing AWS CLI"
apt-get update
apt-get install -y curl unzip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
export PATH=$PATH:/usr/local/bin
rm -rf awscliv2.zip aws/

# Verify AWS CLI installation
echo "$(date) - Verifying AWS CLI installation"
aws --version

# Wait for metadata and network
echo "$(date) - Waiting for metadata service"
until curl -s -m 5 http://169.254.169.254/latest/meta-data/ > /dev/null; do
  echo "Waiting for metadata service..."
  sleep 5
done

# Get metadata token
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
if [ -z "$TOKEN" ]; then
  echo "Failed to retrieve metadata token" >> ${LOGFILE}
  exit 1
fi

# Get region
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
if [ -z "$REGION" ]; then
  echo "Failed to retrieve region from metadata" >> ${LOGFILE}
  exit 1
fi

# Configure AWS CLI with region
export AWS_DEFAULT_REGION="$REGION"

# After getting instance metadata
PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
PROVIDER_ID="aws:///${AZ}/${INSTANCE_ID}"

# Add logging with S3 upload function at the top of the script, after the LOGFILE and error handling setup
# Function to upload logs to S3 even if script fails
upload_logs_to_s3() {
  LOG_STATUS=$1
  echo "$(date) - $LOG_STATUS - Uploading logs to S3"
  
  # Only run if we have instance ID
  if [ -n "$INSTANCE_ID" ]; then
    # Create a unique log filename
    LOG_FILENAME="worker-init-${INSTANCE_ID}-${LOG_STATUS}-$(date +%Y%m%d-%H%M%S).log"
    
    # Copy the log file to S3
    if aws s3 cp "$LOGFILE" "s3://guy-polybot-logs/${LOG_FILENAME}" --region "$REGION" 2>/dev/null; then
      echo "$(date) - Logs uploaded to s3://guy-polybot-logs/${LOG_FILENAME}"
    else
      echo "$(date) - Failed to upload logs to S3"
    fi
  else
    echo "$(date) - Cannot upload logs: no instance ID yet"
  fi
}

# Set up trap to upload logs on exit
trap 'upload_logs_to_s3 "ERROR_TRAP"; echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> "$LOGFILE"; exit 1' ERR

# Set up SSH access (using your existing key)
echo "$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp
EOF
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Upload initialization logs
upload_logs_to_s3 "INIT"

# Update package lists
echo "$(date) - Updating package lists"
apt-get update
echo "$(date) - Fixing package manager state"
apt-get install -f -y
dpkg --configure -a

# Install base packages first
echo "$(date) - Installing base packages"
apt-get install -y apt-transport-https ca-certificates curl gnupg software-properties-common jq

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

# Function to validate and fix a join command
validate_and_fix_join_command() {
  local cmd="$1"
  
  echo "$(date) - Validating join command: $cmd"
  
  # Check if it starts with kubeadm join
  if [[ ! "$cmd" =~ ^kubeadm\ join ]]; then
    echo "$(date) - Not a valid join command, doesn't start with 'kubeadm join'"
    return 1
  fi
  
  # Extract server address
  local server_addr=$(echo "$cmd" | grep -oP '^\s*kubeadm\s+join\s+\K[^:]+:[0-9]+')
  if [ -z "$server_addr" ]; then
    echo "$(date) - Cannot extract server address from join command"
    return 1
  fi
  
  # Check if it has the token parameter
  if [[ ! "$cmd" =~ --token ]]; then
    echo "$(date) - Join command is missing --token parameter"
    # Find a token from the command if possible
    local possible_token=$(echo "$cmd" | grep -oP '(?<=kubeadm join )[^:]+:[0-9]+ \K\S+' || echo "")
    if [[ "$possible_token" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]]; then
      echo "$(date) - Found token in an unexpected position: $possible_token"
      cmd="kubeadm join $server_addr --token $possible_token --discovery-token-unsafe-skip-ca-verification"
      echo "$(date) - Fixed join command: $cmd"
      echo "$cmd"
      return 0
    else
      # Generate a new token
      echo "$(date) - Generating a new token"
      local new_token=$(kubeadm token generate)
      cmd="kubeadm join $server_addr --token $new_token --discovery-token-unsafe-skip-ca-verification"
      echo "$(date) - Join command with new token: $cmd"
      echo "$cmd"
      return 0
    fi
  fi
  
  # If it has a token but no ca-cert-hash or unsafe-skip, add unsafe-skip
  if [[ ! "$cmd" =~ --discovery-token-ca-cert-hash ]] && [[ ! "$cmd" =~ --discovery-token-unsafe-skip-ca-verification ]]; then
    echo "$(date) - Join command is missing certificate verification parameter"
    cmd="$cmd --discovery-token-unsafe-skip-ca-verification"
    echo "$(date) - Fixed join command: $cmd"
  fi
  
  echo "$cmd"
  return 0
}

# Fetch join command from Secrets Manager - using direct approach
echo "$(date) - Fetching join command from Secrets Manager"
MAX_ATTEMPTS=30
# Define the secret names to try - templated from Terraform
MAIN_SECRET="${kubernetes_join_command_secret}"
LATEST_SECRET="${kubernetes_join_command_latest_secret}"
SECRET_NAMES=("$MAIN_SECRET" "$LATEST_SECRET")
JOIN_COMMAND=""

for ((ATTEMPT=1; ATTEMPT<=MAX_ATTEMPTS; ATTEMPT++)); do
  echo "$(date) - Join command fetch attempt $ATTEMPT/$MAX_ATTEMPTS"
  
  # Try each possible secret name
  for SECRET_NAME in "${SECRET_NAMES[@]}"; do
    echo "$(date) - Trying secret: $SECRET_NAME"
    JOIN_COMMAND=$(aws secretsmanager get-secret-value \
      --region "$REGION" \
      --secret-id "$SECRET_NAME" \
      --query SecretString \
      --output text 2>/dev/null || echo "")
    
    if [ -n "$JOIN_COMMAND" ]; then
      # Check if the value is a valid join command or another secret name
      if [[ "$JOIN_COMMAND" =~ ^kubeadm\ join ]]; then
        # Validate that it has the token parameter
        if [[ ! "$JOIN_COMMAND" =~ --token ]]; then
          echo "$(date) - Join command is missing the --token parameter"
          # Extract the server address and try to fix it
          SERVER_ADDR=$(echo "$JOIN_COMMAND" | grep -oP '^kubeadm join \K[^[:space:]]+')
          if [ -n "$SERVER_ADDR" ]; then
            # Generate a token locally and use it
            LOCAL_TOKEN=$(kubeadm token generate)
            JOIN_COMMAND="kubeadm join $SERVER_ADDR --token $LOCAL_TOKEN --discovery-token-unsafe-skip-ca-verification"
            echo "$(date) - Fixed join command: $JOIN_COMMAND"
            break 2
          fi
        else
          echo "$(date) - Successfully retrieved valid join command from $SECRET_NAME"
          break 2
        fi
      elif [[ "$JOIN_COMMAND" =~ ^kubernetes-join-command ]]; then
        echo "$(date) - Secret value appears to be another secret name: $JOIN_COMMAND"
        # Skip this and try another secret
        JOIN_COMMAND=""
      else
        echo "$(date) - Successfully retrieved join command from $SECRET_NAME"
        break 2
      fi
    fi
  done
  
  # Try to find the latest secret by listing
  if [ -z "$JOIN_COMMAND" ]; then
    echo "$(date) - Failed to get join command from known secret names, looking for latest..."
    QUERY_PREFIX=$(echo "$MAIN_SECRET" | cut -d'-' -f1-3) # Get the prefix part of the secret name
    LATEST_SECRET=$(aws secretsmanager list-secrets \
      --region "$REGION" \
      --query "sort_by(SecretList[?contains(Name, '$QUERY_PREFIX')], &CreatedDate)[-1].Name" \
      --output text)
    
    if [ -n "$LATEST_SECRET" ] && [ "$LATEST_SECRET" != "None" ]; then
      echo "$(date) - Found latest secret: $LATEST_SECRET"
      JOIN_COMMAND=$(aws secretsmanager get-secret-value \
        --region "$REGION" \
        --secret-id "$LATEST_SECRET" \
        --query SecretString \
        --output text 2>/dev/null || echo "")
      
      if [ -n "$JOIN_COMMAND" ]; then
        # Check if it's a valid join command
        if [[ "$JOIN_COMMAND" =~ ^kubeadm\ join ]]; then
          # Validate that it has the token parameter
          if [[ ! "$JOIN_COMMAND" =~ --token ]]; then
            echo "$(date) - Join command is missing the --token parameter"
            # Extract the server address and try to fix it
            SERVER_ADDR=$(echo "$JOIN_COMMAND" | grep -oP '^kubeadm join \K[^[:space:]]+')
            if [ -n "$SERVER_ADDR" ]; then
              # Generate a token locally and use it
              LOCAL_TOKEN=$(kubeadm token generate)
              JOIN_COMMAND="kubeadm join $SERVER_ADDR --token $LOCAL_TOKEN --discovery-token-unsafe-skip-ca-verification"
              echo "$(date) - Fixed join command: $JOIN_COMMAND"
              break
            fi
          else
            echo "$(date) - Successfully retrieved valid join command from $LATEST_SECRET"
            break
          fi
        elif [[ "$JOIN_COMMAND" =~ ^kubernetes-join-command ]]; then
          # Try to retrieve the nested secret
          NESTED_SECRET=$JOIN_COMMAND
          JOIN_COMMAND=$(aws secretsmanager get-secret-value \
            --region "$REGION" \
            --secret-id "$NESTED_SECRET" \
            --query SecretString \
            --output text 2>/dev/null || echo "")
          
          if [ -n "$JOIN_COMMAND" ] && [[ "$JOIN_COMMAND" =~ ^kubeadm\ join ]]; then
            # Validate that it has the token parameter
            if [[ ! "$JOIN_COMMAND" =~ --token ]]; then
              echo "$(date) - Nested join command is missing the --token parameter"
              # Extract the server address and try to fix it
              SERVER_ADDR=$(echo "$JOIN_COMMAND" | grep -oP '^kubeadm join \K[^[:space:]]+')
              if [ -n "$SERVER_ADDR" ]; then
                # Generate a token locally and use it
                LOCAL_TOKEN=$(kubeadm token generate)
                JOIN_COMMAND="kubeadm join $SERVER_ADDR --token $LOCAL_TOKEN --discovery-token-unsafe-skip-ca-verification"
                echo "$(date) - Fixed nested join command: $JOIN_COMMAND"
                break
              fi
            else
              echo "$(date) - Successfully retrieved valid join command from nested secret $NESTED_SECRET"
              break
            fi
          fi
        fi
      fi
    fi
  fi
  
  if [ $ATTEMPT -lt 10 ]; then
    sleep 30
  else
    # If we've been waiting too long, try creating our own join command directly
    echo "$(date) - Too many attempts, trying to generate join command directly..."
    
    # Try to find the control plane instance
    CONTROL_PLANE_IP=$(aws ec2 describe-instances \
      --region "$REGION" \
      --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" \
      --query "Reservations[0].Instances[0].PrivateIpAddress" \
      --output text)
    
    if [ -n "$CONTROL_PLANE_IP" ] && [ "$CONTROL_PLANE_IP" != "None" ]; then
      echo "$(date) - Found control plane at $CONTROL_PLANE_IP"
      # Generate a token locally and use it with unsafe skip verification
      LOCAL_TOKEN=$(kubeadm token generate)
      JOIN_COMMAND="kubeadm join ${CONTROL_PLANE_IP}:6443 --token ${LOCAL_TOKEN} --discovery-token-unsafe-skip-ca-verification"
      echo "$(date) - Generated direct join command: $JOIN_COMMAND"
      break
    fi
    
    sleep 30
  fi
done

if [ -z "$JOIN_COMMAND" ]; then
  echo "$(date) - Failed to retrieve a valid join command after $MAX_ATTEMPTS attempts"
  upload_logs_to_s3 "JOIN_COMMAND_FAILED"
  exit 1
fi

echo "$(date) - Join command fetched successfully: $JOIN_COMMAND"

# Join cluster with retry logic
MAX_ATTEMPTS=10
JOIN_SUCCESS=false
RETRY_DELAY=30

for ((ATTEMPT=1; ATTEMPT<=MAX_ATTEMPTS; ATTEMPT++)); do
  echo "$(date) - Attempt $ATTEMPT/$MAX_ATTEMPTS to join cluster"
  
  # Execute the join command
  echo "$(date) - Running: $JOIN_COMMAND --v=5"
  eval $JOIN_COMMAND --v=5 2>&1 | tee -a "$LOGFILE"
  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    JOIN_SUCCESS=true
    echo "$(date) - Successfully joined cluster"
    systemctl restart kubelet
    break
  else
    echo "$(date) - Join failed. Retrying in $RETRY_DELAY seconds..."
    # Check kubelet logs for errors
    echo "$(date) - Checking kubelet logs for errors:"
    journalctl -u kubelet --no-pager -n 30 | tee -a "$LOGFILE"
    
    sleep $RETRY_DELAY
    RETRY_DELAY=$((RETRY_DELAY * 2))
    
    # If we have tried several times and failed, attempt to regenerate a new token
    if [ $ATTEMPT -eq 5 ]; then
      echo "$(date) - Multiple failures, trying with a newly generated token"
      NEW_TOKEN=$(kubeadm token generate)
      # Parse existing control plane address from join command
      CP_ADDR=$(echo "$JOIN_COMMAND" | grep -oP '^\s*kubeadm\s+join\s+\K[^:]+:[0-9]+')
      if [ -n "$CP_ADDR" ]; then
        JOIN_COMMAND="kubeadm join $CP_ADDR --token $NEW_TOKEN --discovery-token-unsafe-skip-ca-verification"
        echo "$(date) - Using new join command: $JOIN_COMMAND"
      fi
    fi
  fi
done

if [ "$JOIN_SUCCESS" = false ]; then
  echo "$(date) - Failed to join cluster after $MAX_ATTEMPTS attempts"
  upload_logs_to_s3 "JOIN_FAILED"
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
    # Set provider ID explicitly
    kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" --kubeconfig=$KUBELET_CONF
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

echo "$(date) - Worker node setup complete. Uploading final logs."

# Upload final logs
upload_logs_to_s3 "COMPLETE"

echo "$(date) - Kubernetes worker node initialization completed successfully" 