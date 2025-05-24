#!/bin/bash
# Minimal bootstrap script for worker nodes with robust error handling
# This bootstrap script ensures proper SSH setup and cluster joining

# Set up basic logging
LOGFILE="/var/log/worker-init.log"
DEBUG_LOG="/home/ubuntu/bootstrap-debug.log"

# Create log files
mkdir -p /home/ubuntu
touch $LOGFILE $DEBUG_LOG
chmod 644 $LOGFILE $DEBUG_LOG
chown ubuntu:ubuntu $DEBUG_LOG

# Set up logging to both files with timestamps
exec > >(tee -a $LOGFILE $DEBUG_LOG) 2>&1
echo "$$(date) - Starting worker node bootstrap with enhanced SSH and join handling"

# Error handling
set -e
trap 'echo "$$(date) - CRITICAL ERROR at line $$LINENO: Command \"$$BASH_COMMAND\" failed with exit code $$?"' ERR

# SSH key configuration - Do this FIRST to ensure access
echo "$$(date) - Configuring SSH access (PRIORITY)"
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh

# Create authorized_keys with both default and provided keys for redundancy
cat > /home/ubuntu/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD3F6tyPEFEzV0LX3X8BsXdMsQz1x2cEikKDEY0aIj41qgxMCP/iteneqXSIFZBp5vizPvaoIR3Um9xK7PGoW8giupGn+EPuxIA4cDM4vzOqOkiMPhz5XK0whEjkVzTo4+S0puvDZuwIsdiW9mxhJc7tgBNL0cYlWSYVkz4G/fslNfRPW5mYAM49f4fhtxPb5ok4Q2Lg9dPKVHO/Bgeu5woMc7RY0p1ej6D4CKFE6lymSDJpW0YHX/wqE9+cfEauh7xZcG0q9t2ta6F6fmX0agvpFyZo8aFbXeUBr7osSCJNgvavWbM/06niWrOvYX2xwWdhXmXSrbX8ZbabVohBK41 default-key
${SSH_PUBLIC_KEY}
EOF

chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

echo "$$(date) - SSH key configuration complete - Debug info:"
ls -la /home/ubuntu/.ssh/
cat /home/ubuntu/.ssh/authorized_keys

# Fix SSH daemon configuration
echo "$$(date) - Configuring SSH daemon"
grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

# Restart SSH daemon to apply changes (try both service names)
echo "$$(date) - Restarting SSH daemon"
systemctl restart ssh || systemctl restart sshd || echo "WARNING: Could not restart SSH service"

# Install minimal dependencies
echo "$$(date) - Installing minimal dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -y -q apt-transport-https ca-certificates curl gnupg unzip jq || {
    echo "WARNING: Basic package install failed, continuing anyway"
}

# Get instance metadata
echo "$$(date) - Fetching EC2 instance metadata..."
TOKEN=$$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
INSTANCE_ID=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
PRIVATE_IP=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "unknown")
PUBLIC_IP=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "unknown")
AVAILABILITY_ZONE=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone || echo "unknown")
export AWS_DEFAULT_REGION="$$REGION"

echo "$$(date) - Instance metadata: ID=$$INSTANCE_ID, Region=$$REGION, Private IP=$$PRIVATE_IP, Public IP=$$PUBLIC_IP, AZ=$$AVAILABILITY_ZONE"

# Install Kubernetes components
echo "$$(date) - Installing Kubernetes components"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

# Install AWS CLI
echo "$$(date) - Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install

# Enable br_netfilter
echo "$$(date) - Configuring kernel modules and network"
modprobe br_netfilter
echo "br_netfilter" > /etc/modules-load.d/k8s.conf

# Disable swap
echo "$$(date) - Disabling swap"
swapoff -a
sed -i '/ swap / s/^/#/' /etc/fstab

# Configure kernel parameters
echo "$$(date) - Setting up sysctl parameters"
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
sysctl --system

# Function to get join command with retries
get_join_command() {
  local secret_name="$1"
  local max_retries=5
  local retry_delay=5
  local attempt=1
  
  while [ $$attempt -le $$max_retries ]; do
    echo "$$(date) - Attempting to retrieve join command from $$secret_name (attempt $$attempt/$$max_retries)"
    local cmd=$$(aws secretsmanager get-secret-value --region $$REGION --secret-id "$$secret_name" \
      --query "SecretString" --output text 2>/dev/null)
    
    if [ -n "$$cmd" ]; then
      echo "$$(date) - Successfully retrieved join command from $$secret_name"
      echo "$$cmd"
      return 0
    fi
    
    echo "$$(date) - Failed to retrieve join command, retrying in $$retry_delay seconds..."
    sleep $$retry_delay
    attempt=$$((attempt + 1))
  done
  
  echo ""  # Return empty string on failure
  return 1
}

# Retrieve join command (prioritize the latest secret)
echo "$$(date) - Retrieving join command with improved retry logic"

# First try the latest secret
JOIN_CMD=""
echo "$$(date) - Trying latest join command secret first: ${JOIN_COMMAND_LATEST_SECRET}"
JOIN_CMD=$$(get_join_command "${JOIN_COMMAND_LATEST_SECRET}")

# Fall back to the main secret if latest fails
if [ -z "$$JOIN_CMD" ] && [ -n "${JOIN_COMMAND_SECRET}" ] && [ "${JOIN_COMMAND_SECRET}" != "${JOIN_COMMAND_LATEST_SECRET}" ]; then
  echo "$$(date) - Latest secret failed, trying main secret: ${JOIN_COMMAND_SECRET}"
  JOIN_CMD=$$(get_join_command "${JOIN_COMMAND_SECRET}")
fi

# If both direct secret retrievals fail, try to find any join command secret
if [ -z "$$JOIN_CMD" ]; then
  echo "$$(date) - Trying to find join command by listing all related secrets"
  SECRET_LIST=$$(aws secretsmanager list-secrets --region $$REGION --query "SecretList[?contains(Name, 'kubernetes-join-command')].Name" --output text)
  
  for SECRET in $$SECRET_LIST; do
    echo "$$(date) - Trying secret: $$SECRET"
    JOIN_CMD=$$(get_join_command "$$SECRET")
    
    if [ -n "$$JOIN_CMD" ]; then
      echo "$$(date) - Found valid join command in secret: $$SECRET"
      break
    fi
  done
fi

# Execute join command if found
if [ -n "$$JOIN_CMD" ]; then
  echo "$$(date) - Executing join command"
  echo "$$JOIN_CMD" > /tmp/join_command.sh
  chmod +x /tmp/join_command.sh
  
  # Execute with a retry mechanism
  JOIN_SUCCESS=false
  for i in {1..3}; do
    echo "$$(date) - Join attempt $$i/3"
    if /tmp/join_command.sh; then
      JOIN_SUCCESS=true
      echo "$$(date) - Successfully joined the Kubernetes cluster!"
      break
    else
      echo "$$(date) - Join attempt $$i failed, waiting before retry..."
      sleep 15
    fi
  done
  
  if [ "$$JOIN_SUCCESS" != "true" ]; then
    echo "$$(date) - ERROR: Failed to join the Kubernetes cluster after multiple attempts"
    exit 1
  fi
else
  echo "$$(date) - ERROR: Could not retrieve join command from any secret"
  exit 1
fi

# Configure the Kubernetes node name based on the instance metadata
echo "$$(date) - Configuring kubelet"
PRIVATE_DNS=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/local-hostname || echo "unknown")
NODE_NAME=$$(echo $$PRIVATE_DNS | sed 's/\./-/g')

# Configure kubelet WITHOUT cloud-provider flag
cat > /etc/default/kubelet << EOF
NODE_NAME=$$NODE_NAME
KUBELET_EXTRA_ARGS=--node-ip=$$PRIVATE_IP
EOF

# Restart kubelet to apply configuration
systemctl daemon-reload
systemctl restart kubelet

# Print kubelet status for debugging
echo "$$(date) - Kubelet status:"
systemctl status kubelet --no-pager || true

# Print kubelet logs for debugging
echo "$$(date) - Kubelet logs:"
journalctl -u kubelet --no-pager -n 50 || true

echo "$$(date) - Worker node bootstrap completed successfully"
exit 0 
