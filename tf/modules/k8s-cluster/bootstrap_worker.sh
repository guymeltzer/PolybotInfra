#!/bin/bash
# Minimal bootstrap script for worker nodes with robust decompression
# This bootstrap uses base64+gzip compression to stay under the 16KB user-data limit

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
echo "$(date) - Starting worker node bootstrap (compressed version)"

# Error handling
set -e
trap 'echo "$(date) - CRITICAL ERROR at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Install minimal dependencies silently
echo "$(date) - Installing minimal dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -y -q curl ca-certificates gnupg unzip jq || {
    echo "WARNING: Basic package install failed, continuing anyway"
}

# Get instance metadata
echo "$(date) - Fetching EC2 instance metadata..."
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
export AWS_DEFAULT_REGION="$REGION"

echo "$(date) - Instance ID: $INSTANCE_ID, Region: $REGION"

# --------------------------------------------------
# Skip compression and directly use fallback script
# --------------------------------------------------
echo "$(date) - Executing emergency fallback script"
FALLBACK_SCRIPT="/tmp/worker_fallback.sh"

# Write out the emergency fallback script
cat > "$FALLBACK_SCRIPT" << 'FALLBACK_SCRIPT'
#!/bin/bash
# Emergency fallback script - essential functionality only
echo "$(date) - Running emergency fallback script" | tee -a /var/log/worker-init.log

# Core setup to join cluster
echo "$(date) - Installing essential packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y apt-transport-https ca-certificates curl gnupg
apt-get install -y curl jq netcat-openbsd unzip

# Install kubeadm, kubectl, kubelet
echo "$(date) - Installing kubernetes components"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

# Install AWS CLI
echo "$(date) - Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# Set up SSH 
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh
echo "$1" > /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Enable br_netfilter
echo "$(date) - Enabling br_netfilter"
modprobe br_netfilter
echo "br_netfilter" > /etc/modules-load.d/k8s.conf

# Disable swap
echo "$(date) - Disabling swap"
swapoff -a
sed -i '/ swap / s/^/#/' /etc/fstab

# Configure kernel parameters
echo "$(date) - Setting up sysctl parameters"
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
sysctl --system

# Try to get join command
echo "$(date) - Retrieving join command"
if [ -n "$2" ]; then
  echo "Trying to get join command from secret $2"
  JOIN_CMD=$(aws secretsmanager get-secret-value --region us-east-1 --secret-id "$2" \
    --query "SecretString" --output text)
fi

if [ -z "$JOIN_CMD" ] && [ -n "$3" ]; then
  echo "Trying to get join command from backup secret $3"
  JOIN_CMD=$(aws secretsmanager get-secret-value --region us-east-1 --secret-id "$3" \
    --query "SecretString" --output text)
fi

# Execute join command if found
if [ -n "$JOIN_CMD" ]; then
  echo "$(date) - Executing join command"
  $JOIN_CMD
  echo "$(date) - Join command executed"
else
  echo "$(date) - ERROR: Could not retrieve join command from secrets"
  exit 1
fi
FALLBACK_SCRIPT

# Make fallback script executable
chmod +x "$FALLBACK_SCRIPT"

# Execute the fallback script
echo "$(date) - Executing fallback script..."
"$FALLBACK_SCRIPT" "${SSH_PUBLIC_KEY}" "${JOIN_COMMAND_SECRET}" "${JOIN_COMMAND_LATEST_SECRET}"
EXIT_CODE=$?
echo "$(date) - Worker initialization completed with exit code: $EXIT_CODE"

exit $EXIT_CODE 
