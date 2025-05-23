#!/bin/bash
# Minimal bootstrap script for worker nodes with ACTUAL COMPRESSION
# This bootstrap uses base64+gzip compression to stay under the 16KB user-data limit (7,980 bytes)

# Set up basic logging
LOGFILE="/var/log/worker-init.log"
DEBUG_LOG="/home/ubuntu/bootstrap-debug.log"

# Create log files
mkdir -p /home/ubuntu
touch $LOGFILE $DEBUG_LOG
chmod 644 $LOGFILE $DEBUG_LOG
chown ubuntu:ubuntu $DEBUG_LOG

# Set up logging to both files
exec > >(tee -a $LOGFILE $DEBUG_LOG) 2>&1
echo "$(date) - Starting worker node bootstrap (compressed version)"

# Error handling
set -e
trap 'echo "$(date) - CRITICAL ERROR at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Install minimal dependencies
echo "$(date) - Installing minimal dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -y -q curl ca-certificates || {
    echo "WARNING: Basic package install failed, continuing anyway"
}

# Get instance metadata
echo "$(date) - Fetching EC2 instance metadata..."
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
export AWS_DEFAULT_REGION="$REGION"

echo "$(date) - Instance ID: $INSTANCE_ID, Region: $REGION"

# Store compressed script in variable - ACTUAL compressed data (7,980 bytes)
COMPRESSED_SCRIPT="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"

# Function to decompress and run the script
decompress_and_run() {
    LOCAL_FILE="/tmp/worker_full_init.sh"
    
    # Decompress script from base64+gzip encoding
    echo "$COMPRESSED_SCRIPT" | base64 -d | gunzip > "$LOCAL_FILE"
    
    if [ ! -s "$LOCAL_FILE" ]; then
        echo "$(date) - ERROR: Decompression failed or empty script produced"
        # Fallback - try to manually construct a minimal script
        cat > "$LOCAL_FILE" << 'FALLBACK_SCRIPT'
#!/bin/bash
# Emergency fallback script - minimal functionality
echo "$(date) - Running emergency fallback script" > /var/log/worker-init.log

# Install basic dependencies
apt-get update && apt-get install -y curl jq netcat-openbsd unzip

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# Set up SSH 
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh
echo "$1" > /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Try to get join command
aws secretsmanager get-secret-value --region us-east-1 --secret-id "$2" \
  --query "SecretString" --output text > /tmp/join-command.txt

# Execute join command
bash -c "$(cat /tmp/join-command.txt)"
FALLBACK_SCRIPT
    fi
    
    # Make script executable
    chmod +x "$LOCAL_FILE"
    
    # Execute the decompressed script with parameters
    echo "$(date) - Executing full worker initialization script..."
    $LOCAL_FILE "${SSH_PUBLIC_KEY}" "${JOIN_COMMAND_SECRET}" "${JOIN_COMMAND_LATEST_SECRET}"
    
    # Capture exit code
    EXIT_CODE=$?
    echo "$(date) - Worker initialization completed with exit code: $EXIT_CODE"
    return $EXIT_CODE
}

# Execute the decompression and script execution
decompress_and_run

exit $? 