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
