#!/bin/bash
# Minimal bootstrap script for worker nodes
# This small bootstrap script stays under the 16KB AWS user-data limit
# It downloads and executes the full initialization script from S3

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
echo "$(date) - Starting worker node minimal bootstrap"

# Error handling
set -e
trap 'echo "$(date) - CRITICAL ERROR at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Install minimal dependencies
echo "$(date) - Installing minimal dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -y -q curl unzip jq ca-certificates python3-pip || {
    echo "WARNING: Basic package install failed. Attempting individual installs."
    apt-get install -y curl || echo "Failed to install curl"
    apt-get install -y python3-pip || echo "Failed to install pip"
}

# Install AWS CLI
echo "$(date) - Installing AWS CLI..."
pip3 install --quiet awscli || echo "Warning: Failed to install AWS CLI with pip, will try alternative method"

# Get instance metadata
echo "$(date) - Fetching EC2 instance metadata..."
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "us-east-1")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
export AWS_DEFAULT_REGION="$REGION"

echo "$(date) - Instance ID: $INSTANCE_ID, Region: $REGION"

# S3 bucket and script information
S3_BUCKET="guy-polybot-scripts"
SCRIPT_NAME="worker_full_init.sh"
LOCAL_SCRIPT="/tmp/$SCRIPT_NAME"

# Download the full script from S3
echo "$(date) - Downloading full initialization script from S3..."
if command -v aws &> /dev/null; then
    aws s3 cp "s3://$S3_BUCKET/$SCRIPT_NAME" "$LOCAL_SCRIPT" || {
        echo "ERROR: Failed to download script from S3. Attempting curl fallback."
        curl "https://$S3_BUCKET.s3.amazonaws.com/$SCRIPT_NAME" -o "$LOCAL_SCRIPT"
    }
else
    echo "AWS CLI not available, using curl for S3 access"
    curl "https://$S3_BUCKET.s3.amazonaws.com/$SCRIPT_NAME" -o "$LOCAL_SCRIPT"
fi

# Make script executable
chmod +x "$LOCAL_SCRIPT"

# Execute the full script with required variables
echo "$(date) - Executing full worker initialization script..."
$LOCAL_SCRIPT "${SSH_PUBLIC_KEY}" "${JOIN_COMMAND_SECRET}" "${JOIN_COMMAND_LATEST_SECRET}"

# Capture exit code
EXIT_CODE=$?
echo "$(date) - Worker initialization completed with exit code: $EXIT_CODE"
exit $EXIT_CODE 