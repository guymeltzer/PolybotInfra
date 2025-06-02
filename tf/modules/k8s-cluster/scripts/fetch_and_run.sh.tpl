#!/bin/bash
set -euo pipefail # Exit on error, unset variable, or pipe failure

# Log file for this fetcher script itself
FETCHER_LOG_FILE="/var/log/s3-bootstrap-fetcher.log"

# Redirect all output of this fetcher script to its log file
# Also send to /var/log/cloud-init-output.log for standard cloud-init logging
exec > >(tee -a "$${FETCHER_LOG_FILE}" /var/log/cloud-init-output.log) 2>&1

echo "========================================================="
echo "= S3 BOOTSTRAP SCRIPT FETCHER - STARTING              ="
echo "= Time: $$(date -u)" # Use UTC for consistency in logs
echo "= Instance: $$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown-instance')"
echo "========================================================="
echo "Fetching S3 script: s3://${S3_BUCKET_NAME}/${S3_SCRIPT_KEY}"
echo "Target Region: ${AWS_REGION}"
echo "Extra Args for main script: '${EXTRA_ARGS}'" # Log extra args

MAIN_SCRIPT_PATH="/tmp/main_bootstrap_from_s3.sh" # Path to download the main script

# Simple error handler for this fetcher script
fetcher_error_exit() {
    local error_message="$$1"
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "❌ FETCHER SCRIPT ERROR: $$error_message"
    echo "❌ Script: fetch_and_run.sh.tpl"
    echo "❌ Time (UTC): $$(date -u)"
    echo "❌ Exit Code: $$?"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    exit 1
}

trap 'fetcher_error_exit "An unexpected error occurred in fetcher script on line $$LINENO"' ERR

# Ensure AWS CLI is available (basic check and install for Debian/Ubuntu/Amazon Linux)
if ! command -v aws &> /dev/null; then
  echo "AWS CLI not found. Attempting to install..."
  if command -v apt-get &> /dev/null; then
    apt-get update -y && apt-get install -y awscli unzip # Unzip might be needed if awscli v2 is fetched as zip
  elif command -v yum &> /dev/null; then
    yum install -y aws-cli # Or awscli for AL2023+, yum install -y unzip
  else
    fetcher_error_exit "Cannot install AWS CLI. Package manager (apt-get/yum) not found."
  fi
  # Re-check after attempting install
  if ! command -v aws &> /dev/null; then
     fetcher_error_exit "AWS CLI installation attempt failed."
  fi
  echo "AWS CLI installed successfully."
else
  echo "AWS CLI already available."
fi
aws --version # Log AWS CLI version

# Download the main bootstrap script from S3 with retries
echo "📥 Downloading main bootstrap script from S3..."
DOWNLOAD_SUCCESS=false
for i in {1..5}; do
  echo "   Download attempt $$i/5 for s3://${S3_BUCKET_NAME}/${S3_SCRIPT_KEY} to $${MAIN_SCRIPT_PATH} in region ${AWS_REGION}..."
  if aws s3 cp "s3://${S3_BUCKET_NAME}/${S3_SCRIPT_KEY}" "$${MAIN_SCRIPT_PATH}" --region "${AWS_REGION}"; then
    echo "   ✅ Script downloaded successfully to $${MAIN_SCRIPT_PATH}"
    DOWNLOAD_SUCCESS=true
    break
  else
    echo "   ⚠️ Download attempt $$i failed. Retrying in 10 seconds..."
    sleep 10
  fi
done

if [ "$${DOWNLOAD_SUCCESS}" != "true" ]; then
  fetcher_error_exit "Failed to download main bootstrap script from S3 (s3://${S3_BUCKET_NAME}/${S3_SCRIPT_KEY}) after 5 attempts."
fi

# Verify script was downloaded and has content
if [ ! -s "$${MAIN_SCRIPT_PATH}" ]; then # -s checks if file exists and is not empty
    fetcher_error_exit "Main bootstrap script $${MAIN_SCRIPT_PATH} was not downloaded correctly or is empty."
fi
SCRIPT_SIZE="$$(stat -c%s "$${MAIN_SCRIPT_PATH}")"
echo "📊 Downloaded script size: $${SCRIPT_SIZE} bytes."
if [ "$${SCRIPT_SIZE}" -lt 100 ]; then # Arbitrary small size check
    fetcher_error_exit "Downloaded script $${MAIN_SCRIPT_PATH} is too small ($${SCRIPT_SIZE} bytes), likely corrupted or incorrect."
fi

# Make the downloaded script executable
echo "🔧 Making $${MAIN_SCRIPT_PATH} executable..."
chmod +x "$${MAIN_SCRIPT_PATH}" || fetcher_error_exit "Failed to make $${MAIN_SCRIPT_PATH} executable."

# Execute the downloaded bootstrap script, passing any EXTRA_ARGS
echo "🚀 Executing main bootstrap script: $${MAIN_SCRIPT_PATH} ${EXTRA_ARGS} ..."
echo "   Start time (UTC): $$(date -u)"

# Note: EXTRA_ARGS should be handled carefully if they contain spaces or special characters.
# Using 'eval' can be risky if EXTRA_ARGS is not controlled.
# A safer way if EXTRA_ARGS can have multiple arguments is to use an array if bash version supports it,
# or pass them one by one. For now, assuming EXTRA_ARGS is simple or empty.
if "$${MAIN_SCRIPT_PATH}" ${EXTRA_ARGS}; then # This might have issues if EXTRA_ARGS has spaces.
# A potentially safer way if EXTRA_ARGS could be multiple arguments:
# eval "$${MAIN_SCRIPT_PATH} $${EXTRA_ARGS}" # Use with caution, ensure EXTRA_ARGS is trusted.
# Or, if EXTRA_ARGS is a single string arg:
# "$${MAIN_SCRIPT_PATH}" "${EXTRA_ARGS}"
  echo "✅ Main bootstrap script completed successfully!"
  echo "   End time (UTC): $$(date -u)"
else
  SCRIPT_EXIT_CODE=$$?
  fetcher_error_exit "Main bootstrap script ($${MAIN_SCRIPT_PATH}) execution failed with exit code $${SCRIPT_EXIT_CODE}."
fi

echo "========================================================="
echo "= S3 BOOTSTRAP SCRIPT FETCHER - COMPLETED             ="
echo "= Time: $$(date -u)"
echo "========================================================="

exit 0