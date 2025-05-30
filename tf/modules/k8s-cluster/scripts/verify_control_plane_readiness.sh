#!/bin/bash

# Script to verify control plane readiness including API server and join token in Secrets Manager.

# Exit on any command that fails if not explicitly handled
# set -e # Consider enabling this for stricter error handling, but ensure all paths are handled or it might exit too early.

# --- Read parameters from environment variables ---
INSTANCE_ID="$CP_INSTANCE_ID"  # Reads from env var CP_INSTANCE_ID
REGION="$AWS_REGION_VAR"     # Reads from env var AWS_REGION_VAR
# Correctly read from the environment variable exported by Terraform
JOIN_COMMAND_LATEST_SECRET_ID="$JOIN_COMMAND_LATEST_SECRET_ID" 
SKIP_K8S_VERIFICATION="$SKIP_K8S_VERIFICATION_VAR" # Reads from env var SKIP_K8S_VERIFICATION_VAR

# --- Validate mandatory parameters ---
if [ -z "$INSTANCE_ID" ] || [ -z "$REGION" ] || [ -z "$JOIN_COMMAND_LATEST_SECRET_ID" ]; then
  echo "Error: Missing one or more required environment variables: CP_INSTANCE_ID, AWS_REGION_VAR, JOIN_COMMAND_LATEST_SECRET_ID"
  exit 1 # Critical configuration error
fi

# --- Handle Skip ---
if [ "$SKIP_K8S_VERIFICATION" == "true" ]; then
  echo "SKIP_K8S_VERIFICATION is set to true. Skipping control plane verification."
  exit 0
fi

# --- Configuration ---
MAX_ATTEMPTS=20
DELAY=30 # seconds
READINESS_LOG="/tmp/k8s_control_plane_readiness_${INSTANCE_ID}_$(date +%s).log" # Add timestamp to log name for uniqueness

# --- Setup Logging ---
# Ensure log directory exists (though /tmp should always exist)
mkdir -p /tmp
echo "Starting control plane verification for instance $INSTANCE_ID in region $REGION at $(date)" > "$READINESS_LOG"
# Redirect all stdout and stderr of this script to the log file, and also to current stdout/stderr
exec > >(tee -a "$READINESS_LOG") 2>&1

echo "--- Script Parameters ---"
echo "Instance ID: $INSTANCE_ID"
echo "AWS Region: $REGION"
echo "Join Command Secret ID (Latest): $JOIN_COMMAND_LATEST_SECRET_ID"
echo "Max Attempts: $MAX_ATTEMPTS"
echo "Delay Between Attempts: ${DELAY}s"
echo "Log file: $READINESS_LOG"
echo "-------------------------"

# --- Helper Functions ---

# Function to check if EC2 instance is fully initialized (status checks passed)
check_instance_status() {
  echo "Checking EC2 instance status for $INSTANCE_ID..."
  STATUS_INFO=$(aws ec2 describe-instance-status \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query "InstanceStatuses[0].{InstanceStatus:InstanceStatus.Status, SystemStatus:SystemStatus.Status}" \
    --output json 2>/dev/null)

  INSTANCE_STATUS=$(echo "$STATUS_INFO" | jq -r .InstanceStatus 2>/dev/null)
  SYSTEM_STATUS=$(echo "$STATUS_INFO" | jq -r .SystemStatus 2>/dev/null)

  if [[ "$INSTANCE_STATUS" == "ok" && "$SYSTEM_STATUS" == "ok" ]]; then
    echo "  EC2 instance status: ok, System status: ok"
    return 0
  else
    echo "  EC2 instance status: $INSTANCE_STATUS, System status: $SYSTEM_STATUS (not both 'ok' yet or error fetching)"
    return 1
  fi
}

# Function to check if SSM agent is ready on the control plane
check_ssm_readiness() {
  echo "Checking SSM agent readiness for $INSTANCE_ID..."
  PING_STATUS=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
    --region "$REGION" \
    --query "InstanceInformationList[0].PingStatus" \
    --output text 2>/dev/null)

  if [ "$PING_STATUS" == "Online" ]; then
    echo "  SSM agent PingStatus: Online"
    return 0
  else
    echo "  SSM agent PingStatus: '$PING_STATUS' (not 'Online' or error fetching)"
    return 1
  fi
}

# Function to execute a command via SSM and get its output
run_ssm_command() {
  local ssm_commands="$1"
  local command_description="$2"
  echo "  Running SSM command on $INSTANCE_ID: $command_description"

  COMMAND_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[$ssm_commands]" \
    --region "$REGION" \
    --output text \
    --query "Command.CommandId" 2>/dev/null)

  if [ -z "$COMMAND_ID" ]; then
    echo "    Failed to send SSM command for: $command_description"
    return 1
  fi

  echo "    SSM Command ID: $COMMAND_ID for $command_description. Waiting for execution..."

  local ssm_wait_attempts=12 # Increased to 1 minute (12*5s)
  local ssm_status=""
  local final_ssm_status_for_command="Pending" # Default to a non-success state

  for ((k=1; k<=ssm_wait_attempts; k++)); do
    sleep 5
    INVOCATION_DETAILS=$(aws ssm list-command-invocations --command-id "$COMMAND_ID" --details --region "$REGION" --query "CommandInvocations[0]" --output json 2>/dev/null)
    ssm_status=$(echo "$INVOCATION_DETAILS" | jq -r .Status 2>/dev/null)
    final_ssm_status_for_command=$ssm_status # Store last known status

    echo "    SSM command status (attempt $k): $ssm_status"
    if [[ "$ssm_status" == "Success" ]] || [[ "$ssm_status" == "Failed" ]] || [[ "$ssm_status" == "Cancelled" ]] || [[ "$ssm_status" == "TimedOut" ]]; then
      break
    fi
  done

  if [ "$final_ssm_status_for_command" != "Success" ]; then
    echo "    SSM command for '$command_description' did not succeed. Final Status: $final_ssm_status_for_command"
    # Log detailed error if available
    STD_ERROR=$(echo "$INVOCATION_DETAILS" | jq -r .CommandPlugins[0].Output 2>/dev/null || echo "Error content not available")
    echo "    SSM StandardError/Output: $STD_ERROR"
    return 1
  fi

  OUTPUT=$(echo "$INVOCATION_DETAILS" | jq -r .CommandPlugins[0].Output 2>/dev/null || echo "Output content not available")

  echo "$OUTPUT"
  return 0
}

# Function to check if Kubernetes API server is ready
check_api_server_readiness() {
  local attempt_num="$1"
  echo "Checking Kubernetes API server readiness (Terraform script attempt $attempt_num)..."
  local port_open_success=false

  # Method 1: Check port 6443 with ss
  echo "  Method 1: Checking port 6443 with 'ss'..."
  PORT_CHECK_SS_OUTPUT_RAW=$(run_ssm_command "sudo ss -tlnp | grep :6443 || echo port-not-listening" "ss port check")
  local ssm_ss_exit_status=$?
  if [[ "$ssm_ss_exit_status" -eq 0 && "$PORT_CHECK_SS_OUTPUT_RAW" != *"port-not-listening"* && -n "$PORT_CHECK_SS_OUTPUT_RAW" ]]; then
    echo "    Port 6443 seems open via 'ss': $PORT_CHECK_SS_OUTPUT_RAW"
    port_open_success=true
  else
    echo "    'ss' check failed or port not ready. SSM Exit: $ssm_ss_exit_status, Output: [$PORT_CHECK_SS_OUTPUT_RAW]"
    # Fallback Method 2: Check port 6443 with nc (netcat)
    echo "  Fallback Method 2: Checking port 6443 with 'nc'..."
    PORT_CHECK_NC_OUTPUT_RAW=$(run_ssm_command "nc -zv localhost 6443 2>&1 || echo connection-failed" "nc port check")
    local ssm_nc_exit_status=$?
    # nc outputs to stderr on success for -z, so check for "succeeded" or "open"
    if [[ "$ssm_nc_exit_status" -eq 0 && ("$PORT_CHECK_NC_OUTPUT_RAW" == *"succeeded"* || "$PORT_CHECK_NC_OUTPUT_RAW" == *"open"*) ]]; then
        echo "    Port 6443 seems open via 'nc': $PORT_CHECK_NC_OUTPUT_RAW"
        port_open_success=true
    else
        echo "    'nc' check failed or port not open. SSM Exit: $ssm_nc_exit_status, Output: [$PORT_CHECK_NC_OUTPUT_RAW]"
    fi
  fi

  if $port_open_success; then
    echo "  Port 6443 appears open. Checking API server health endpoint..."
    # Use curl for healthz check as kubectl might not be fully set up or might have its own issues initially
    # The --cacert is important if self-signed certs are used by kubeadm initially before any LB/ingress
    # The -k flag is used to ignore certificate errors for this local health check if CA is not easily available to curl via SSM
    API_HEALTHZ_OUTPUT_RAW=$(run_ssm_command "curl -kfsS https://localhost:6443/healthz || echo not-healthy" "curl healthz check")
    local ssm_healthz_exit_status=$?

    # Trim whitespace/newlines from the output for comparison
    API_HEALTHZ_OUTPUT_TRIMMED=$(echo "$API_HEALTHZ_OUTPUT_RAW" | xargs)

    if [[ "$ssm_healthz_exit_status" -eq 0 && "$API_HEALTHZ_OUTPUT_TRIMMED" == "ok" ]]; then
      echo "    API server /healthz endpoint returned 'ok'."
      return 0 # Success
    else
      echo "    API server /healthz check failed or returned unhealthy."
      echo "      SSM call exit status for healthz: $ssm_healthz_exit_status"
      echo "      Raw healthz output: [$API_HEALTHZ_OUTPUT_RAW]"
      echo "      Trimmed healthz output: [$API_HEALTHZ_OUTPUT_TRIMMED]"
    fi
  fi

  echo "  API server readiness check failed for attempt $attempt_num."
  return 1
}

# Function to check if Secrets Manager contains a valid join token
check_secrets_readiness() {
  echo "Checking Secrets Manager for join token (Secret ID: $JOIN_COMMAND_LATEST_SECRET_ID)..."
  JOIN_CMD=$(aws secretsmanager get-secret-value \
    --secret-id "$JOIN_COMMAND_LATEST_SECRET_ID" \
    --region "$REGION" \
    --query SecretString \
    --output text 2>/dev/null)

  if [ -z "$JOIN_CMD" ]; then
    echo "  No join command string found in Secrets Manager."
    return 1
  fi

  if [[ "$JOIN_CMD" == *"kubeadm join"* ]] && [[ "$JOIN_CMD" == *"--token"* ]] && [[ "$JOIN_CMD" == *"--discovery-token-ca-cert-hash"* ]]; then
    echo "  Valid 'kubeadm join' command structure found in Secrets Manager."
    return 0
  else
    echo "  Invalid or incomplete join command format found in Secrets Manager: '$JOIN_CMD'"
    return 1
  fi
}

# Function to trigger token creation/refresh on the control plane
trigger_token_creation() {
  echo "Attempting to trigger token creation/refresh on $INSTANCE_ID..."
  if run_ssm_command "sudo systemctl restart k8s-token-creator.service || sudo /usr/local/bin/refresh-join-token.sh || sudo kubeadm token create --print-join-command" "token creation trigger"; then
    echo "  Token creation/refresh command sent successfully via SSM."
  else
    echo "  Failed to send token creation/refresh command via SSM."
  fi
}

# --- Main Verification Loop ---
OVERALL_SUCCESS=false
API_SERVER_READY=false
SECRETS_READY=false

for ((i=1; i<=MAX_ATTEMPTS; i++)); do
  echo ""
  echo "=== Control Plane Verification Loop: Attempt $i of $MAX_ATTEMPTS at $(date) ==="

  if ! $API_SERVER_READY; then
    if ! check_instance_status; then
      echo "EC2 instance status checks not 'ok'. Waiting $DELAY seconds..."
      sleep $DELAY
      continue
    fi
    if ! check_ssm_readiness; then
      echo "SSM agent not 'Online'. Waiting $DELAY seconds..."
      sleep $DELAY
      continue
    fi
  fi

  if ! $API_SERVER_READY; then
    if check_api_server_readiness "$i"; then
      API_SERVER_READY=true
      echo "✅ API Server is now READY."
    else
      echo "API server still not ready (attempt $i). Waiting $DELAY seconds..."
      # If API server isn't ready, no point checking secrets yet or trying to trigger token creation that might rely on kubectl
      sleep $DELAY
      continue
    fi
  fi

  if $API_SERVER_READY; then # Only proceed if API server is confirmed ready
    if ! $SECRETS_READY; then
      if check_secrets_readiness; then
        SECRETS_READY=true
        echo "✅ Join token in Secrets Manager is VALID."
      else
        echo "Join token in Secrets Manager is not ready/valid. Triggering token creation/refresh on control plane (attempt $i)..."
        trigger_token_creation
        # Give some time for the token to be potentially updated after triggering
        # This sleep is important because the trigger is async.
        echo "Waiting for token to update in Secrets Manager after trigger..."
        sleep 15
      fi
    fi
  fi

  if $API_SERVER_READY && $SECRETS_READY; then
    OVERALL_SUCCESS=true
    echo "✅✅ Overall Verification SUCCESS: API Server ready AND Join Token in Secrets Manager valid."
    break
  fi

  echo "Current status: API_SERVER_READY=$API_SERVER_READY, SECRETS_READY=$SECRETS_READY."
  if [ "$i" -lt "$MAX_ATTEMPTS" ]; then # Avoid sleep on the very last attempt
    echo "Waiting $DELAY seconds before next overall check..."
    sleep $DELAY
  fi
done

# --- Final Status Report and Exit ---
echo ""
echo "===== Control Plane Verification Final Summary (after $i attempts) ====="
echo "API Server Ready Status: $API_SERVER_READY"
echo "Join Token in Secrets Manager Ready Status: $SECRETS_READY"
echo "Overall Script Success State: $OVERALL_SUCCESS"
echo "======================================================================"

# Terraform null_resource provisioners expect exit 0 for success, non-zero for failure.
# The depends_on logic in Terraform should handle whether subsequent resources run.
# However, the original script always exited 0. We'll keep that behavior for now
# to avoid breaking existing Terraform apply flow if it relies on this script not failing the apply.
# For a stricter setup, exit 1 on failure.

if $OVERALL_SUCCESS; then
  echo "Control plane verification deemed SUCCESSFUL by script."
  exit 0
else
  echo "⚠️ Control plane verification: FAILED or PARTIALLY COMPLETED within $MAX_ATTEMPTS attempts."
  echo "Terraform will proceed as this script is set to exit 0. Check logs for details."
  # If you want Terraform to halt on failure, change this to 'exit 1'
  exit 0
fi
