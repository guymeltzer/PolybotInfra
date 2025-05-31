#!/bin/bash

# Log file for debugging
LOGFILE="/var/log/k8s-node-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes worker node initialization (CRI-O)"

# These variables are expected to be substituted by Terraform's templatefile function:
# ${JOIN_COMMAND_LATEST_SECRET}, ${region}, ${worker_asg_name} (and others if used, e.g. K8S versions)
# For K8S versions, we'll hardcode to match 1.28.3 for now, or they could be passed too.

K8S_VERSION_TO_INSTALL="1.28.3-1.1" # Match control plane K8S_PACKAGE_VERSION
K8S_MAJOR_MINOR_FOR_REPO="1.28"    # For Kubernetes apt repo
CRIO_K8S_MAJOR_MINOR_FOR_REPO="1.28" # For CRI-O apt repo

# Function to log messages
log() {
  echo "$(date) - $1"
}

# Function to retry commands
retry() {
  local attempts=$1
  local delay=$2
  shift 2
  local cmd="$@"
  for ((i=1; i<=attempts; i++)); do
    log "Executing: $cmd (Attempt $i/$attempts)"
    if eval "$cmd"; then # Use eval to correctly execute complex commands
      return 0
    fi
    log "Attempt $i/$attempts failed for: $cmd. Retrying in $delay seconds..."
    sleep $delay
  done
  log "Command failed after $attempts attempts: $cmd"
  # Do not exit here, let the calling function decide if it's fatal
  return 1
}

# Wait for metadata service with retry
log "Waiting for metadata service..."
retry 10 30 "curl -s -f -m 5 http://169.254.169.254/latest/meta-data/"

# Install base packages
log "Installing base packages..."
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl gnupg software-properties-common jq unzip ebtables ethtool

# Install AWS CLI
log "Installing AWS CLI..."
if ! command -v aws &> /dev/null; then
    retry 3 10 "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
    unzip -q awscliv2.zip
    ./aws/install --update
    rm -rf awscliv2.zip aws/
    export PATH=$PATH:/usr/local/bin # May not persist for later commands if not in .bashrc
else
    log "AWS CLI already installed."
fi

IMDS_TOKEN=$(retry 5 10 "curl -s -f -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'")
if [ -z "$IMDS_TOKEN" ]; then
    log "Warning: Failed to get IMDSv2 token. Attempting IMDSv1 for region."
    REGION=$(retry 5 10 "curl -s -f http://169.254.169.254/latest/meta-data/placement/region")
else
    REGION=$(retry 5 10 "curl -s -f -H 'X-aws-ec2-metadata-token: $IMDS_TOKEN' http://169.254.169.254/latest/meta-data/placement/region")
fi
[ -z "$REGION" ] && { log "Failed to retrieve region"; exit 1; }
log "Retrieved region: $REGION. Terraform should pass this as '${region}'."
# Use region passed from Terraform for consistency if available, otherwise use discovered.
EFFECTIVE_REGION="${region:-$REGION}" # ${region} is from templatefile

# Verify AWS CLI access
log "Verifying AWS CLI access..."
aws sts get-caller-identity --region "$EFFECTIVE_REGION" || { log "AWS CLI access verification failed"; exit 1; }

# Get instance metadata
log "Retrieving instance metadata..."
if [ -n "$IMDS_TOKEN" ]; then
    PRIVATE_IP=$(curl -s -f -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
    INSTANCE_ID=$(curl -s -f -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
    AZ=$(curl -s -f -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
else # Fallback to IMDSv1
    PRIVATE_IP=$(curl -s -f http://169.254.169.254/latest/meta-data/local-ipv4)
    INSTANCE_ID=$(curl -s -f http://169.254.169.254/latest/meta-data/instance-id)
    AZ=$(curl -s -f http://169.254.169.254/latest/meta-data/placement/availability-zone)
fi
[ -z "$INSTANCE_ID" ] && { log "Failed to retrieve instance ID"; exit 1; }
PROVIDER_ID="aws:///${AZ}/${INSTANCE_ID}"

# Set sequential hostname using SSM Parameter Store
SSM_PARAM_NAME="/k8s/worker-node-counter"
log "Retrieving SSM parameter for hostname counter..."
COUNTER=$(aws ssm get-parameter --name "$SSM_PARAM_NAME" --region "$EFFECTIVE_REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "0")
# Ensure COUNTER is a number
if ! [[ "$COUNTER" =~ ^[0-9]+$ ]]; then
    log "Warning: SSM parameter $SSM_PARAM_NAME was not a number or not found, resetting to 0."
    COUNTER=0
fi

if [ "$COUNTER" -eq 0 ]; then
  log "Initializing SSM parameter for hostname counter..."
  aws ssm put-parameter --name "$SSM_PARAM_NAME" --value "1" --type String --region "$EFFECTIVE_REGION" --overwrite # Add overwrite
  COUNTER=1
else
  NEXT_COUNTER=$((COUNTER + 1))
  aws ssm put-parameter --name "$SSM_PARAM_NAME" --value "$NEXT_COUNTER" --type String --overwrite --region "$EFFECTIVE_REGION"
  COUNTER=$NEXT_COUNTER # Use the updated counter
fi
NODE_NAME="guy-worker-node-$COUNTER" # Consider using a unique suffix from instance ID if SSM is problematic
hostnamectl set-hostname "$NODE_NAME"
echo "127.0.0.1 $NODE_NAME" >> /etc/hosts # Appending, ensure localhost is already there or add it too
log "Set hostname to $NODE_NAME"

# Configure kernel modules
log "Configuring kernel modules..."
modprobe overlay
modprobe br_netfilter
cat <<EOF | tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

# Configure network settings
log "Configuring network settings (sysctl)..."
cat <<EOF | tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system

# Install CRI-O runtime
log "Installing CRI-O (stable v${CRIO_K8S_MAJOR_MINOR_FOR_REPO})..."
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/addons:/cri-o:/stable:/v${CRIO_K8S_MAJOR_MINOR_FOR_REPO}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/stable:/v${CRIO_K8S_MAJOR_MINOR_FOR_REPO}/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

# Add Kubernetes repository
log "Adding Kubernetes repository (stable v${K8S_MAJOR_MINOR_FOR_REPO})..."
curl -fsSL "https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR_FOR_REPO}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR_FOR_REPO}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components and CRI-O
log "Installing Kubernetes components (kubelet, kubeadm, kubectl) version ${K8S_VERSION_TO_INSTALL} and cri-o..."
apt-get update -y
apt-get install -y cri-o cri-o-runc kubelet="$K8S_VERSION_TO_INSTALL" kubeadm="$K8S_VERSION_TO_INSTALL" kubectl="$K8S_VERSION_TO_INSTALL"
apt-mark hold kubelet kubeadm kubectl cri-o
log "Packages installed and held."

# Configure CRI-O for systemd cgroup manager
CRIO_CONF_WORKER="/etc/crio/crio.conf"
if [ -f "$CRIO_CONF_WORKER" ]; then
    if grep -q "cgroup_manager" "$CRIO_CONF_WORKER"; then
        sed -i 's/cgroup_manager = "cgroupfs"/cgroup_manager = "systemd"/' "$CRIO_CONF_WORKER"
    else 
        if grep -q "\[crio.runtime\]" "$CRIO_CONF_WORKER"; then
            sed -i '/\[crio.runtime\]/a \cgroup_manager = "systemd"' "$CRIO_CONF_WORKER"
        else
            echo -e "\n[crio.runtime]\ncgroup_manager = \"systemd\"" >> "$CRIO_CONF_WORKER"
        fi
    fi
else
    mkdir -p /etc/crio/crio.conf.d
    cat > /etc/crio/crio.conf.d/01-cgroup-manager.conf << EOF
[crio.runtime]
cgroup_manager = "systemd"
EOF
fi
log "Ensured CRI-O is configured for systemd cgroup manager on worker."

# Start and enable CRI-O and kubelet
log "Starting and enabling CRI-O and Kubelet services..."
systemctl daemon-reload
systemctl enable --now crio
systemctl restart crio # ensure config is picked up
systemctl enable --now kubelet # Kubelet will wait for kubeadm join

# Verify services
log "Verifying CRI-O service status..."
systemctl status crio.service --no-pager || { log "CRI-O service failed to start"; exit 1; }

# Disable swap
log "Disabling swap..."
swapoff -a
sed -i.bak '/swap/s/^/#/' /etc/fstab || echo "No swap entries found in /etc/fstab or sed failed for worker."


# Fetch join command from Secrets Manager
# The variable ${JOIN_COMMAND_LATEST_SECRET} must be passed by Terraform's templatefile function
if [ -z "${JOIN_COMMAND_LATEST_SECRET}" ]; then
    log "FATAL: JOIN_COMMAND_LATEST_SECRET variable not set in template. Cannot get join command."
    exit 1
fi
log "Fetching join command from Secrets Manager (${JOIN_COMMAND_LATEST_SECRET})..."

# Retry fetching the secret, as it might take a moment for the control plane to create/update it
FETCH_SECRET_CMD="aws secretsmanager get-secret-value --region \"$EFFECTIVE_REGION\" --secret-id \"${JOIN_COMMAND_LATEST_SECRET}\" --query SecretString --output text"
RAW_JOIN_COMMAND=$(retry 10 60 "$FETCH_SECRET_CMD")

if [ -z "$RAW_JOIN_COMMAND" ]; then
  log "Failed to retrieve join command from ${JOIN_COMMAND_LATEST_SECRET} after multiple retries."
  exit 1
fi
log "Raw join command retrieved."

# Append CRI-O socket to the join command
# Kubeadm join will use this; alternatively, configure kubelet default via /etc/default/kubelet
# or systemd drop-in before kubelet starts. Appending to join command is often simplest for dynamic join.
CRIO_SOCKET_PATH="unix:///run/crio/crio.sock"
MODIFIED_JOIN_COMMAND="$RAW_JOIN_COMMAND --cri-socket $CRIO_SOCKET_PATH --node-name $NODE_NAME --kubelet-extra-args cloud-provider=external"

log "Modified join command: $MODIFIED_JOIN_COMMAND"

# Verify API server accessibility from join command (optional, but good debug)
API_SERVER_ADDRESS=$(echo "$RAW_JOIN_COMMAND" | awk '{print $3}')
log "Checking API server accessibility at $API_SERVER_ADDRESS..."
retry 5 20 "curl -s -f --connect-timeout 10 https://$API_SERVER_ADDRESS/healthz -k" || { log "API server ($API_SERVER_ADDRESS) not accessible. Health check failed."; exit 1; }


# Join cluster with retry logic
log "Attempting to join cluster..."
MAX_JOIN_ATTEMPTS=10
JOIN_RETRY_DELAY=30
JOIN_SUCCESS=false
for ((ATTEMPT=1; ATTEMPT<=MAX_JOIN_ATTEMPTS; ATTEMPT++)); do
  log "Join attempt $ATTEMPT/$MAX_JOIN_ATTEMPTS"
  if eval "$MODIFIED_JOIN_COMMAND --v=5" 2>&1 | tee -a $LOGFILE; then # eval to execute the command string
    JOIN_SUCCESS=true
    log "Successfully joined cluster."
    break
  else
    log "Join attempt $ATTEMPT failed. Retrying in $JOIN_RETRY_DELAY seconds..."
    sleep $JOIN_RETRY_DELAY
    # Optional: Increase delay: RETRY_DELAY=$((RETRY_DELAY + 30))
  fi
done

if [ "$JOIN_SUCCESS" = false ]; then
  log "Failed to join cluster after $MAX_JOIN_ATTEMPTS attempts."
  # Dump kubelet logs for more info on join failure
  journalctl -u kubelet --no-pager -n 100 >> $LOGFILE
  exit 1
fi

# For cloud-provider=external, the kubelet needs the providerID. Kubeadm join with --cloud-provider=external should handle this.
# If not, patching might be needed, but kubeadm is preferred to configure kubelet.
# The --kubelet-extra-args cloud-provider=external in the join command should make kubelet aware.
# ProviderID is usually set by the cloud controller manager after node registration.
# Let's remove manual kubectl patch node as CCM should handle it.
# log "Setting providerID for node $NODE_NAME"
# KUBECONFIG_PATH="/etc/kubernetes/bootstrap-kubelet.conf" # Or /etc/kubernetes/kubelet.conf after join
# retry 5 10 "kubectl patch node \"$NODE_NAME\" -p \"{\\\"spec\\\":{\\\"providerID\\\":\\\"$PROVIDER_ID\\\"}}\" --kubeconfig=$KUBECONFIG_PATH"

# Signal lifecycle hook completion
# The variable ${worker_asg_name} must be passed by Terraform's templatefile function
if [ -n "${worker_asg_name}" ]; then
    LIFECYCLE_HOOK_NAME="guy-scale-up-hook" # Ensure this matches your ASG lifecycle hook name
    log "Signaling lifecycle hook completion for ASG ${worker_asg_name} and hook $LIFECYCLE_HOOK_NAME..."
    
    SIGNAL_CMD="aws autoscaling complete-lifecycle-action \
      --lifecycle-hook-name \"$LIFECYCLE_HOOK_NAME\" \
      --auto-scaling-group-name \"${worker_asg_name}\" \
      --lifecycle-action-result \"CONTINUE\" \
      --instance-id \"$INSTANCE_ID\" \
      --region \"$EFFECTIVE_REGION\""

    if ! retry 3 10 "$SIGNAL_CMD"; then
        log "Failed to signal lifecycle hook with CONTINUE. Attempting to ABANDON..."
        ABANDON_CMD="aws autoscaling complete-lifecycle-action \
          --lifecycle-hook-name \"$LIFECYCLE_HOOK_NAME\" \
          --auto-scaling-group-name \"${worker_asg_name}\" \
          --lifecycle-action-result \"ABANDON\" \
          --instance-id \"$INSTANCE_ID\" \
          --region \"$EFFECTIVE_REGION\""
        retry 2 5 "$ABANDON_CMD" || log "Failed to signal ABANDON for lifecycle hook."
        # Not exiting with 1 here, as node might be partially functional or issue is with hook only.
    else
        log "Lifecycle hook signaled successfully."
    fi
else
    log "Warning: worker_asg_name not provided, skipping lifecycle hook signaling."
fi


# Set EC2 tags (optional, if IAM role has ec2:CreateTags)
log "Setting EC2 tags..."
aws ec2 create-tags --region "$EFFECTIVE_REGION" --resources "$INSTANCE_ID" \
  --tags Key=Name,Value="$NODE_NAME" \
         Key=kubernetes.io/cluster/"${cluster_name}",Value=owned \
         Key=k8s.io/role/node,Value= \
         Key=Role,Value=worker 2>/dev/null || log "Warning: Failed to set some EC2 tags. Check IAM permissions."
# Note: ${cluster_name} must be passed by templatefile if used here.

# Add kubectl alias to ubuntu user's bashrc
log "Adding kubectl alias to ubuntu user's bashrc..."
echo "# kubectl alias" >> /home/ubuntu/.bashrc
echo "alias k='kubectl'" >> /home/ubuntu/.bashrc

# Also add the alias to root's bashrc for completeness  
echo "# kubectl alias" >> /root/.bashrc
echo "alias k='kubectl'" >> /root/.bashrc

log "kubectl alias 'k' added to both ubuntu and root user bashrc files"

log "Worker node setup with CRI-O completed."