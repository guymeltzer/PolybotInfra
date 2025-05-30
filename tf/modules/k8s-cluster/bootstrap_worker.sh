#!/bin/bash
# Kubernetes worker node bootstrap script with CRI-O

# Basic setup
set -euo pipefail # Exit on error, unset variable, or pipe failure
export DEBIAN_FRONTEND=noninteractive

# Log everything to a file and also to stdout/stderr (for cloud-init output)
LOGFILE="/var/log/k8s-worker-bootstrap.log"
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"
mkdir -p /var/log
touch "$LOGFILE"
chmod 644 "$LOGFILE"

exec > >(tee -a "$LOGFILE" "$CLOUD_INIT_LOG") 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting Kubernetes worker node bootstrap (CRI-O)"

# Error handling with clear error messages
trap 'echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Error at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?" >&2' ERR

# These variables are NOW expected to be substituted by Terraform's templatefile function:
# ${SSH_PUBLIC_KEY}, ${region}, ${JOIN_COMMAND_SECRET}, ${JOIN_COMMAND_LATEST_SECRET},
# ${K8S_PACKAGE_VERSION_TO_INSTALL}, ${K8S_MAJOR_MINOR_FOR_REPO}, ${CRIO_K8S_MAJOR_MINOR_FOR_REPO}
# ${cluster_name} (if used by script for tagging etc.)

# REMOVE THESE BASH DEFINITIONS - Values will come from Terraform template
# K8S_PACKAGE_VERSION_TO_INSTALL="1.28.3-1.1"
# K8S_MAJOR_MINOR_FOR_REPO="1.28"
# CRIO_K8S_MAJOR_MINOR_FOR_REPO="1.28"

# Initialize progress tracking
mark_progress() {
  local stage="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $stage"
  echo "$stage" > /var/log/worker-bootstrap-progress
}

# 1. Configure SSH first for emergency access
mark_progress "Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh

if [ -n "${SSH_PUBLIC_KEY}" ]; then # ${SSH_PUBLIC_KEY} is from templatefile
  cat > /home/ubuntu/.ssh/authorized_keys << 'EOF'
${SSH_PUBLIC_KEY}
EOF
  chmod 600 /home/ubuntu/.ssh/authorized_keys
  chown -R ubuntu:ubuntu /home/ubuntu/.ssh

  mkdir -p /root/.ssh
  cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys
  chmod 700 /root/.ssh
  chmod 600 /root/.ssh/authorized_keys
  chown -R root:root /root/.ssh
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] SSH public key configured via template."
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] No explicit SSH_PUBLIC_KEY provided by template; relying on EC2 instance key pair."
fi

# 2. Install essential packages
mark_progress "Installing essential packages"
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl unzip jq gpg

# 3. Install AWS CLI for metadata access
mark_progress "Installing AWS CLI"
if ! command -v aws &> /dev/null; then
  curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip
  ./aws/install --update
  rm -rf awscliv2.zip aws/
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] AWS CLI installed."
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] AWS CLI already present."
fi
aws --version

# 4. Get instance metadata with robust retry
mark_progress "Retrieving instance metadata"
get_metadata() {
  local max_attempts=5; local attempt=1; local wait_time=5; local key="$1"; local value=""
  local imds_token
  imds_token=$(curl -s -f -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || echo "")
  
  while [ "$attempt" -le "$max_attempts" ]; do
    if [ -n "$imds_token" ]; then
      value=$(curl -s -f -H "X-aws-ec2-metadata-token: $imds_token" "http://169.254.169.254/latest/meta-data/$key" 2>/dev/null || echo "")
    else
      value=$(curl -s -f "http://169.254.169.254/latest/meta-data/$key" 2>/dev/null || echo "")
    fi
    if [ -n "$value" ] && [ "$value" != "404 - Not Found" ]; then echo "$value"; return 0; fi
    # Escape bash-specific ${imds_token:0:5} for templatefile
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to get metadata: $key (attempt $attempt/$max_attempts). Token: [$${imds_token:0:5}...]. Value: [$value]"
    sleep "$wait_time"; attempt=$((attempt + 1)); wait_time=$((wait_time * 2))
  done
  echo ""; return 1
}

# Use ${region} passed from Terraform template as the primary source for EFFECTIVE_REGION
EFFECTIVE_REGION="${region}" # ${region} is from templatefile
INSTANCE_ID_FROM_META=$(get_metadata "instance-id")
PRIVATE_IP_FROM_META=$(get_metadata "local-ipv4")
AZ_FROM_META=$(get_metadata "placement/availability-zone")

if [ -z "$EFFECTIVE_REGION" ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] AWS Region not provided via template."; exit 1; fi
if [ -z "$INSTANCE_ID_FROM_META" ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] Could not retrieve Instance ID."; exit 1; fi
if [ -z "$PRIVATE_IP_FROM_META" ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] Could not retrieve Private IP."; exit 1; fi
if [ -z "$AZ_FROM_META" ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Could not retrieve Availability Zone. Using fallback."; AZ_FROM_META="$${EFFECTIVE_REGION}a"; fi # Escape for templatefile

NODE_NAME_SUFFIX=$(echo "$INSTANCE_ID_FROM_META" | cut -d'-' -f2)
NODE_NAME="worker-$NODE_NAME_SUFFIX"
hostnamectl set-hostname "$NODE_NAME"
echo "127.0.0.1 $NODE_NAME" >> /etc/hosts

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Instance metadata:"
echo "  Instance ID: $INSTANCE_ID_FROM_META"
echo "  Private IP: $PRIVATE_IP_FROM_META"
echo "  Region: $EFFECTIVE_REGION" # This is the bash variable EFFECTIVE_REGION
echo "  AZ: $AZ_FROM_META"
echo "  Node name: $NODE_NAME"

# 6. Configure basic Kubernetes prerequisites
mark_progress "Configuring Kubernetes prerequisites"
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system

swapoff -a
sed -i.bak '/swap/s/^/#/' /etc/fstab || echo "No swap entries found in /etc/fstab or sed failed."

# 7. Install CRI-O (Container Runtime)
# Use ${CRIO_K8S_MAJOR_MINOR_FOR_REPO} from templatefile
mark_progress "Installing CRI-O (for K8s v${CRIO_K8S_MAJOR_MINOR_FOR_REPO})"
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/addons:/cri-o:/stable:/v${CRIO_K8S_MAJOR_MINOR_FOR_REPO}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/stable:/v${CRIO_K8S_MAJOR_MINOR_FOR_REPO}/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update -y
apt-get install -y cri-o cri-o-runc
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] CRI-O packages installed."

CRIO_CONF_DIR="/etc/crio/crio.conf.d"
mkdir -p "$CRIO_CONF_DIR"
cat > "$${CRIO_CONF_DIR}/01-cgroup-manager.conf" << EOF
[crio.runtime]
cgroup_manager = "systemd"
EOF
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Configured CRI-O for systemd cgroup manager."

systemctl daemon-reload
systemctl enable --now crio
systemctl restart crio
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] CRI-O started and enabled."

# 8. Install Kubernetes components
# Use ${K8S_MAJOR_MINOR_FOR_REPO} and ${K8S_PACKAGE_VERSION_TO_INSTALL} from templatefile
mark_progress "Installing Kubernetes components (v${K8S_MAJOR_MINOR_FOR_REPO}, package ${K8S_PACKAGE_VERSION_TO_INSTALL})"
curl -fsSL "https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR_FOR_REPO}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR_FOR_REPO}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update -y
apt-get install -y kubelet="${K8S_PACKAGE_VERSION_TO_INSTALL}" kubeadm="${K8S_PACKAGE_VERSION_TO_INSTALL}" kubectl="${K8S_PACKAGE_VERSION_TO_INSTALL}"
apt-mark hold kubelet kubeadm kubectl cri-o
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Kubernetes components installed and held."

# 9. Configure Kubelet to use CRI-O
mark_progress "Configuring Kubelet for CRI-O"
KUBELET_DROPIN_DIR="/etc/systemd/system/kubelet.service.d"
mkdir -p "$KUBELET_DROPIN_DIR" # Use $KUBELET_DROPIN_DIR (bash variable)
cat > "$${KUBELET_DROPIN_DIR}/10-kubeadm.conf" << EOF # Escape $ for KUBELET_DROPIN_DIR
# This file is created by kubeadm init/join.
# To override kubelet args, create a file like /etc/systemd/system/kubelet.service.d/20-extra-args.conf
EOF
cat > "$${KUBELET_DROPIN_DIR}/00-crio.conf" << EOF # Escape $ for KUBELET_DROPIN_DIR
[Service]
Environment="KUBELET_EXTRA_ARGS=--container-runtime-endpoint=unix:///var/run/crio/crio.sock --node-ip=$${PRIVATE_IP_FROM_META} --hostname-override=$${NODE_NAME} --cloud-provider=external"
EOF

systemctl daemon-reload
systemctl enable --now kubelet
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Kubelet configured for CRI-O, started and enabled."

# 10. Retrieve and execute join command
mark_progress "Retrieving join command"
# ${JOIN_COMMAND_LATEST_SECRET} and ${JOIN_COMMAND_SECRET} are from templatefile
JOIN_SECRETS_TO_TRY=("${JOIN_COMMAND_LATEST_SECRET}" "${JOIN_COMMAND_SECRET}")
RAW_JOIN_COMMAND=""

MAX_SECRET_FETCH_ATTEMPTS=10
for attempt in $(seq 1 $MAX_SECRET_FETCH_ATTEMPTS); do
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempt $attempt/$MAX_SECRET_FETCH_ATTEMPTS to retrieve join command secret"
  # Correctly escaped for templatefile, iterate through array elements differently
  for secret_id_to_try in $${JOIN_SECRETS_TO_TRY[*]}; do
    if [ -z "$secret_id_to_try" ]; then continue; fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Trying to retrieve secret: $secret_id_to_try"
    
    RAW_JOIN_COMMAND=$(aws secretsmanager get-secret-value \
      --secret-id "$secret_id_to_try" \
      --region "$EFFECTIVE_REGION" \
      --query 'SecretString' \
      --output text 2>/dev/null || echo "")
    
    if [ -n "$RAW_JOIN_COMMAND" ] && [[ "$RAW_JOIN_COMMAND" == *"kubeadm join"* ]]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Successfully retrieved join command from $secret_id_to_try"
      break 2
    else
      RAW_JOIN_COMMAND=""
    fi
  done
  if [ -n "$RAW_JOIN_COMMAND" ]; then break; fi
  echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to get valid join command on attempt $attempt, waiting 30s..."
  sleep 30
done

if [ -z "$RAW_JOIN_COMMAND" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] Failed to retrieve a valid join command after $MAX_SECRET_FETCH_ATTEMPTS attempts."
  exit 1
fi

CRIO_SOCKET_PATH="unix:///var/run/crio/crio.sock"
MODIFIED_JOIN_COMMAND="$RAW_JOIN_COMMAND --cri-socket $CRIO_SOCKET_PATH --node-name $NODE_NAME"

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Using join command: $MODIFIED_JOIN_COMMAND"

mark_progress "Joining cluster"
kubeadm reset -f || echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] kubeadm reset failed, proceeding with join anyway..."

MAX_JOIN_ATTEMPTS=10
JOIN_RETRY_DELAY=30
for attempt in $(seq 1 $MAX_JOIN_ATTEMPTS); do
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Attempt $attempt/$MAX_JOIN_ATTEMPTS to join Kubernetes cluster"
  if eval "$MODIFIED_JOIN_COMMAND --v=5"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Successfully joined the cluster!"
    touch /var/log/worker-join-success
    mark_progress "Joined successfully"
    
    # Optional: Tag instance. Ensure ${cluster_name} is passed if used.
    # aws ec2 create-tags \
    #   --resources "$INSTANCE_ID_FROM_META" \
    #   --tags Key=Name,Value="$NODE_NAME" Key=kubernetes.io/cluster/"${cluster_name}",Value=owned \
    #   --region "$EFFECTIVE_REGION" || echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to create some EC2 tags."
    
    exit 0
  fi
  echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to join cluster on attempt $attempt. Retrying in $JOIN_RETRY_DELAY seconds..."
  sleep $JOIN_RETRY_DELAY
done

echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] Failed to join cluster after $MAX_JOIN_ATTEMPTS attempts"
journalctl -u kubelet --no-pager -n 100
mark_progress "Failed to join cluster"
exit 1
