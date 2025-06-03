#!/bin/bash
set -euo pipefail # Exit on error, unset variable, or pipe failure

# Log file for this worker bootstrap script
WORKER_BOOTSTRAP_LOG="/var/log/k8s-worker-bootstrap.log"
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"

# Create log files and ensure they're writable
touch "$WORKER_BOOTSTRAP_LOG" "$CLOUD_INIT_LOG"
chmod 644 "$WORKER_BOOTSTRAP_LOG" "$CLOUD_INIT_LOG"

# Redirect all output (stdout and stderr) to both bootstrap log and cloud-init log
exec > >(tee -a "$WORKER_BOOTSTRAP_LOG" "$CLOUD_INIT_LOG") 2>&1

echo "================================================================="
echo "= KUBERNETES WORKER NODE BOOTSTRAP SCRIPT (TEMPLATE VERSION) ="
echo "================================================================="
echo "= K8S Major.Minor:       ${K8S_MAJOR_MINOR}"
echo "=   K8S Package Version: ${K8S_PACKAGE_VERSION}"
echo "=   Region:              ${REGION}"
echo "=   Cluster Name:        ${CLUSTER_NAME}"
echo "=   Join Secret Name:    ${TF_JOIN_COMMAND_LATEST_SECRET_NAME}"
echo "=   Control Plane IP:    ${TF_CONTROL_PLANE_PRIVATE_IP} (Note: kubeadm join uses discovery, not this IP directly)"
echo "================================================================="
echo "= Current Time (UTC):    $(date -u)"

# Get IMDSv2 token for instance metadata
IMDS_TOKEN_INITIAL=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || echo "")
if [ -n "$IMDS_TOKEN_INITIAL" ]; then
    echo "= Instance ID:         $(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN_INITIAL" -s "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || echo 'unknown')"
    echo "= Private IP (metadata): $(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN_INITIAL" -s "http://169.254.169.254/latest/meta-data/local-ipv4" 2>/dev/null || echo 'unknown')"
else
    echo "= Instance ID:         $(echo 'unknown - IMDS token failed')"
    echo "= Private IP (metadata): $(echo 'unknown - IMDS token failed')"
fi
echo "================================================================="

# Error handling function
error_exit() {
    local error_message="$1" # Capture argument
    local exit_code_val="$?"  # Capture exit code immediately
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "❌ WORKER NODE FATAL ERROR: $error_message"
    echo "❌ Script: worker_user_data.sh.tpl"
    echo "❌ Time (UTC): $(date -u)"
    echo "❌ Exit Code: $exit_code_val"
    echo "❌ Line Number: $LINENO"
    echo "-----------------------------------------------------------------"
    echo "RECENT LOGS ($WORKER_BOOTSTRAP_LOG) - Last 50 lines:"
    tail -n 50 "$WORKER_BOOTSTRAP_LOG"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    # Attempt to upload log to S3 if variables are available and awscli works
    # TF_S3_WORKER_LOGS_BUCKET and TF_WORKER_ASG_NAME are template variables
    if [ -n "${TF_S3_WORKER_LOGS_BUCKET}" ] && [ -n "${TF_WORKER_ASG_NAME}" ] && command -v aws >/dev/null && aws sts get-caller-identity >/dev/null 2>&1; then
        S3_LOG_BUCKET_NAME="${TF_S3_WORKER_LOGS_BUCKET}"
        ASG_NAME_LOG="${TF_WORKER_ASG_NAME}"
        
        # Get instance ID using IMDSv2
        IMDS_TOKEN_ERROR=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || echo "")
        if [ -n "$IMDS_TOKEN_ERROR" ]; then
            INSTANCE_ID_FOR_LOG="$(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN_ERROR" -s "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || echo 'unknown-instance')"
        else
            INSTANCE_ID_FOR_LOG="unknown-instance-no-token"
        fi
        
        LOG_S3_KEY="worker-node-failures/$ASG_NAME_LOG/$INSTANCE_ID_FOR_LOG-bootstrap-$(date +%Y%m%d%H%M%S).log"
        echo "Attempting to upload full log to s3://$S3_LOG_BUCKET_NAME/$LOG_S3_KEY"
        aws s3 cp "$WORKER_BOOTSTRAP_LOG" "s3://$S3_LOG_BUCKET_NAME/$LOG_S3_KEY" --region "${REGION}" || echo "Warning: Failed to upload full debug log to S3."
    fi
    exit $exit_code_val
}

trap 'error_exit "An unexpected error occurred on line $LINENO"' ERR

# Optional: Install SSH Public Key if provided
# SSH_PUBLIC_KEY_CONTENT is a template variable
if [ -n "${SSH_PUBLIC_KEY_CONTENT}" ]; then
    echo "🔑 STEP 0a: Installing SSH public key for default user..."
    DEFAULT_USER_HOME="/home/ubuntu" # Change if your AMI default user is different
    if [ -d "$DEFAULT_USER_HOME" ]; then
        mkdir -p "$DEFAULT_USER_HOME/.ssh"
        echo "${SSH_PUBLIC_KEY_CONTENT}" >> "$DEFAULT_USER_HOME/.ssh/authorized_keys"
        chmod 700 "$DEFAULT_USER_HOME/.ssh"
        chmod 600 "$DEFAULT_USER_HOME/.ssh/authorized_keys"
        # Use shell command substitution for basename
        chown -R "$(basename "$DEFAULT_USER_HOME")":"$(basename "$DEFAULT_USER_HOME")" "$DEFAULT_USER_HOME/.ssh"
        echo "✅ SSH public key installed for user $(basename "$DEFAULT_USER_HOME")."
    else
        echo "⚠️  Default user home directory '$DEFAULT_USER_HOME' not found. Skipping SSH key installation."
    fi
fi

# Step 1: System updates and essential packages (similar to control plane)
echo ""
echo "📦 STEP 1: System updates and essential package installation..."
export DEBIAN_FRONTEND=noninteractive

echo "   Updating package lists (apt-get update)..."
apt-get update -y || error_exit "Failed to update package lists (apt-get update)"

echo "   Installing essential packages (curl, awscli, gnupg, etc.)..."
apt-get install -y \
    curl \
    wget \
    jq \
    awscli \
    ca-certificates \
    gnupg \
    lsb-release \
    apt-transport-https \
    socat \
    conntrack \
    ipset || error_exit "Failed to install one or more essential packages"
echo "✅ Essential packages installed."

echo "   Verifying AWS CLI..."
aws --version || error_exit "AWS CLI is not working after installation"
echo "✅ AWS CLI verified."

# Step 2: System configuration for Kubernetes (similar to control plane)
echo ""
echo "⚙️  STEP 2: Configuring system for Kubernetes..."
echo "   Disabling swap..."
if [ -n "$(free | grep Swap | awk '{print $2}')" ] && [ "$(free | grep Swap | awk '{print $2}')" -ne "0" ]; then
  swapoff -a || echo "Warning: swapoff -a command failed, but proceeding."
fi
sed -i.bak '/swap/s/^#*/#/' /etc/fstab
echo "✅ Swap disabled (or attempted)."

echo "   Loading required kernel modules (overlay, br_netfilter)..."
cat > /etc/modules-load.d/k8s-custom.conf <<EOF
overlay
br_netfilter
EOF
modprobe overlay || error_exit "Failed to load overlay kernel module"
modprobe br_netfilter || error_exit "Failed to load br_netfilter kernel module"
echo "✅ Kernel modules loaded."

echo "   Configuring sysctl parameters for Kubernetes networking..."
cat > /etc/sysctl.d/99-kubernetes-cri.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system || error_exit "Failed to apply sysctl settings"
echo "✅ Sysctl parameters configured."
echo "✅ System configuration for Kubernetes completed."

# Step 3: Install containerd (Container Runtime) (similar to control plane)
echo ""
echo "🐳 STEP 3: Installing and configuring containerd..."
echo "   Ensuring containerd dependencies are met..."
apt-get install -y libseccomp2 || error_exit "Failed to install libseccomp2 for containerd"

echo "   Installing containerd package..."
apt-get update -y
if ! apt-get install -y containerd.io; then
    echo "Warning: containerd.io package not found or failed to install, attempting 'containerd' package..."
    apt-get install -y containerd || error_exit "Failed to install containerd (tried containerd.io then containerd)"
fi

echo "   Configuring containerd..."
mkdir -p /etc/containerd
if ! containerd config default > /etc/containerd/config.toml; then
    echo "Warning: 'containerd config default' failed. Creating a minimal config."
    cat > /etc/containerd/config.toml <<EOF
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
EOF
else
    echo "   Enabling SystemdCgroup for containerd in generated config..."
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml || error_exit "Failed to set SystemdCgroup = true"
fi

echo "   Restarting and enabling containerd service..."
systemctl daemon-reload
systemctl restart containerd || error_exit "Failed to restart containerd service"
systemctl enable containerd || error_exit "Failed to enable containerd service"
if ! systemctl is-active --quiet containerd; then
    sleep 5
    if ! systemctl is-active --quiet containerd; then
        systemctl status containerd --no-pager
        error_exit "Containerd service is not active after restart"
    fi
fi
echo "✅ Containerd installed and configured successfully."

# Step 4: Install Kubernetes components (kubelet, kubeadm, kubectl)
# K8S_MAJOR_MINOR and K8S_PACKAGE_VERSION are template variables
echo ""
echo "☸️  STEP 4: Installing Kubernetes components (kubelet, kubeadm, kubectl)..."
echo "   Adding Kubernetes apt repository GPG key (Major.Minor: ${K8S_MAJOR_MINOR})..."
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg || error_exit "Failed to add K8s GPG key"
chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "   Adding Kubernetes apt repository..."
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list > /dev/null || error_exit "Failed to add K8s apt repository"
echo "   Updating package lists after adding Kubernetes repository..."
apt-get update -y || error_exit "Failed to update package lists after K8s repo"
echo "   Installing kubelet, kubeadm, kubectl (Package Version: ${K8S_PACKAGE_VERSION})..."
for i in 1 2 3; do
  if apt-get install -y \
      kubelet=${K8S_PACKAGE_VERSION} \
      kubeadm=${K8S_PACKAGE_VERSION} \
      kubectl=${K8S_PACKAGE_VERSION}; then
    break
  fi
  if [ $i -eq 3 ]; then
    error_exit "Failed to install K8s components (version ${K8S_PACKAGE_VERSION}) after 3 attempts."
  fi
  echo "Warning: apt-get install failed (attempt $i/3), retrying in 10 seconds..."
  sleep 10
  apt-get update -y
done
echo "   Holding Kubernetes packages..."
apt-mark hold kubelet kubeadm kubectl || error_exit "Failed to hold K8s packages"
echo "   Verifying Kubernetes component installations..."
kubectl version --client --output=yaml || error_exit "kubectl not installed/working"
kubeadm version -o yaml || error_exit "kubeadm not installed/working"
kubelet --version || error_exit "kubelet not installed/working"
echo "✅ Kubernetes components installed and verified."

# Step 5: Configure Kubelet (Worker specific)
echo ""
echo "🛠️  STEP 5: Configuring Kubelet for worker node..."

# Get IMDSv2 token first, then use it to get private IP
echo "   Getting IMDSv2 session token..."
IMDS_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
if [ -z "$IMDS_TOKEN" ]; then
    error_exit "Failed to retrieve IMDSv2 session token"
fi

echo "   Retrieving private IP using IMDSv2..."
PRIVATE_IP="$(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" -fsSL "http://169.254.169.254/latest/meta-data/local-ipv4" 2>/dev/null)"
if [ -z "$PRIVATE_IP" ]; then
    error_exit "Failed to retrieve private IP for Kubelet configuration on worker."
fi
echo "   Retrieved Private IP for Kubelet: $PRIVATE_IP"

KUBELET_CONF_DIR="/etc/systemd/system/kubelet.service.d"
mkdir -p "$KUBELET_CONF_DIR"
cat > "$KUBELET_CONF_DIR/20-aws.conf" <<EOF
[Service]
Environment="KUBELET_EXTRA_ARGS=--cloud-provider=external --node-ip=$PRIVATE_IP"
EOF

echo "   Reloading systemd daemon and enabling Kubelet (will be started by kubeadm join)..."
systemctl daemon-reload
systemctl enable kubelet || error_exit "Failed to enable kubelet service"
echo "✅ Kubelet configured and enabled."

# Step 6: Join the Kubernetes cluster
echo ""
echo "🔗 STEP 6: Joining the Kubernetes cluster..."
# TF_JOIN_COMMAND_LATEST_SECRET_NAME and REGION are template variables
echo "   Fetching join command from AWS Secrets Manager: ${TF_JOIN_COMMAND_LATEST_SECRET_NAME}"

JOIN_COMMAND=""
for i in {1..10}; do
    JOIN_COMMAND="$(aws secretsmanager get-secret-value \
        --secret-id "${TF_JOIN_COMMAND_LATEST_SECRET_NAME}" \
        --region "${REGION}" \
        --query SecretString --output text 2>/dev/null || echo "")"
    if [ -n "$JOIN_COMMAND" ] && echo "$JOIN_COMMAND" | grep -q "kubeadm join"; then
        echo "   ✅ Successfully fetched join command (attempt $i)."
        break
    fi
    echo "   ⚠️ Failed to fetch join command or command invalid (attempt $i/10). Retrying in 10 seconds..."
    sleep 10
    JOIN_COMMAND=""
done

if [ -z "$JOIN_COMMAND" ]; then
    error_exit "Failed to retrieve a valid join command from Secrets Manager (${TF_JOIN_COMMAND_LATEST_SECRET_NAME}) after multiple attempts."
fi

# Generate standardized worker node name using instance ID
echo "   Generating standardized worker node name..."
INSTANCE_ID="$(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" -fsSL "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null)"
if [ -z "$INSTANCE_ID" ]; then
    error_exit "Failed to retrieve instance ID for worker node naming."
fi
WORKER_NODE_NAME="guy-worker-node-$INSTANCE_ID"
echo "   Worker node will be named: $WORKER_NODE_NAME"

echo "   Retrieved Join Command (first 30 chars): $(echo "$JOIN_COMMAND" | cut -c 1-30)..."
echo "   Executing 'kubeadm join' with custom node name..."
echo "   Command: $JOIN_COMMAND --node-name=$WORKER_NODE_NAME --v=5"
echo "   Start time (UTC): $(date -u)"
KUBEADM_JOIN_LOG="/var/log/kubeadm-join.log"

# Execute kubeadm join with custom node name
if eval "$JOIN_COMMAND --node-name=$WORKER_NODE_NAME --v=5" > "$KUBEADM_JOIN_LOG" 2>&1; then
    echo "✅ 'kubeadm join' completed successfully!"
    echo "   End time (UTC): $(date -u)"
    echo "   Worker node joined as: $WORKER_NODE_NAME"
    echo "   Last 10 lines of kubeadm join log ($KUBEADM_JOIN_LOG):"
    tail -n 10 "$KUBEADM_JOIN_LOG"
else
    echo "❌ 'kubeadm join' FAILED!"
    echo "   End time (UTC): $(date -u)"
    echo "   Full kubeadm join log ($KUBEADM_JOIN_LOG) content:"
    cat "$KUBEADM_JOIN_LOG"
    error_exit "'kubeadm join' command failed. Check $KUBEADM_JOIN_LOG for details."
fi

# Verify Kubelet is active after join
echo "   Verifying Kubelet service is active after join..."
sleep 10
if ! systemctl is-active --quiet kubelet; then
    systemctl status kubelet --no-pager
    error_exit "Kubelet service is not active after 'kubeadm join'."
fi
echo "✅ Kubelet is active."

echo ""
echo "================================================================="
echo "= KUBERNETES WORKER NODE BOOTSTRAP - COMPLETED (TEMPLATE v1) ="
echo "= Current Time (UTC): $(date -u)"
echo "= Overall Status: SUCCESS"
echo "================================================================="
echo "📊 Final System Verification:"
echo "   kubelet service:      $(systemctl is-active kubelet 2>/dev/null || echo 'N/A')"
echo "   containerd service:   $(systemctl is-active containerd 2>/dev/null || echo 'N/A')"
echo "================================================================="
echo "✅ Worker node bootstrap script finished successfully."
echo "ℹ️ Main log: $WORKER_BOOTSTRAP_LOG"
echo "ℹ️ Kubeadm join log: $KUBEADM_JOIN_LOG"
echo "================================================================="

# End of script
