#!/bin/bash
set -euo pipefail # Exit on error, unset variable, or pipe failure

# =================================================================
# KUBERNETES CONTROL PLANE BOOTSTRAP - COMPREHENSIVE v10.4 (IMDSv2 & Shell Corrected)
# =================================================================

# Set up comprehensive logging
BOOTSTRAP_LOG="/var/log/k8s-bootstrap-control-plane.log"
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"

# Create log files and ensure they're writable
touch "$BOOTSTRAP_LOG" "$CLOUD_INIT_LOG"
chmod 644 "$BOOTSTRAP_LOG" "$CLOUD_INIT_LOG"

# Redirect all output (stdout and stderr) to both bootstrap log and cloud-init log
exec > >(tee -a "$BOOTSTRAP_LOG" "$CLOUD_INIT_LOG") 2>&1

# --- IMDSv2 Token Fetch ---
# Fetch the IMDSv2 token. If this fails, the script cannot proceed with metadata calls.
# Retry fetching token a few times in case of transient issues.
IMDS_TOKEN=""
for i in 1 2 3; do
    IMDS_TOKEN=$(curl -fsSL -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    if [ -n "$IMDS_TOKEN" ]; then
        break
    fi
    echo "Warning: Failed to fetch IMDSv2 token (attempt $i/3). Retrying in 2 seconds..."
    sleep 2
done

if [ -z "$IMDS_TOKEN" ]; then
    echo "CRITICAL: Failed to retrieve IMDSv2 token after 3 attempts. Cannot access instance metadata."
    # Not calling error_exit here as it also uses metadata, just exit.
    exit 1
fi
echo "IMDSv2 token fetched successfully."
# --- End IMDSv2 Token Fetch ---

# Function to get metadata using the token
get_metadata() {
    local path="$1"
    curl -fsSL -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" "http://169.254.169.254/latest/meta-data/$path" 2>/dev/null || echo "unknown"
}


echo "================================================================="
echo "= KUBERNETES CONTROL PLANE BOOTSTRAP - STARTED (TEMPLATE v10.4) ="
echo "= Template Variables Received & Used:                           ="
echo "=   K8S Version Full:    ${K8S_VERSION_FULL}"
echo "=   K8S Major.Minor:     ${K8S_MAJOR_MINOR}"
echo "=   K8S Package Version: ${K8S_PACKAGE_VERSION}"
echo "=   Region:              ${REGION}"
echo "=   Cluster Name:        ${CLUSTER_NAME}"
echo "=   Hostname Suffix:     ${HOSTNAME_SUFFIX}"
echo "=   Kubeadm Token:       (Value is sensitive, not logged)"
echo "=   Pod CIDR:            ${POD_CIDR_BLOCK}"
echo "=   Kubeconfig Secret:   ${KUBECONFIG_SECRET_NAME}"
echo "=   Primary Join Secret: ${JOIN_COMMAND_PRIMARY_SECRET_NAME}"
echo "=   Latest Join Secret:  ${JOIN_COMMAND_LATEST_SECRET_NAME}"
echo "=   Calico Version:      ${CALICO_VERSION}"
echo "================================================================="
echo "= Current Time (UTC):    $(date -u)"
echo "= Instance ID:         $(get_metadata instance-id)"
echo "= Private IP (metadata): $(get_metadata local-ipv4)"
echo "= Public IP (metadata):  $(get_metadata public-ipv4)"
echo "================================================================="

# Error handling function
error_exit() {
    local error_message="$1"
    local exit_code_val="$?"
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "❌ FATAL ERROR: $error_message"
    echo "❌ Script: control_plane_bootstrap.sh.tpl"
    echo "❌ Time (UTC): $(date -u)"
    echo "❌ Exit Code: $exit_code_val"
    echo "❌ Line Number: $LINENO"
    echo "❌ Working Directory: $(pwd)"
    echo "-----------------------------------------------------------------"
    echo "RECENT LOGS ($BOOTSTRAP_LOG) - Last 50 lines:"
    tail -n 50 "$BOOTSTRAP_LOG"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    if command -v aws >/dev/null && aws sts get-caller-identity >/dev/null 2>&1; then
        S3_DEBUG_BUCKET_NAME="${CLUSTER_NAME}-bootstrap-debug-logs"
        INSTANCE_ID_DEBUG="$(get_metadata instance-id)" # Use get_metadata function
        LOG_S3_KEY="control-plane-failures/$INSTANCE_ID_DEBUG-bootstrap-$(date +%Y%m%d%H%M%S).log"
        echo "Attempting to upload full log to s3://$S3_DEBUG_BUCKET_NAME/$LOG_S3_KEY"
        aws s3 cp "$BOOTSTRAP_LOG" "s3://$S3_DEBUG_BUCKET_NAME/$LOG_S3_KEY" --region "${REGION}" || echo "Warning: Failed to upload full debug log to S3."
    fi
    exit $exit_code_val
}

trap 'error_exit "An unexpected error occurred on line $LINENO"' ERR

# Step 0: Set hostname
echo ""
echo "🏷️ STEP 0: Setting hostname..."
NEW_HOSTNAME="${CLUSTER_NAME}-cp-${HOSTNAME_SUFFIX}"
CURRENT_HOSTNAME="$(hostname)"
if [ "$CURRENT_HOSTNAME" != "$NEW_HOSTNAME" ]; then
    hostnamectl set-hostname "$NEW_HOSTNAME" || error_exit "Failed to set hostname using hostnamectl."
    if ! grep -q "$NEW_HOSTNAME" /etc/hosts; then
      echo "127.0.0.1 $NEW_HOSTNAME" >> /etc/hosts
    fi
    echo "✅ Hostname set to: $NEW_HOSTNAME (Previous: $CURRENT_HOSTNAME)."
else
    echo "✅ Hostname already set to: $NEW_HOSTNAME"
fi
echo "   Current effective hostname: $(hostname)"

# Step 1: System updates and essential packages (No changes needed for IMDSv2 here)
# ... (Content from your previous script, lines for Step 1 are generally fine) ...
echo ""
echo "📦 STEP 1: System updates and essential package installation..."
export DEBIAN_FRONTEND=noninteractive
echo "   Updating package lists (apt-get update)..."
apt-get update -y || error_exit "Failed to update package lists (apt-get update)"
echo "   Installing essential packages (curl, wget, unzip, jq, awscli, gnupg, etc.)..."
apt-get install -y curl wget unzip jq awscli ca-certificates gnupg lsb-release software-properties-common apt-transport-https socat conntrack ipset || error_exit "Failed to install one or more essential packages"
echo "✅ Essential packages installed."
echo "   Verifying AWS CLI..."
aws --version || error_exit "AWS CLI is not working after installation"
echo "✅ AWS CLI verified."

# Step 2: System configuration for Kubernetes (No changes needed for IMDSv2 here)
# ... (Content from your previous script, lines for Step 2 are generally fine) ...
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
sysctl --system || error_exit "Failed to apply sysctl settings from /etc/sysctl.d/99-kubernetes-cri.conf"
echo "✅ Sysctl parameters configured."
echo "✅ System configuration for Kubernetes completed."

# Step 3: Install containerd (No changes needed for IMDSv2 here)
# ... (Content from your previous script, lines for Step 3 are generally fine) ...
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
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml || error_exit "Failed to set SystemdCgroup = true in containerd config"
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

# Step 4: Install Kubernetes components (No changes needed for IMDSv2 here)
# ... (Content from your previous script, lines for Step 4 are generally fine) ...
echo ""
echo "☸️  STEP 4: Installing Kubernetes components (kubelet, kubeadm, kubectl)..."
echo "   Adding Kubernetes apt repository GPG key (Major.Minor: ${K8S_MAJOR_MINOR})..."
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg || error_exit "Failed to download or dearmor Kubernetes GPG key"
chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "   Adding Kubernetes apt repository to sources.list.d..."
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list > /dev/null || error_exit "Failed to add Kubernetes apt repository"
echo "   Updating package lists after adding Kubernetes repository..."
apt-get update -y || error_exit "Failed to update package lists after adding K8s repo"
echo "   Installing kubelet, kubeadm, kubectl (Package Version: ${K8S_PACKAGE_VERSION})..."
for i in 1 2 3; do
  if apt-get install -y \
      kubelet=${K8S_PACKAGE_VERSION} \
      kubeadm=${K8S_PACKAGE_VERSION} \
      kubectl=${K8S_PACKAGE_VERSION}; then
    break
  fi
  if [ $i -eq 3 ]; then
    error_exit "Failed to install kubelet, kubeadm, or kubectl (version ${K8S_PACKAGE_VERSION}) after 3 attempts."
  fi
  echo "Warning: apt-get install failed (attempt $i/3), retrying in 10 seconds..."
  sleep 10
  apt-get update -y
done
echo "   Holding Kubernetes packages to prevent unintended upgrades..."
apt-mark hold kubelet kubeadm kubectl || error_exit "Failed to put Kubernetes packages on hold"
echo "   Verifying Kubernetes component installations..."
kubectl version --client --output=yaml || error_exit "kubectl command failed or not installed correctly"
kubeadm version -o yaml || error_exit "kubeadm command failed or not installed correctly"
kubelet --version || error_exit "kubelet command failed or not installed correctly"
echo "✅ Kubernetes components installed and verified."

# Step 5: Configure Kubelet
echo ""
echo "🛠️  STEP 5: Configuring Kubelet..."
PRIVATE_IP="$(get_metadata local-ipv4)" # Use get_metadata function
if [ -z "$PRIVATE_IP" ] || [ "$PRIVATE_IP" == "unknown" ]; then
    error_exit "Failed to retrieve private IP from instance metadata for Kubelet configuration"
fi
echo "   Retrieved Private IP for Kubelet: $PRIVATE_IP"
echo "   Creating Kubelet drop-in configuration for cloud provider and node IP..."
KUBELET_CONF_DIR="/etc/systemd/system/kubelet.service.d"
mkdir -p "$KUBELET_CONF_DIR"
cat > "$KUBELET_CONF_DIR/20-aws.conf" <<EOF
[Service]
Environment="KUBELET_EXTRA_ARGS=--cloud-provider=external --node-ip=$PRIVATE_IP"
EOF
echo "   Reloading systemd daemon and restarting Kubelet (kubeadm will also manage this)..."
systemctl daemon-reload
systemctl restart kubelet || echo "Warning: Kubelet restart attempt failed. Kubeadm init will attempt to manage it."
echo "✅ Kubelet configuration updated."

# Step 6: Initialize Kubernetes cluster with Kubeadm
echo ""
echo "🚀 STEP 6: Initializing Kubernetes cluster with Kubeadm..."
echo "   Creating Kubeadm configuration file (/etc/kubernetes/kubeadm/kubeadm-config.yaml)..."
mkdir -p /etc/kubernetes/kubeadm
# PRIVATE_IP and NEW_HOSTNAME are now correctly expanded shell variables
cat > /etc/kubernetes/kubeadm/kubeadm-config.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${KUBEADM_TOKEN}"
  description: "kubeadm bootstrap token for joining nodes"
  ttl: "24h0m0s"
  usages:
  - signing
  - authentication
localAPIEndpoint:
  advertiseAddress: "$PRIVATE_IP"
  bindPort: 6443
nodeRegistration:
  name: "$NEW_HOSTNAME"
  criSocket: "unix:///run/containerd/containerd.sock"
  kubeletExtraArgs:
    cloud-provider: "external"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: "v${K8S_VERSION_FULL}"
controlPlaneEndpoint: "$PRIVATE_IP:6443"
apiServer:
  certSANs:
  - "$PRIVATE_IP"
  - "$NEW_HOSTNAME"
  - "127.0.0.1"
  - "localhost"
  - "kubernetes"
  - "kubernetes.default"
  - "kubernetes.default.svc"
  - "kubernetes.default.svc.cluster.local"
  # - "$(get_metadata public-ipv4)" # If API needs to be exposed on public IP via cert
controllerManager:
  extraArgs:
    cloud-provider: "external"
networking:
  podSubnet: "${POD_CIDR_BLOCK}"
  serviceSubnet: "10.96.0.0/12"
EOF
echo "   Kubeadm configuration file created."
echo "   Configuration preview (first 20 lines):"
head -n 20 /etc/kubernetes/kubeadm/kubeadm-config.yaml || echo "Warning: Could not display kubeadm config preview."
echo "   Running 'kubeadm init' (this may take several minutes)..."
echo "   Command: kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5"
echo "   Start time (UTC): $(date -u)"
KUBEADM_INIT_LOG="/var/log/kubeadm-init.log"
if kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5 > "$KUBEADM_INIT_LOG" 2>&1; then
    echo "✅ 'kubeadm init' completed successfully!"
    echo "   End time (UTC): $(date -u)"
    echo "   Last 20 lines of kubeadm init log ($KUBEADM_INIT_LOG):"
    tail -n 20 "$KUBEADM_INIT_LOG"
else
    echo "❌ 'kubeadm init' FAILED!"
    echo "   End time (UTC): $(date -u)"
    echo "   Full kubeadm init log ($KUBEADM_INIT_LOG) content:"
    cat "$KUBEADM_INIT_LOG"
    error_exit "'kubeadm init' command failed. Check $KUBEADM_INIT_LOG for details."
fi
echo "   Verifying admin.conf creation..."
if [ ! -f /etc/kubernetes/admin.conf ] || [ ! -s /etc/kubernetes/admin.conf ]; then
    error_exit "/etc/kubernetes/admin.conf was not created or is empty after kubeadm init."
fi
ADMIN_CONF_SIZE="$(stat -c%s /etc/kubernetes/admin.conf)"
echo "✅ /etc/kubernetes/admin.conf created successfully (Size: $ADMIN_CONF_SIZE bytes)."

# Step 7: Set up Kubeconfig for root and default (ubuntu/ec2-user) users
echo ""
echo "🔧 STEP 7: Setting up Kubeconfig for local users..."
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config
chmod 0600 /root/.kube/config
echo "   Kubeconfig for root user set up."
DEFAULT_USER="ubuntu"
if id "$DEFAULT_USER" &>/dev/null; then
    mkdir -p "/home/$DEFAULT_USER/.kube"
    cp -i /etc/kubernetes/admin.conf "/home/$DEFAULT_USER/.kube/config"
    chown "$DEFAULT_USER":"$DEFAULT_USER" "/home/$DEFAULT_USER/.kube/config" "/home/$DEFAULT_USER/.kube"
    chmod 0600 "/home/$DEFAULT_USER/.kube/config"
    echo "   Kubeconfig for $DEFAULT_USER user set up."
else
    echo "   Default user '$DEFAULT_USER' not found, skipping its kubeconfig setup."
fi
echo "✅ Kubeconfig setup for local users completed."

# Step 8: Store modified Kubeconfig in AWS Secrets Manager
echo ""
echo "🔐 STEP 8: Preparing and Storing Kubeconfig in AWS Secrets Manager..."
KUBECONFIG_CONTENT_ORIGINAL="$(cat /etc/kubernetes/admin.conf)"
PUBLIC_IP_FOR_KUBECONFIG="$(get_metadata public-ipv4 || echo "$PRIVATE_IP")"
if [ -z "$PUBLIC_IP_FOR_KUBECONFIG" ] || [ "$PUBLIC_IP_FOR_KUBECONFIG" == "unknown" ]; then
    echo "Warning: Could not determine public IP for Kubeconfig. Using private IP: $PRIVATE_IP"
    PUBLIC_IP_FOR_KUBECONFIG="$PRIVATE_IP"
fi
if [ -z "$PUBLIC_IP_FOR_KUBECONFIG" ]; then
    error_exit "Failed to get a usable IP (public or private) for kubeconfig server field."
fi
echo "   Updating kubeconfig server endpoint for external access to: https://$PUBLIC_IP_FOR_KUBECONFIG:6443"
MODIFIED_KUBECONFIG_FOR_SECRET="$(echo "$KUBECONFIG_CONTENT_ORIGINAL" | sed "s|server: https://[^:]*:6443|server: https://$PUBLIC_IP_FOR_KUBECONFIG:6443|")"
if ! echo "$MODIFIED_KUBECONFIG_FOR_SECRET" | grep -q "server: https://$PUBLIC_IP_FOR_KUBECONFIG:6443"; then
    echo "Warning: sed command might not have correctly updated the server IP in kubeconfig for secret."
    echo "Original content server line: $(echo "$KUBECONFIG_CONTENT_ORIGINAL" | grep "server:")"
    echo "Attempted modified content server line: $(echo "$MODIFIED_KUBECONFIG_FOR_SECRET" | grep "server:")"
    MODIFIED_KUBECONFIG_FOR_SECRET="$KUBECONFIG_CONTENT_ORIGINAL"
    echo "Using original kubeconfig content for secret due to modification issue."
fi
if echo "$MODIFIED_KUBECONFIG_FOR_SECRET" | grep -q "apiVersion"; then
    echo "   Attempting to store modified kubeconfig in Secret: ${KUBECONFIG_SECRET_NAME}"
    # REMOVED --no-cli-pager
    aws secretsmanager put-secret-value \
      --secret-id "${KUBECONFIG_SECRET_NAME}" \
      --secret-string "$MODIFIED_KUBECONFIG_FOR_SECRET" \
      --region "${REGION}" \
      || error_exit "Failed to upload Kubeconfig to AWS Secrets Manager (${KUBECONFIG_SECRET_NAME})"
    echo "✅ Kubeconfig successfully stored in AWS Secrets Manager: ${KUBECONFIG_SECRET_NAME}"
else
    error_exit "Generated Kubeconfig content for secret appears invalid (missing apiVersion after potential modification)."
fi

# Step 9: Test cluster access (No changes needed for IMDSv2 here if KUBECONFIG is set)
echo ""
echo "🔍 STEP 9: Testing cluster access using local Kubeconfig (admin.conf)..."
export KUBECONFIG=/etc/kubernetes/admin.conf
echo "   Running 'kubectl cluster-info'..."
if kubectl cluster-info; then
    echo "✅ 'kubectl cluster-info' successful."
    echo "   Running 'kubectl get nodes'..."
    kubectl get nodes -o wide || echo "Warning: 'kubectl get nodes' failed but cluster-info was okay."
else
    error_exit "Failed to access Kubernetes cluster using local Kubeconfig (/etc/kubernetes/admin.conf) even after kubeadm init supposedly succeeded."
fi
echo "✅ Cluster access test (local admin.conf) completed."

# Step 10: Install CNI (Calico) (No changes needed for IMDSv2 here if KUBECONFIG is set)
echo ""
echo "🌐 STEP 10: Installing CNI (Calico)..."
export KUBECONFIG=/etc/kubernetes/admin.conf
CALICO_MANIFEST_URL="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
echo "   Applying Calico manifest (Version from Terraform: ${CALICO_VERSION}) from: $CALICO_MANIFEST_URL"
CNI_APPLY_SUCCESS=false
for i in 1 2 3; do
  if kubectl apply -f "$CALICO_MANIFEST_URL"; then
    echo "✅ Calico CNI manifest applied successfully (attempt $i)."
    CNI_APPLY_SUCCESS=true
    break
  fi
  echo "⚠️ Calico apply failed (attempt $i/3), retrying in 15 seconds..."
  sleep 15
done
if [ "$CNI_APPLY_SUCCESS" != "true" ]; then
    echo "⚠️ WARNING: 'kubectl apply -f calico.yaml' (URL: $CALICO_MANIFEST_URL) failed after 3 attempts. CNI may not be functional. Check $BOOTSTRAP_LOG."
else
    echo "   Waiting briefly for Calico pods to start (approx 60-120s, this is not a comprehensive check)..."
    sleep 60
    kubectl get pods -n kube-system -l k8s-app=calico-node --no-headers=true || echo "Info: Could not list calico-node pods immediately, they might still be starting."
    kubectl get pods -n kube-system -l k8s-app=calico-kube-controllers --no-headers=true || echo "Info: Could not list calico-kube-controllers pods immediately."
fi
echo "✅ CNI installation step completed."

# Step 11: Store Join Command (No changes needed for IMDSv2 here if KUBECONFIG is set)
echo ""
echo "🔑 STEP 11: Generating and storing new Kubeadm Join Command in AWS Secrets Manager..."
echo "   Generating new join command (kubeadm token create --print-join-command)..."
export KUBECONFIG=/etc/kubernetes/admin.conf
FRESH_JOIN_COMMAND="$(kubeadm token create --print-join-command 2>/dev/null || echo "")"
if [ -n "$FRESH_JOIN_COMMAND" ]; then
    echo "   Join command generated successfully."
    echo "   Storing join command in Primary Secret: ${JOIN_COMMAND_PRIMARY_SECRET_NAME}"
    # REMOVED --no-cli-pager
    aws secretsmanager put-secret-value \
        --secret-id "${JOIN_COMMAND_PRIMARY_SECRET_NAME}" \
        --secret-string "$FRESH_JOIN_COMMAND" \
        --region "${REGION}" \
        || echo "⚠️ Warning: Failed to store join command in primary secret (${JOIN_COMMAND_PRIMARY_SECRET_NAME})"
    echo "   Storing join command in Latest Secret: ${JOIN_COMMAND_LATEST_SECRET_NAME}"
    # REMOVED --no-cli-pager
    aws secretsmanager put-secret-value \
        --secret-id "${JOIN_COMMAND_LATEST_SECRET_NAME}" \
        --secret-string "$FRESH_JOIN_COMMAND" \
        --region "${REGION}" \
        || echo "⚠️ Warning: Failed to store join command in latest secret (${JOIN_COMMAND_LATEST_SECRET_NAME})"
    echo "✅ Join command stored/updated in AWS Secrets Manager."
else
    error_exit "Failed to generate a fresh Kubeadm join command. Workers will not be able to join."
fi

# Final status report (Use get_metadata for instance ID)
echo ""
echo "================================================================="
echo "= KUBERNETES CONTROL PLANE BOOTSTRAP - COMPLETED (TEMPLATE v10.4)="
echo "= Current Time (UTC): $(date -u)"
echo "= Overall Status: SUCCESS"
echo "================================================================="
echo "📊 Final System Verification:"
echo "   kubectl client version: $(kubectl version --client --short 2>/dev/null || echo 'N/A')"
echo "   kubeadm version:        $(kubeadm version -o short 2>/dev/null || echo 'N/A')"
echo "   kubelet service:      $(systemctl is-active kubelet 2>/dev/null || echo 'N/A')"
echo "   containerd service:   $(systemctl is-active containerd 2>/dev/null || echo 'N/A')"
echo "   admin.conf status:    $([ -f /etc/kubernetes/admin.conf ] && [ -s /etc/kubernetes/admin.conf ] && echo 'EXISTS and NOT EMPTY' || echo 'MISSING or EMPTY')"
echo "================================================================="
echo "✅ Bootstrap script finished successfully."
echo "ℹ️ Main log: $BOOTSTRAP_LOG"
echo "ℹ️ Kubeadm init log: $KUBEADM_INIT_LOG (if created)"
echo "================================================================="

# End of script
