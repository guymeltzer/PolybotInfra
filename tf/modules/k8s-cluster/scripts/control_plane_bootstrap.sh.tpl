#!/bin/bash
set -euo pipefail # Exit on error, unset variable, or pipe failure

# =================================================================
# KUBERNETES CONTROL PLANE BOOTSTRAP - COMPREHENSIVE v10 (Templated)
# =================================================================

# Set up comprehensive logging
BOOTSTRAP_LOG="/var/log/k8s-bootstrap-control-plane.log" # More specific name
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"         # Standard cloud-init log

# Create log files and ensure they're writable
touch "$$BOOTSTRAP_LOG" "$$CLOUD_INIT_LOG"
chmod 644 "$$BOOTSTRAP_LOG" "$$CLOUD_INIT_LOG"

# Redirect all output (stdout and stderr) to both bootstrap log and cloud-init log
exec > >(tee -a "$$BOOTSTRAP_LOG" "$$CLOUD_INIT_LOG") 2>&1

echo "================================================================="
echo "= KUBERNETES CONTROL PLANE BOOTSTRAP - STARTED (TEMPLATE v10)  ="
echo "= Template Variables Used:                                      ="
echo "=   K8S Version Full:    ${K8S_VERSION_FULL}"
echo "=   K8S Major.Minor:     ${K8S_MAJOR_MINOR}"
echo "=   K8S Package Version: ${K8S_PACKAGE_VERSION}"
echo "=   Region:              ${REGION}"
echo "=   Cluster Name:        ${CLUSTER_NAME}"
echo "=   Hostname Suffix:     ${HOSTNAME_SUFFIX}"
echo "=   Kubeadm Token:       (hidden for security)" # Or just first part: ${substr(KUBEADM_TOKEN, 0, 6)}.******
echo "=   Pod CIDR:            ${POD_CIDR_BLOCK}"
echo "=   Kubeconfig Secret:   ${KUBECONFIG_SECRET_NAME}"
echo "=   Primary Join Secret: ${JOIN_COMMAND_PRIMARY_SECRET_NAME}"
echo "=   Latest Join Secret:  ${JOIN_COMMAND_LATEST_SECRET_NAME}"
echo "================================================================="
echo "= Current Time: $$(date)"
echo "= Instance ID:  $$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')"
echo "= Private IP:   $$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null || echo 'unknown')"
echo "= Public IP:    $$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'unknown')"
echo "================================================================="

# Error handling function
error_exit() {
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "❌ FATAL ERROR: $$1"
    echo "❌ Script: control_plane_bootstrap.sh.tpl"
    echo "❌ Time: $$(date)"
    echo "❌ Exit code: $$?"
    echo "❌ Working directory: $$(pwd)"
    echo "-----------------------------------------------------------------"
    echo "RECENT LOGS ($$BOOTSTRAP_LOG):"
    tail -n 50 "$$BOOTSTRAP_LOG"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    # Attempt to upload the bootstrap log to S3 for easier debugging, if awscli is installed and configured
    # This part is best-effort and should not itself cause an exit if it fails.
    if command -v aws >/dev/null && aws sts get-caller-identity >/dev/null 2>&1; then
        S3_DEBUG_BUCKET="s3://${CLUSTER_NAME}-debug-logs" # Define a consistent bucket or make it a var
        INSTANCE_ID_DEBUG="$$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown-instance')"
        aws s3 cp "$$BOOTSTRAP_LOG" "$$S3_DEBUG_BUCKET/control-plane/$$INSTANCE_ID_DEBUG-bootstrap-failure.log" --region "${REGION}" || echo "Failed to upload debug log to S3"
    fi
    exit 1
}

# Trap errors to call the error_exit function
trap 'error_exit "An unexpected error occurred. Line $$LINENO"' ERR

# Step 0: Set hostname
echo ""
echo "🏷️ STEP 0: Setting hostname..."
NEW_HOSTNAME="${CLUSTER_NAME}-cp-${HOSTNAME_SUFFIX}" # Construct hostname using template variables
hostnamectl set-hostname "$$NEW_HOSTNAME"
# Ensure hostname resolves locally
if ! grep -q "$$NEW_HOSTNAME" /etc/hosts; then
  echo "127.0.0.1 $$NEW_HOSTNAME" >> /etc/hosts
fi
echo "✅ Hostname set to: $$NEW_HOSTNAME ($$(hostname))"

# Step 1: System updates and essential packages
echo ""
echo "📦 STEP 1: System updates and essential package installation..."
export DEBIAN_FRONTEND=noninteractive

echo "   Updating package lists..."
apt-get update -y || error_exit "Failed to update package lists (apt-get update)"

echo "   Installing essential packages (curl, wget, unzip, jq, awscli, gnupg, etc.)..."
apt-get install -y \
    curl \
    wget \
    unzip \
    jq \
    awscli \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    apt-transport-https \
    socat \
    conntrack \
    ipset || error_exit "Failed to install one or more essential packages"
echo "✅ Essential packages installed."

echo "   Verifying AWS CLI..."
aws --version || error_exit "AWS CLI is not working after installation"
echo "✅ AWS CLI verified."

# Step 2: System configuration for Kubernetes
echo ""
echo "⚙️  STEP 2: Configuring system for Kubernetes..."
echo "   Disabling swap..."
swapoff -a || echo "Warning: swapoff -a failed, but continuing. This might be okay if swap is already off."
# Comment out swap entries in fstab to make it persistent
sed -i.bak '/swap/s/^/#/' /etc/fstab
echo "✅ Swap disabled (or attempted)."

echo "   Loading required kernel modules (overlay, br_netfilter)..."
cat > /etc/modules-load.d/k8s.conf <<EOF
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

# Step 3: Install containerd (Container Runtime)
echo ""
echo "🐳 STEP 3: Installing and configuring containerd..."
echo "   Installing containerd package..."
apt-get update -y # Ensure lists are fresh before specific package install
apt-get install -y containerd.io || apt-get install -y containerd || error_exit "Failed to install containerd (tried containerd.io then containerd)"

echo "   Configuring containerd..."
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml || error_exit "Failed to generate default containerd config"

echo "   Enabling SystemdCgroup for containerd..."
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml || error_exit "Failed to set SystemdCgroup = true in containerd config"

echo "   Restarting and enabling containerd service..."
systemctl daemon-reload
systemctl restart containerd || error_exit "Failed to restart containerd service"
systemctl enable containerd || error_exit "Failed to enable containerd service"

if ! systemctl is-active --quiet containerd; then
    error_exit "Containerd service is not active after restart"
fi
echo "✅ Containerd installed and configured successfully."

# Step 4: Install Kubernetes components (kubelet, kubeadm, kubectl)
echo ""
echo "☸️  STEP 4: Installing Kubernetes components (kubelet, kubeadm, kubectl)..."
echo "   Adding Kubernetes apt repository GPG key..."
mkdir -p -m 755 /etc/apt/keyrings # Ensure directory exists
curl -fsSL "https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg || error_exit "Failed to download or dearmor Kubernetes GPG key"
chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "   Adding Kubernetes apt repository..."
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list || error_exit "Failed to add Kubernetes apt repository to sources.list.d"

echo "   Updating package lists after adding Kubernetes repository..."
apt-get update -y || error_exit "Failed to update package lists after adding K8s repo"

echo "   Installing kubelet, kubeadm, kubectl (version ${K8S_PACKAGE_VERSION})..."
apt-get install -y \
    kubelet=${K8S_PACKAGE_VERSION} \
    kubeadm=${K8S_PACKAGE_VERSION} \
    kubectl=${K8S_PACKAGE_VERSION} || error_exit "Failed to install kubelet, kubeadm, or kubectl version ${K8S_PACKAGE_VERSION}"

echo "   Holding Kubernetes packages to prevent unintended upgrades..."
apt-mark hold kubelet kubeadm kubectl || error_exit "Failed to put Kubernetes packages on hold"

echo "   Verifying Kubernetes component installations..."
kubectl version --client --output=yaml || error_exit "kubectl command failed or not installed correctly"
kubeadm version -o yaml || error_exit "kubeadm command failed or not installed correctly"
kubelet --version || error_exit "kubelet command failed or not installed correctly"
echo "✅ Kubernetes components (kubelet, kubeadm, kubectl) installed and verified."

# Step 5: Configure Kubelet
echo ""
echo "🛠️  STEP 5: Configuring Kubelet..."
# Fetch private IP from instance metadata for kubelet node-ip
PRIVATE_IP="$$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
if [ -z "$$PRIVATE_IP" ]; then
    error_exit "Failed to retrieve private IP from instance metadata for Kubelet configuration"
fi
echo "   Retrieved Private IP for Kubelet: $$PRIVATE_IP"

echo "   Creating Kubelet drop-in configuration for cloud provider and node IP..."
# KUBELET_DROPIN_DIR is passed from local.template_vars, but not used directly in this version
# We use the standard path.
KUBELET_CONF_DIR="/etc/systemd/system/kubelet.service.d"
mkdir -p "$$KUBELET_CONF_DIR"
cat > "$$KUBELET_CONF_DIR/20-aws.conf" <<EOF
[Service]
Environment="KUBELET_EXTRA_ARGS=--cloud-provider=external --node-ip=$$PRIVATE_IP"
EOF
# Note: If using AWS cloud provider (--cloud-provider=aws), ensure IAM permissions are sufficient.
# For external, other components might need to fulfill cloud provider duties.

echo "   Reloading systemd daemon and restarting Kubelet..."
systemctl daemon-reload
systemctl restart kubelet || echo "Warning: Kubelet restart failed, but continuing to kubeadm init. Kubeadm will manage it."
# Kubeadm will often start/manage kubelet, so a restart failure here might not be fatal yet.
echo "✅ Kubelet configuration updated."

# Step 6: Initialize Kubernetes cluster with Kubeadm
echo ""
echo "🚀 STEP 6: Initializing Kubernetes cluster with Kubeadm..."
echo "   Creating Kubeadm configuration file (/etc/kubernetes/kubeadm/kubeadm-config.yaml)..."
mkdir -p /etc/kubernetes/kubeadm

# Ensure NEW_HOSTNAME and PRIVATE_IP are correctly used from above
# KUBEADM_TOKEN, K8S_VERSION_FULL, POD_CIDR_BLOCK are from template variables
cat > /etc/kubernetes/kubeadm/kubeadm-config.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${KUBEADM_TOKEN}"
  description: "kubeadm bootstrap token"
  ttl: "24h"
localAPIEndpoint:
  advertiseAddress: "$$PRIVATE_IP"
  bindPort: 6443
nodeRegistration:
  name: "$$NEW_HOSTNAME" # Shell variable set in Step 0
  criSocket: "unix:///run/containerd/containerd.sock" # Ensure this matches your container runtime
  kubeletExtraArgs:
    cloud-provider: "external" # Matches Kubelet config
    # Add any other critical Kubelet args needed at registration
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: "v${K8S_VERSION_FULL}" # Template variable
controlPlaneEndpoint: "$$PRIVATE_IP:6443" # PRIVATE_IP is shell variable set above
apiServer:
  certSANs:
  - "$$PRIVATE_IP"   # Shell variable
  - "$$NEW_HOSTNAME" # Shell variable
  - "127.0.0.1"
  - "localhost"
  - "kubernetes"
  - "kubernetes.default"
  - "kubernetes.default.svc"
  - "kubernetes.default.svc.cluster.local"
  # Add public IP or DNS if API server needs to be accessible externally directly through cert SANs
  # - "$$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
controllerManager:
  extraArgs:
    cloud-provider: "external" # If you have an external cloud controller manager
# scheduler:
#   extraArgs:
#     cloud-provider: "external" # If needed
networking:
  podSubnet: "${POD_CIDR_BLOCK}" # Template variable
  serviceSubnet: "10.96.0.0/12" # Default K8s service CIDR, adjust if needed
# etcd:
#   local:
#     dataDir: /var/lib/etcd # Default
EOF

echo "   Kubeadm configuration file created."
echo "   Configuration preview:"
cat /etc/kubernetes/kubeadm/kubeadm-config.yaml || echo "Warning: Could not display kubeadm config preview."

echo "   Running 'kubeadm init' (this may take several minutes)..."
echo "   Command: kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5"
echo "   Start time: $$(date)"
KUBEADM_INIT_LOG="/var/log/kubeadm-init.log" # Log specifically for kubeadm init

# Run kubeadm init and capture all output
if kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5 > "$$KUBEADM_INIT_LOG" 2>&1; then
    echo "✅ 'kubeadm init' completed successfully!"
    echo "   End time: $$(date)"
    echo "   Last 20 lines of kubeadm init log ($$KUBEADM_INIT_LOG):"
    tail -n 20 "$$KUBEADM_INIT_LOG"
else
    echo "❌ 'kubeadm init' FAILED!"
    echo "   End time: $$(date)"
    echo "   Full kubeadm init log ($$KUBEADM_INIT_LOG) content:"
    cat "$$KUBEADM_INIT_LOG"
    error_exit "'kubeadm init' command failed. Check $$KUBEADM_INIT_LOG for details."
fi

echo "   Verifying admin.conf creation..."
if [ ! -f /etc/kubernetes/admin.conf ] || [ ! -s /etc/kubernetes/admin.conf ]; then
    error_exit "/etc/kubernetes/admin.conf was not created or is empty after kubeadm init."
fi
ADMIN_CONF_SIZE="$$(stat -c%s /etc/kubernetes/admin.conf)"
echo "✅ /etc/kubernetes/admin.conf created successfully (Size: $$ADMIN_CONF_SIZE bytes)."

# Step 7: Set up Kubeconfig for root and ubuntu users
echo ""
echo "🔧 STEP 7: Setting up Kubeconfig for local users (root, ubuntu)..."
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config
chmod 0600 /root/.kube/config
echo "   Kubeconfig for root user set up."

if id "ubuntu" &>/dev/null; then
    mkdir -p /home/ubuntu/.kube
    cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
    chown ubuntu:ubuntu /home/ubuntu/.kube/config /home/ubuntu/.kube
    chmod 0600 /home/ubuntu/.kube/config
    echo "   Kubeconfig for ubuntu user set up."
else
    echo "   User 'ubuntu' not found, skipping kubeconfig setup for ubuntu."
fi
echo "✅ Kubeconfig setup for local users completed."

# Step 8: Store modified Kubeconfig in AWS Secrets Manager
echo ""
echo "🔐 STEP 8: Storing Kubeconfig in AWS Secrets Manager..."
KUBECONFIG_CONTENT_ORIGINAL="$$(cat /etc/kubernetes/admin.conf)"
PUBLIC_IP_FOR_KUBECONFIG="$$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "$$PRIVATE_IP")" # Fallback to private IP if public isn't found

if [ -z "$$PUBLIC_IP_FOR_KUBECONFIG" ]; then
    error_exit "Failed to get a usable IP (public or private) for kubeconfig server field."
fi

echo "   Updating kubeconfig server endpoint to: https://$$PUBLIC_IP_FOR_KUBECONFIG:6443"
MODIFIED_KUBECONFIG_FOR_SECRET="$$(echo "$$KUBECONFIG_CONTENT_ORIGINAL" | sed "s|server: https://.*:6443|server: https://$$PUBLIC_IP_FOR_KUBECONFIG:6443|")"

if echo "$$MODIFIED_KUBECONFIG_FOR_SECRET" | grep -q "apiVersion"; then
    echo "   Attempting to store modified kubeconfig in Secret: ${KUBECONFIG_SECRET_NAME}"
    aws secretsmanager put-secret-value \
      --secret-id "${KUBECONFIG_SECRET_NAME}" \
      --secret-string "$$MODIFIED_KUBECONFIG_FOR_SECRET" \
      --region "${REGION}" \
      --no-cli-pager || error_exit "Failed to upload Kubeconfig to AWS Secrets Manager (${KUBECONFIG_SECRET_NAME})"
    echo "✅ Kubeconfig successfully stored in AWS Secrets Manager: ${KUBECONFIG_SECRET_NAME}"
else
    error_exit "Generated Kubeconfig content for secret appears invalid (missing apiVersion)."
fi

# Step 9: Test cluster access using the newly configured Kubeconfig
echo ""
echo "🔍 STEP 9: Testing cluster access using local Kubeconfig..."
export KUBECONFIG=/etc/kubernetes/admin.conf # Use the original admin.conf for local kubectl tests
echo "   Running 'kubectl cluster-info'..."
if kubectl cluster-info; then
    echo "✅ 'kubectl cluster-info' successful."
    echo "   Running 'kubectl get nodes'..."
    kubectl get nodes -o wide || echo "Warning: 'kubectl get nodes' failed but cluster-info was okay."
else
    error_exit "Failed to access Kubernetes cluster using local Kubeconfig even after kubeadm init."
fi
echo "✅ Cluster access test completed."

# Step 10: Install CNI (Calico)
echo ""
echo "🌐 STEP 10: Installing CNI (Calico)..."
# Ensure KUBECONFIG is set for kubectl apply
export KUBECONFIG=/etc/kubernetes/admin.conf

# The CALICO_VERSION template variable is directly used here from Terraform.
# Remove the line: CALICO_VERSION="v3.27.3" from your .tpl script.

# Construct the manifest URL using the template variable ${CALICO_VERSION}
# This variable will be replaced by the value from local.control_plane_template_vars
# The result is then assigned to a shell variable CALICO_MANIFEST_URL
CALICO_MANIFEST_URL="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"

echo "   Applying Calico manifest (Version from Terraform: ${CALICO_VERSION}) from: $$CALICO_MANIFEST_URL" # Log the version being used
# $$CALICO_MANIFEST_URL is used because CALICO_MANIFEST_URL is now a shell variable
if kubectl apply -f "$$CALICO_MANIFEST_URL"; then
    echo "✅ Calico CNI manifest applied successfully."
    echo "   Waiting briefly for Calico pods to start (this is not a comprehensive check)..."
    sleep 60 # Give Calico some time to initialize
    kubectl get pods -n kube-system -l k8s-app=calico-node || echo "Could not list calico-node pods immediately."
    kubectl get pods -n kube-system -l k8s-app=calico-kube-controllers || echo "Could not list calico-kube-controllers pods immediately."
else
    # Do not exit, as CNI can sometimes be applied later or through other means if this fails.
    echo "⚠️  WARNING: 'kubectl apply -f calico.yaml' (URL: $$CALICO_MANIFEST_URL) failed. CNI may not be functional. Check $$BOOTSTRAP_LOG."
fi
echo "✅ CNI installation step completed."

# Step 11: Store Join Command in AWS Secrets Manager
echo ""
echo "🔑 STEP 11: Generating and storing new Kubeadm Join Command in AWS Secrets Manager..."
echo "   Generating new join command (kubeadm token create --print-join-command)..."
# This command needs KUBECONFIG set if run after initial init and some time has passed
export KUBECONFIG=/etc/kubernetes/admin.conf
FRESH_JOIN_COMMAND="$$(kubeadm token create --print-join-command 2>/dev/null || echo "")"

if [ -n "$$FRESH_JOIN_COMMAND" ]; then
    echo "   Join command generated successfully."
    echo "   Storing join command in Primary Secret: ${JOIN_COMMAND_PRIMARY_SECRET_NAME}"
    aws secretsmanager put-secret-value \
        --secret-id "${JOIN_COMMAND_PRIMARY_SECRET_NAME}" \
        --secret-string "$$FRESH_JOIN_COMMAND" \
        --region "${REGION}" \
        --no-cli-pager || echo "⚠️ Warning: Failed to store join command in primary secret (${JOIN_COMMAND_PRIMARY_SECRET_NAME})"

    echo "   Storing join command in Latest Secret: ${JOIN_COMMAND_LATEST_SECRET_NAME}"
    aws secretsmanager put-secret-value \
        --secret-id "${JOIN_COMMAND_LATEST_SECRET_NAME}" \
        --secret-string "$$FRESH_JOIN_COMMAND" \
        --region "${REGION}" \
        --no-cli-pager || echo "⚠️ Warning: Failed to store join command in latest secret (${JOIN_COMMAND_LATEST_SECRET_NAME})"
    echo "✅ Join command stored/updated in AWS Secrets Manager."
else
    error_exit "Failed to generate a fresh Kubeadm join command."
fi

# Final status report
echo ""
echo "================================================================="
echo "= KUBERNETES CONTROL PLANE BOOTSTRAP - COMPLETED (TEMPLATE v10)="
echo "= Current Time: $$(date)"
echo "= Overall Status: SUCCESS"
echo "================================================================="
echo "📊 Final System Verification:"
echo "   kubectl client version: $$(kubectl version --client --short 2>/dev/null || echo 'N/A')"
echo "   kubeadm version:        $$(kubeadm version -o short 2>/dev/null || echo 'N/A')"
echo "   kubelet service:      $$(systemctl is-active kubelet 2>/dev/null || echo 'N/A')"
echo "   containerd service:   $$(systemctl is-active containerd 2>/dev/null || echo 'N/A')"
echo "   admin.conf status:    $$([ -f /etc/kubernetes/admin.conf ] && [ -s /etc/kubernetes/admin.conf ] && echo 'EXISTS and NOT EMPTY' || echo 'MISSING or EMPTY')"
echo "================================================================="
echo "✅ Bootstrap script finished successfully."
echo "ℹ️ Main log: $$BOOTSTRAP_LOG"
echo "ℹ️ Kubeadm init log: $$KUBEADM_INIT_LOG (if created)"
echo "================================================================="

# End of script