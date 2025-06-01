#!/bin/bash
# Control plane initialization script with CRI-O

# Basic setup
set -euo pipefail # Exit on error, unset variable, or pipe failure
export DEBIAN_FRONTEND=noninteractive

# Log everything to a file and also to stdout/stderr (for cloud-init output)
exec > >(tee -a /var/log/k8s-init.log) 2>&1

echo "--- Starting control plane initialization at $(date) ---"

# These variables are expected to be substituted by Terraform's templatefile function:
# ${token_formatted}, ${TOKEN_SUFFIX}, ${ssh_public_key}, ${POD_CIDR},
# ${JOIN_COMMAND_SECRET}, ${JOIN_COMMAND_LATEST_SECRET}, ${region},
# ${K8S_VERSION_FULL}, ${K8S_PACKAGE_VERSION}, ${K8S_MAJOR_MINOR}

# 0. Set Hostname (Good Practice)
echo "Setting hostname..."
if [ -z "${token_formatted}" ]; then # This is substituted by templatefile
  echo "FATAL: token_formatted variable not set in template. Exiting."
  exit 1
fi
# TOKEN_SUFFIX is substituted by templatefile
NEW_HOSTNAME="guy-control-plane-${TOKEN_SUFFIX}"
hostnamectl set-hostname "$NEW_HOSTNAME"
if grep -q "127.0.0.1 $NEW_HOSTNAME" /etc/hosts; then
    echo "Hostname $NEW_HOSTNAME already in /etc/hosts for 127.0.0.1."
else
    if grep -q "127.0.0.1 localhost" /etc/hosts; then
        sed -i "/^127.0.0.1 localhost/ s/$/ $NEW_HOSTNAME/" /etc/hosts
    else
        echo "127.0.0.1 localhost $NEW_HOSTNAME" >> /etc/hosts
    fi
fi
echo "Hostname set to $NEW_HOSTNAME"

# 1. Install essential packages
echo "Installing essential packages..."
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl unzip jq awscli software-properties-common gpg

# 2. SSH setup
echo "Configuring SSH authorized_keys..."
if [ -n "${ssh_public_key}" ]; then # ssh_public_key is substituted by templatefile
  mkdir -p /home/ubuntu/.ssh /root/.ssh
  echo "${ssh_public_key}" >> /home/ubuntu/.ssh/authorized_keys
  echo "${ssh_public_key}" >> /root/.ssh/authorized_keys
  sort -u /home/ubuntu/.ssh/authorized_keys -o /home/ubuntu/.ssh/authorized_keys
  sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys
  chmod 700 /home/ubuntu/.ssh /root/.ssh
  chmod 600 /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys
  chown -R ubuntu:ubuntu /home/ubuntu/.ssh
  chown -R root:root /root/.ssh
  echo "SSH public key added to authorized_keys."
else
  echo "No explicit SSH public key provided via template; relying on EC2 instance key pair."
fi

# 3. Kubernetes prerequisites (kernel modules, sysctl)
echo "Configuring Kubernetes prerequisites (kernel modules, sysctl)..."
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

# Disable swap
echo "Disabling swap..."
swapoff -a
sed -i.bak '/swap/s/^/#/' /etc/fstab || echo "No swap entries found in /etc/fstab or sed failed."

# 4. Install CRI-O (Container Runtime)
echo "Installing and configuring CRI-O..."
#CRIO_K8S_MAJOR_MINOR="${K8S_MAJOR_MINOR}" # Use the K8S_MAJOR_MINOR passed from Terraform

# Add CRI-O repository
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https$${":"//pkgs.k8s.io/addons$${":"}cri-o$${":"}stable$${":"}v${CRIO_K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https$${":"//pkgs.k8s.io/addons$${":"}cri-o$${":"}stable$${":"}v${CRIO_K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update -y
apt-get install -y cri-o
echo "CRI-O packages installed."

# Configure CRI-O to use systemd cgroup driver (usually default but good to ensure)
# CRI-O config is typically at /etc/crio/crio.conf or /etc/crio/crio.conf.d/
# We'll ensure the main config uses systemd cgroup.
# Kubeadm usually prefers systemd cgroup driver.
# If /etc/crio/crio.conf exists, check/modify it.
CRIO_CONF="/etc/crio/crio.conf"
if [ -f "$CRIO_CONF" ]; then
    if grep -q "cgroup_manager" "$CRIO_CONF"; then
        sed -i 's/cgroup_manager = "cgroupfs"/cgroup_manager = "systemd"/' "$CRIO_CONF"
    else # Add it under [crio.runtime] if not present
        if grep -q "\[crio.runtime\]" "$CRIO_CONF"; then
            sed -i '/\[crio.runtime\]/a \cgroup_manager = "systemd"' "$CRIO_CONF"
        else # Add the section and the setting
            echo -e "\n[crio.runtime]\ncgroup_manager = \"systemd\"" >> "$CRIO_CONF"
        fi
    fi
else
    echo "Warning: CRI-O main config $CRIO_CONF not found. Assuming default is systemd or will be set by drop-in."
    # Create a drop-in to enforce systemd cgroup manager
    mkdir -p /etc/crio/crio.conf.d
    cat > /etc/crio/crio.conf.d/01-cgroup-manager.conf << EOF
[crio.runtime]
cgroup_manager = "systemd"
EOF
fi
echo "Ensured CRI-O is configured for systemd cgroup manager."

systemctl daemon-reload
systemctl enable --now crio
systemctl restart crio # Restart to apply any config changes
echo "CRI-O started and enabled."

# 5. Install Kubernetes components (kubeadm, kubelet, kubectl)
# K8S_VERSION_FULL, K8S_PACKAGE_VERSION, K8S_MAJOR_MINOR are substituted by templatefile
echo "Installing Kubernetes components (kubeadm, kubelet, kubectl) version ${K8S_VERSION_FULL} (package version ${K8S_PACKAGE_VERSION})..."

# Kubernetes apt repository (already uses K8S_MAJOR_MINOR from templatefile)
mkdir -p -m 755 /etc/apt/keyrings # Redundant if CRI-O section did it, but harmless
curl -fsSL "https$${":"//pkgs.k8s.io/core$${":"}stable$${":"}v${K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https$${":"//pkgs.k8s.io/core$${":"}stable$${":"}v${K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update -y
apt-get install -y kubeadm="${K8S_PACKAGE_VERSION}" kubelet="${K8S_PACKAGE_VERSION}" kubectl="${K8S_PACKAGE_VERSION}"
apt-mark hold kubeadm kubelet kubectl
echo "Kubernetes components installed and held."

# 6. Get instance metadata and prepare kubeadm config values
echo "Fetching instance metadata (using IMDSv2 where possible)..."
IMDS_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s -f)
if [ -n "$IMDS_TOKEN" ]; then
    echo "Acquired IMDSv2 token."
    PRIVATE_IP=$(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" -s -f http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$(curl -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" -s -f http://169.254.169.254/latest/meta-data/public-ipv4)
else
    echo "Warning: Failed to get IMDSv2 token or IMDSv2 is disabled. Attempting IMDSv1."
    PRIVATE_IP=$(curl -s -f http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$(curl -s -f http://169.254.169.254/latest/meta-data/public-ipv4)
fi

if [ -z "$PRIVATE_IP" ]; then
  echo "FATAL: Could not determine Private IP from instance metadata."
  exit 1
fi
echo "Private IP: $PRIVATE_IP"
if [ -n "$PUBLIC_IP" ]; then
  echo "Public IP: $PUBLIC_IP"
else
  echo "Public IP not found or not assigned to this instance."
fi

if [ -z "${POD_CIDR}" ]; then # POD_CIDR is substituted by templatefile
  echo "FATAL: POD_CIDR variable not set in template. Exiting."
  exit 1
fi
echo "Using POD_CIDR: ${POD_CIDR}"
echo "Using bootstrap token prefix: $(echo "${token_formatted}" | cut -d. -f1).*****" # token_formatted is from templatefile

# 7. Construct and Initialize Kubernetes with Kubeadm
echo "Constructing kubeadm configuration..."
mkdir -p /etc/kubernetes/kubeadm
# NEW_HOSTNAME is a bash variable, derived from template variable ${TOKEN_SUFFIX}
# PRIVATE_IP is a bash variable
# Variables like ${token_formatted}, ${K8S_VERSION_FULL}, ${POD_CIDR} are substituted by templatefile
cat > /etc/kubernetes/kubeadm/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${token_formatted}"
  description: "Initial token for worker nodes to join"
  ttl: "24h"
localAPIEndpoint:
  advertiseAddress: $PRIVATE_IP
  bindPort: 6443
nodeRegistration:
  name: $NEW_HOSTNAME
  criSocket: "unix$${":"///run/crio/crio.sock" # Specify CRI-O socket"
  kubeletExtraArgs:
    cloud-provider: "external"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: "v${K8S_VERSION_FULL}" # Use template variable
controlPlaneEndpoint: "$PRIVATE_IP$${":"}6443"
apiServer:
  certSANs:
  - "$PRIVATE_IP"
$( [ -n "$PUBLIC_IP" ] && echo "  - \"$PUBLIC_IP\"" )
  - "$NEW_HOSTNAME"
  - "127.0.0.1"
  - "localhost"
  - "kubernetes"
  - "kubernetes.default"
  - "kubernetes.default.svc"
  - "kubernetes.default.svc.cluster.local"
controllerManager:
  extraArgs:
    cloud-provider: "external"
networking:
  podSubnet: "${POD_CIDR}"
  serviceSubnet: "10.96.0.0/12"
EOF

echo "Kubeadm configuration generated. Contents:"
cat /etc/kubernetes/kubeadm/kubeadm-config.yaml

echo "Running kubeadm init..."
kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs
echo "Kubeadm init completed."

# 8. Setup kubeconfig for root and ubuntu users
echo "Setting up kubeconfig..."
mkdir -p /root/.kube /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown root:root /root/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube
chown -R root:root /root/.kube
echo "Kubeconfig setup complete."

export KUBECONFIG=/etc/kubernetes/admin.conf

# 9. Install CNI (Calico)
echo "Installing Calico CNI (v3.26.4)..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml
echo "Calico CNI installation initiated."

# 9.1. Handle cloud-provider=external taint for system pods
echo "Handling cloud-provider=external taint for critical system pods..."

# Wait a moment for the Calico deployment to be created
sleep 10

# Patch calico-kube-controllers to tolerate the uninitialized cloud provider taint
echo "Patching calico-kube-controllers deployment to tolerate cloud provider uninitialized taint..."
kubectl patch deployment calico-kube-controllers -n kube-system -p '{
  "spec": {
    "template": {
      "spec": {
        "tolerations": [
          {
            "key": "node-role.kubernetes.io/control-plane",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node-role.kubernetes.io/master",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.cloudprovider.kubernetes.io/uninitialized",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.cloudprovider.kubernetes.io/uninitialized",
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ]
      }
    }
  }
}' || echo "Warning: Failed to patch calico-kube-controllers tolerations"

# Patch CoreDNS to tolerate the uninitialized cloud provider taint
echo "Patching CoreDNS deployment to tolerate cloud provider uninitialized taint..."
kubectl patch deployment coredns -n kube-system -p '{
  "spec": {
    "template": {
      "spec": {
        "tolerations": [
          {
            "key": "CriticalAddonsOnly",
            "operator": "Exists"
          },
          {
            "key": "node-role.kubernetes.io/control-plane",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node-role.kubernetes.io/master",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.cloudprovider.kubernetes.io/uninitialized",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.cloudprovider.kubernetes.io/uninitialized",
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ]
      }
    }
  }
}' || echo "Warning: Failed to patch CoreDNS tolerations"

# Create a background script to manage the cloud provider taint
echo "Creating cloud provider taint management script..."
cat > /usr/local/bin/manage-cloud-provider-taint.sh << 'TAINT_SCRIPT_EOF'
#!/bin/bash
# Script to manage cloud provider uninitialized taint

LOGFILE="/var/log/cloud-provider-taint-manager.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "$(date): Starting cloud provider taint management"

export KUBECONFIG=/etc/kubernetes/admin.conf
NODE_NAME=$(hostname)

# Function to check if cloud controller manager is running
check_ccm_running() {
    kubectl get pods -A -l app=aws-cloud-controller-manager 2>/dev/null | grep -q Running
    return $?
}

# Function to check if node has provider ID set
check_provider_id() {
    kubectl get node "$NODE_NAME" -o jsonpath='{.spec.providerID}' | grep -q "aws$${":"}//"
    return $?
}

# Wait up to 10 minutes for CCM to initialize the node
CCM_TIMEOUT=600  # 10 minutes
WAITED=0
SLEEP_INTERVAL=30

echo "$(date): Waiting up to $CCM_TIMEOUT seconds for cloud controller manager to initialize node..."

while [ $WAITED -lt $CCM_TIMEOUT ]; do
    # Check if CCM is running and has set provider ID
    if check_ccm_running && check_provider_id; then
        echo "$(date): Cloud controller manager has initialized the node successfully"
        echo "$(date): Provider ID: $(kubectl get node "$NODE_NAME" -o jsonpath='{.spec.providerID}')"
        exit 0
    fi
    
    # Check if the taint is already gone (CCM removed it)
    if ! kubectl get node "$NODE_NAME" -o json | jq -r '.spec.taints[]? | select(.key == "node.cloudprovider.kubernetes.io/uninitialized") | .key' | grep -q uninitialized; then
        echo "$(date): Cloud provider uninitialized taint has been removed by cloud controller manager"
        exit 0
    fi
    
    sleep $SLEEP_INTERVAL
    WAITED=$((WAITED + SLEEP_INTERVAL))
    echo "$(date): Still waiting for CCM initialization... ($WAITED/$CCM_TIMEOUT seconds)"
done

# If we reach here, CCM didn't initialize the node in time
echo "$(date): WARNING: Cloud controller manager did not initialize the node within $CCM_TIMEOUT seconds"
echo "$(date): Attempting to remove the uninitialized taint to unblock system pods"

# Remove the uninitialized taint to allow system pods to schedule
if kubectl taint node "$NODE_NAME" node.cloudprovider.kubernetes.io/uninitialized$${":"}NoSchedule- 2>/dev/null; then
    echo "$(date): Successfully removed NoSchedule taint"
else
    echo "$(date): NoSchedule taint was not present or already removed"
fi

if kubectl taint node "$NODE_NAME" node.cloudprovider.kubernetes.io/uninitialized$${":"}NoExecute- 2>/dev/null; then
    echo "$(date): Successfully removed NoExecute taint"
else
    echo "$(date): NoExecute taint was not present or already removed"
fi

# Set a basic provider ID if none exists (fallback mechanism)
if ! check_provider_id; then
    echo "$(date): Setting fallback provider ID for node"
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
    
    if [ -n "$INSTANCE_ID" ] && [ -n "$AVAILABILITY_ZONE" ]; then
        PROVIDER_ID="aws$${":"}//$${":"}/$AVAILABILITY_ZONE/$INSTANCE_ID"
        echo "$(date): Setting provider ID to: $PROVIDER_ID"
        kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" || echo "$(date): Failed to set provider ID"
    fi
fi

echo "$(date): Cloud provider taint management completed"
TAINT_SCRIPT_EOF

chmod +x /usr/local/bin/manage-cloud-provider-taint.sh

# Create systemd service for taint management
echo "Creating systemd service for cloud provider taint management..."
cat > /etc/systemd/system/cloud-provider-taint-manager.service << 'SERVICE_EOF'
[Unit]
Description=Cloud Provider Taint Manager
After=kubelet.service
Wants=kubelet.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/manage-cloud-provider-taint.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Enable and start the service
systemctl daemon-reload
systemctl enable cloud-provider-taint-manager.service

# Start the taint manager in the background (don't block initialization)
echo "Starting cloud provider taint manager in background..."
nohup /usr/local/bin/manage-cloud-provider-taint.sh &

# 9.2. Wait for critical system pods to become ready
echo "Waiting for critical system pods to become ready..."

# Function to wait for deployment readiness
wait_for_deployment() {
    local namespace=$1
    local deployment=$2
    local timeout=$${3$${":"}$${"-"}300}  # 5 minutes default
    
    echo "Waiting for deployment $deployment in namespace $namespace to be ready..."
    if kubectl wait --for=condition=available --timeout="$${timeout}s" deployment/"$deployment" -n "$namespace"; then
        echo "✅ Deployment $deployment is ready"
        return 0
    else
        echo "❌ Timeout waiting for deployment $deployment"
        return 1
    fi
}

# Function to wait for daemonset readiness
wait_for_daemonset() {
    local namespace=$1
    local daemonset=$2
    local timeout=$${3$${":"}$${"-"}300}  # 5 minutes default
    
    echo "Waiting for daemonset $daemonset in namespace $namespace to be ready..."
    local end_time=$(($(date +%s) + timeout))
    
    while [ $(date +%s) -lt $end_time ]; do
        local desired=$(kubectl get daemonset "$daemonset" -n "$namespace" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
        local ready=$(kubectl get daemonset "$daemonset" -n "$namespace" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
        
        if [ "$desired" -gt 0 ] && [ "$ready" -eq "$desired" ]; then
            echo "✅ DaemonSet $daemonset is ready ($ready/$desired)"
            return 0
        fi
        
        echo "Still waiting for daemonset $daemonset$${":"} $ready/$desired ready"
        sleep 10
    done
    
    echo "❌ Timeout waiting for daemonset $daemonset"
    return 1
}

# Wait for calico-node (DaemonSet)
wait_for_daemonset kube-system calico-node 300

# Wait for calico-kube-controllers (Deployment)
wait_for_deployment kube-system calico-kube-controllers 300

# Wait for CoreDNS (Deployment)
wait_for_deployment kube-system coredns 300

# Verify all system pods are running
echo "Final verification of system pod status..."
kubectl get pods -n kube-system -o wide
echo ""

# Check for any pods that are still pending and show their events
echo "Checking for any pending pods and their events..."
PENDING_PODS=$(kubectl get pods -A --field-selector=status.phase=Pending -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | head -5)

if [ -n "$PENDING_PODS" ]; then
    echo "Found pending pods, showing events:"
    for pod in $PENDING_PODS; do
        echo "Events for pod $pod$${":"}""
        kubectl describe pod "$pod" -A | grep -A 10 "Events:" || echo "No events found"
        echo "---"
    done
else
    echo "✅ No pending pods found"
fi

# 10. Install AWS Cloud Controller Manager (CCM) - Reminder
echo "---------------------------------------------------------------------"
echo "IMPORTANT: 'cloud-provider: external' was specified in kubeadm config."
echo "You MUST deploy the AWS Cloud Controller Manager manually."
echo "Refer to: https://github.com/kubernetes/cloud-provider-aws"
echo "Select a CCM version compatible with Kubernetes ${K8S_VERSION_FULL}." # Uses template variable
echo "Example (replace vX.Y.Z with a compatible version):"
echo "# kubectl apply -f https://raw.githubusercontent.com/kubernetes/cloud-provider-aws/master/releases/vX.Y.Z/aws-cloud-controller-manager.yaml"
echo "---------------------------------------------------------------------"

# 11. Store a fresh join command in AWS Secrets Manager
echo "Creating and storing new Kubeadm join command in AWS Secrets Manager..."
JOIN_COMMAND=$(kubeadm token create --print-join-command)
if [ -z "$JOIN_COMMAND" ]; then
  echo "FATAL: Failed to create a new join command with kubeadm."
  exit 1
fi

# These secret name variables are passed from Terraform via templatefile
if [ -z "${region}" ] || [ -z "${JOIN_COMMAND_SECRET}" ] || [ -z "${JOIN_COMMAND_LATEST_SECRET}" ]; then
    echo "FATAL: region or secret name variables not set in template. Cannot update Secrets Manager."
    exit 1
fi

echo "Attempting to store join command in Secret: ${JOIN_COMMAND_SECRET}"
if aws secretsmanager put-secret-value --secret-id "${JOIN_COMMAND_SECRET}" --secret-string "$JOIN_COMMAND" --region "${region}"; then
  echo "Successfully stored join command in ${JOIN_COMMAND_SECRET}."
else
  echo "ERROR: Failed to store join command in ${JOIN_COMMAND_SECRET}."
fi

echo "Attempting to store join command in Secret: ${JOIN_COMMAND_LATEST_SECRET}"
if aws secretsmanager put-secret-value --secret-id "${JOIN_COMMAND_LATEST_SECRET}" --secret-string "$JOIN_COMMAND" --region "${region}"; then
  echo "Successfully stored join command in ${JOIN_COMMAND_LATEST_SECRET}."
else
  echo "ERROR: Failed to store join command in ${JOIN_COMMAND_LATEST_SECRET}."
fi

echo "--- Control plane initialization script completed at $(date) ---"