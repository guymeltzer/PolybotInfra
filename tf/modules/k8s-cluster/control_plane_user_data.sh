#!/bin/bash
# Control plane initialization script with CRI-O - ENHANCED FOR ROBUSTNESS

# Enhanced error handling and logging
set -euo pipefail # Exit on error, unset variable, or pipe failure
export DEBIAN_FRONTEND=noninteractive

# Enhanced logging setup - log to both file and stdout/stderr
LOGFILE="/var/log/k8s-init.log"
exec > >(tee -a $$LOGFILE) 2>&1

echo "========================================================="
echo "= STARTING CONTROL PLANE INITIALIZATION v2.0         ="
echo "= Date: $$(date)                                        ="
echo "= PID: $$$$                                              ="
echo "========================================================="

# Function for enhanced error handling
error_exit() {
    echo "FATAL ERROR: $$1" >&2
    echo "FATAL ERROR: $$1" >> $$LOGFILE
    echo "Current working directory: $$(pwd)" >> $$LOGFILE
    echo "Environment variables:" >> $$LOGFILE
    env | sort >> $$LOGFILE
    echo "Disk space:" >> $$LOGFILE
    df -h >> $$LOGFILE
    echo "Memory usage:" >> $$LOGFILE
    free -h >> $$LOGFILE
    exit 1
}

# Function to validate critical variables
validate_variables() {
    echo "🔍 Validating template variables..."
    
    if [ -z "${kubeadm_token}" ]; then
        error_exit "kubeadm_token variable not set in template"
    fi
    
    if [ -z "${pod_cidr}" ]; then
        error_exit "pod_cidr variable not set in template"
    fi
    
    if [ -z "${region}" ]; then
        error_exit "region variable not set in template"
    fi
    
    if [ -z "${K8S_VERSION_FULL}" ]; then
        error_exit "K8S_VERSION_FULL variable not set in template"
    fi
    
    if [ -z "${K8S_PACKAGE_VERSION}" ]; then
        error_exit "K8S_PACKAGE_VERSION variable not set in template"
    fi
    
    if [ -z "${K8S_MAJOR_MINOR}" ]; then
        error_exit "K8S_MAJOR_MINOR variable not set in template"
    fi
    
    echo "✅ All critical template variables validated"
    echo "   - kubeadm_token: $$(echo "${kubeadm_token}" | cut -d. -f1).****"
    echo "   - pod_cidr: ${pod_cidr}"
    echo "   - region: ${region}"
    echo "   - K8S version: ${K8S_VERSION_FULL}"
}

# Function to check service status
check_service() {
    local service_name=$$1
    local max_wait=$${2:-60}
    local wait_time=0
    
    echo "🔍 Checking service: $$service_name"
    
    while [ $$wait_time -lt $$max_wait ]; do
        if systemctl is-active --quiet $$service_name; then
            echo "✅ Service $$service_name is active"
            return 0
        fi
        echo "⏳ Waiting for $$service_name to be active... ($$wait_time/$$max_wait)"
        sleep 5
        wait_time=$$((wait_time + 5))
    done
    
    echo "❌ Service $$service_name failed to become active within $$max_wait seconds"
    systemctl status $$service_name || true
    return 1
}

# Validate variables first
validate_variables

# 0. Set Hostname (Good Practice)
echo "🏷️ Setting hostname..."
NEW_HOSTNAME="guy-control-plane-${TOKEN_SUFFIX}"
hostnamectl set-hostname "$$NEW_HOSTNAME"
if grep -q "127.0.0.1 $$NEW_HOSTNAME" /etc/hosts; then
    echo "Hostname $$NEW_HOSTNAME already in /etc/hosts for 127.0.0.1"
else
    if grep -q "127.0.0.1 localhost" /etc/hosts; then
        sed -i "/^127.0.0.1 localhost/ s/$$/ $$NEW_HOSTNAME/" /etc/hosts
    else
        echo "127.0.0.1 localhost $$NEW_HOSTNAME" >> /etc/hosts
    fi
fi
echo "✅ Hostname set to $$NEW_HOSTNAME"

# 1. Install essential packages
echo "📦 Installing essential packages..."
apt-get update -y || error_exit "Failed to update package list"
apt-get install -y apt-transport-https ca-certificates curl unzip jq awscli software-properties-common gpg || error_exit "Failed to install essential packages"
echo "✅ Essential packages installed"

# 2. SSH setup
echo "🔑 Configuring SSH authorized_keys..."
if [ -n "${ssh_public_key}" ]; then
  mkdir -p /home/ubuntu/.ssh /root/.ssh
  echo "${ssh_public_key}" >> /home/ubuntu/.ssh/authorized_keys
  echo "${ssh_public_key}" >> /root/.ssh/authorized_keys
  sort -u /home/ubuntu/.ssh/authorized_keys -o /home/ubuntu/.ssh/authorized_keys
  sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys
  chmod 700 /home/ubuntu/.ssh /root/.ssh
  chmod 600 /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys
  chown -R ubuntu:ubuntu /home/ubuntu/.ssh
  chown -R root:root /root/.ssh
    echo "✅ SSH public key added to authorized_keys"
else
    echo "⚠️ No explicit SSH public key provided via template; relying on EC2 instance key pair"
fi

# 3. Kubernetes prerequisites (kernel modules, sysctl)
echo "⚙️ Configuring Kubernetes prerequisites..."
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF

modprobe overlay || error_exit "Failed to load overlay module"
modprobe br_netfilter || error_exit "Failed to load br_netfilter module"

cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system || error_exit "Failed to apply sysctl settings"

# Disable swap
echo "💾 Disabling swap..."
swapoff -a || error_exit "Failed to disable swap"
sed -i.bak '/swap/s/^/#/' /etc/fstab || echo "No swap entries found in /etc/fstab or sed failed"
echo "✅ Swap disabled"

# 4. Install CRI-O (Container Runtime)
echo "🐳 Installing and configuring CRI-O..."

# Add CRI-O repository with corrected URL format
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/addons/cri-o/stable/v${CRIO_K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg || error_exit "Failed to add CRI-O GPG key"
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons/cri-o/stable/v${CRIO_K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update -y || error_exit "Failed to update package list after adding CRI-O repo"
apt-get install -y cri-o || error_exit "Failed to install CRI-O"
echo "✅ CRI-O packages installed"

# Configure CRI-O to use systemd cgroup driver
CRIO_CONF="/etc/crio/crio.conf"
if [ -f "$$CRIO_CONF" ]; then
    if grep -q "cgroup_manager" "$$CRIO_CONF"; then
        sed -i 's/cgroup_manager = "cgroupfs"/cgroup_manager = "systemd"/' "$$CRIO_CONF"
    else
        if grep -q "\[crio.runtime\]" "$$CRIO_CONF"; then
            sed -i '/\[crio.runtime\]/a \cgroup_manager = "systemd"' "$$CRIO_CONF"
        else
            echo -e "\n[crio.runtime]\ncgroup_manager = \"systemd\"" >> "$$CRIO_CONF"
        fi
    fi
else
    mkdir -p /etc/crio/crio.conf.d
    cat > /etc/crio/crio.conf.d/01-cgroup-manager.conf << EOF
[crio.runtime]
cgroup_manager = "systemd"
EOF
fi
echo "✅ CRI-O configured for systemd cgroup manager"

systemctl daemon-reload
systemctl enable --now crio || error_exit "Failed to enable CRI-O service"
systemctl restart crio || error_exit "Failed to restart CRI-O service"

# Wait for CRI-O to be fully ready
check_service crio 60 || error_exit "CRI-O service failed to start properly"
echo "✅ CRI-O started and enabled"

# 5. Install Kubernetes components
echo "☸️ Installing Kubernetes components version ${K8S_VERSION_FULL}..."

# Add Kubernetes apt repository with corrected URL format
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core/stable/v${K8S_MAJOR_MINOR}/deb/Release.key" | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg || error_exit "Failed to add Kubernetes GPG key"
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core/stable/v${K8S_MAJOR_MINOR}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update -y || error_exit "Failed to update package list after adding Kubernetes repo"
apt-get install -y kubeadm="${K8S_PACKAGE_VERSION}" kubelet="${K8S_PACKAGE_VERSION}" kubectl="${K8S_PACKAGE_VERSION}" || error_exit "Failed to install Kubernetes components"
apt-mark hold kubeadm kubelet kubectl || error_exit "Failed to hold Kubernetes packages"
echo "✅ Kubernetes components installed and held"

# Ensure kubelet is enabled but not started yet (kubeadm will start it)
systemctl enable kubelet

# 6. Get instance metadata and prepare kubeadm config values
echo "📡 Fetching instance metadata..."
IMDS_TOKEN=$$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s -f)
if [ -n "$$IMDS_TOKEN" ]; then
    echo "✅ Acquired IMDSv2 token"
    PRIVATE_IP=$$(curl -H "X-aws-ec2-metadata-token: $$IMDS_TOKEN" -s -f http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$$(curl -H "X-aws-ec2-metadata-token: $$IMDS_TOKEN" -s -f http://169.254.169.254/latest/meta-data/public-ipv4)
else
    echo "⚠️ Failed to get IMDSv2 token, attempting IMDSv1"
    PRIVATE_IP=$$(curl -s -f http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$$(curl -s -f http://169.254.169.254/latest/meta-data/public-ipv4)
fi

if [ -z "$$PRIVATE_IP" ]; then
    error_exit "Could not determine Private IP from instance metadata"
fi

echo "✅ Instance metadata retrieved"
echo "   - Private IP: $$PRIVATE_IP"
echo "   - Public IP: $${PUBLIC_IP:-Not assigned}"
echo "   - Pod CIDR: ${pod_cidr}"

# 7. Construct and Initialize Kubernetes with Kubeadm
echo "📝 Constructing kubeadm configuration..."
mkdir -p /etc/kubernetes/kubeadm

cat > /etc/kubernetes/kubeadm/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${kubeadm_token}"
  description: "Initial token for worker nodes to join"
  ttl: "24h"
localAPIEndpoint:
  advertiseAddress: $$PRIVATE_IP
  bindPort: 6443
nodeRegistration:
  name: $$NEW_HOSTNAME
  criSocket: "unix:///run/crio/crio.sock"
  kubeletExtraArgs:
    cloud-provider: "external"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: "v${K8S_VERSION_FULL}"
controlPlaneEndpoint: "$$PRIVATE_IP:6443"
apiServer:
  certSANs:
  - "$$PRIVATE_IP"
EOF

# Add public IP to certSANs if available
if [ -n "$$PUBLIC_IP" ]; then
    echo "  - \"$$PUBLIC_IP\"" >> /etc/kubernetes/kubeadm/kubeadm-config.yaml
fi

cat >> /etc/kubernetes/kubeadm/kubeadm-config.yaml << EOF
  - "$$NEW_HOSTNAME"
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
  podSubnet: "${pod_cidr}"
  serviceSubnet: "10.96.0.0/12"
EOF

echo "✅ Kubeadm configuration generated:"
echo "----------------------------------------"
cat /etc/kubernetes/kubeadm/kubeadm-config.yaml
echo "----------------------------------------"

# Pre-flight checks before kubeadm init
echo "🔍 Running kubeadm pre-flight checks..."
kubeadm init phase preflight --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml || error_exit "Kubeadm pre-flight checks failed"
echo "✅ Pre-flight checks passed"

# The critical kubeadm init step with enhanced logging
echo "========================================="
echo "🚀 STARTING KUBEADM INIT - CRITICAL STEP"
echo "========================================="
echo "Time: $$(date)"
echo "Config file: /etc/kubernetes/kubeadm/kubeadm-config.yaml"
echo "Log location: $$LOGFILE"

# Run kubeadm init with timeout and detailed error handling
timeout 600 kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5 2>&1 | tee -a /var/log/kubeadm-init.log
KUBEADM_EXIT_CODE=$${PIPESTATUS[0]}

if [ $$KUBEADM_EXIT_CODE -ne 0 ]; then
    echo "❌ KUBEADM INIT FAILED!"
    echo "Exit code: $$KUBEADM_EXIT_CODE"
    echo "Detailed kubeadm init log:"
    cat /var/log/kubeadm-init.log
    echo "Current system status:"
    systemctl status kubelet || true
    systemctl status crio || true
    error_exit "kubeadm init failed with exit code $$KUBEADM_EXIT_CODE"
fi

echo "✅ KUBEADM INIT COMPLETED SUCCESSFULLY!"

# Verify admin.conf was created
if [ ! -f /etc/kubernetes/admin.conf ]; then
    error_exit "admin.conf was not created by kubeadm init"
fi

echo "✅ admin.conf confirmed to exist"

# 8. Setup kubeconfig for root and ubuntu users
echo "🔧 Setting up kubeconfig..."
mkdir -p /root/.kube /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown root:root /root/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube
chown -R root:root /root/.kube
echo "✅ Kubeconfig setup complete"

export KUBECONFIG=/etc/kubernetes/admin.conf

# Verify cluster is accessible
echo "🔍 Verifying cluster access..."
kubectl cluster-info || error_exit "Cannot access cluster after kubeadm init"
kubectl get nodes || error_exit "Cannot get nodes after kubeadm init"
echo "✅ Cluster is accessible"

# 9. Install CNI (Calico)
echo "🌐 Installing Calico CNI (v3.26.4)..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml || error_exit "Failed to install Calico CNI"
echo "✅ Calico CNI installation initiated"

# 9.1. Handle cloud-provider=external taint for system pods
echo "☁️ Handling cloud-provider=external taint for critical system pods..."

# Wait a moment for the Calico deployment to be created
sleep 10

# Patch calico-kube-controllers to tolerate the uninitialized cloud provider taint
echo "🔧 Patching calico-kube-controllers deployment..."
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
}' || echo "⚠️ Warning: Failed to patch calico-kube-controllers tolerations"

# Patch CoreDNS to tolerate the uninitialized cloud provider taint
echo "🔧 Patching CoreDNS deployment..."
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
}' || echo "⚠️ Warning: Failed to patch CoreDNS tolerations"

# Create a background script to manage the cloud provider taint
echo "📋 Creating cloud provider taint management script..."
cat > /usr/local/bin/manage-cloud-provider-taint.sh << 'TAINT_SCRIPT_EOF'
#!/bin/bash
# Script to manage cloud provider uninitialized taint

LOGFILE="/var/log/cloud-provider-taint-manager.log"
exec > >(tee -a "$$LOGFILE") 2>&1

echo "$$(date): Starting cloud provider taint management"

export KUBECONFIG=/etc/kubernetes/admin.conf
NODE_NAME=$$(hostname)

# Function to check if cloud controller manager is running
check_ccm_running() {
    kubectl get pods -A -l app=aws-cloud-controller-manager 2>/dev/null | grep -q Running
    return $$?
}

# Function to check if node has provider ID set
check_provider_id() {
    kubectl get node "$$NODE_NAME" -o jsonpath='{.spec.providerID}' | grep -q "aws://"
    return $$?
}

# Wait up to 10 minutes for CCM to initialize the node
CCM_TIMEOUT=600  # 10 minutes
WAITED=0
SLEEP_INTERVAL=30

echo "$$(date): Waiting up to $$CCM_TIMEOUT seconds for cloud controller manager to initialize node..."

while [ $$WAITED -lt $$CCM_TIMEOUT ]; do
    # Check if CCM is running and has set provider ID
    if check_ccm_running && check_provider_id; then
        echo "$$(date): Cloud controller manager has initialized the node successfully"
        echo "$$(date): Provider ID: $$(kubectl get node "$$NODE_NAME" -o jsonpath='{.spec.providerID}')"
        exit 0
    fi
    
    # Check if the taint is already gone (CCM removed it)
    if ! kubectl get node "$$NODE_NAME" -o json | jq -r '.spec.taints[]? | select(.key == "node.cloudprovider.kubernetes.io/uninitialized") | .key' | grep -q uninitialized; then
        echo "$$(date): Cloud provider uninitialized taint has been removed by cloud controller manager"
        exit 0
    fi
    
    sleep $$SLEEP_INTERVAL
    WAITED=$$((WAITED + SLEEP_INTERVAL))
    echo "$$(date): Still waiting for CCM initialization... ($$WAITED/$$CCM_TIMEOUT seconds)"
done

# If we reach here, CCM didn't initialize the node in time
echo "$$(date): WARNING: Cloud controller manager did not initialize the node within $$CCM_TIMEOUT seconds"
echo "$$(date): Attempting to remove the uninitialized taint to unblock system pods"

# Remove the uninitialized taint to allow system pods to schedule
if kubectl taint node "$$NODE_NAME" node.cloudprovider.kubernetes.io/uninitialized:NoSchedule- 2>/dev/null; then
    echo "$$(date): Successfully removed NoSchedule taint"
else
    echo "$$(date): NoSchedule taint was not present or already removed"
fi

if kubectl taint node "$$NODE_NAME" node.cloudprovider.kubernetes.io/uninitialized:NoExecute- 2>/dev/null; then
    echo "$$(date): Successfully removed NoExecute taint"
else
    echo "$$(date): NoExecute taint was not present or already removed"
fi

# Set a basic provider ID if none exists (fallback mechanism)
if ! check_provider_id; then
    echo "$$(date): Setting fallback provider ID for node"
    INSTANCE_ID=$$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    REGION=$$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    AVAILABILITY_ZONE=$$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
    
    if [ -n "$$INSTANCE_ID" ] && [ -n "$$AVAILABILITY_ZONE" ]; then
        PROVIDER_ID="aws://$$AVAILABILITY_ZONE/$$INSTANCE_ID"
        echo "$$(date): Setting provider ID to: $$PROVIDER_ID"
        kubectl patch node "$$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$$PROVIDER_ID\"}}" || echo "$$(date): Failed to set provider ID"
    fi
fi

echo "$$(date): Cloud provider taint management completed"
TAINT_SCRIPT_EOF

chmod +x /usr/local/bin/manage-cloud-provider-taint.sh

# Create systemd service for taint management
echo "📋 Creating systemd service for cloud provider taint management..."
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
echo "🔄 Starting cloud provider taint manager in background..."
nohup /usr/local/bin/manage-cloud-provider-taint.sh &

# 9.2. Wait for critical system pods to become ready
echo "⏳ Waiting for critical system pods to become ready..."

# Function to wait for deployment readiness
wait_for_deployment() {
    local namespace=$$1
    local deployment=$$2
    local timeout=$${3:-300}
    
    echo "⏳ Waiting for deployment $$deployment in namespace $$namespace to be ready..."
    if kubectl wait --for=condition=available --timeout="$${timeout}s" deployment/"$$deployment" -n "$$namespace"; then
        echo "✅ Deployment $$deployment is ready"
        return 0
    else
        echo "❌ Timeout waiting for deployment $$deployment"
        return 1
    fi
}

# Function to wait for daemonset readiness
wait_for_daemonset() {
    local namespace=$$1
    local daemonset=$$2
    local timeout=$${3:-300}
    
    echo "⏳ Waiting for daemonset $$daemonset in namespace $$namespace to be ready..."
    local end_time=$$(($$$(date +%s) + timeout))
    
    while [ $$$(date +%s) -lt $$end_time ]; do
        local desired=$$(kubectl get daemonset "$$daemonset" -n "$$namespace" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
        local ready=$$(kubectl get daemonset "$$daemonset" -n "$$namespace" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
        
        if [ "$$desired" -gt 0 ] && [ "$$ready" -eq "$$desired" ]; then
            echo "✅ DaemonSet $$daemonset is ready ($$ready/$$desired)"
            return 0
        fi
        
        echo "⏳ Still waiting for daemonset $$daemonset: $$ready/$$desired ready"
        sleep 10
    done
    
    echo "❌ Timeout waiting for daemonset $$daemonset"
    return 1
}

# Wait for calico-node (DaemonSet)
wait_for_daemonset kube-system calico-node 300 || echo "⚠️ Warning: calico-node not ready"

# Wait for calico-kube-controllers (Deployment)
wait_for_deployment kube-system calico-kube-controllers 300 || echo "⚠️ Warning: calico-kube-controllers not ready"

# Wait for CoreDNS (Deployment)
wait_for_deployment kube-system coredns 300 || echo "⚠️ Warning: CoreDNS not ready"

# Verify all system pods are running
echo "📊 Final verification of system pod status..."
kubectl get pods -n kube-system -o wide
echo ""

# Check for any pods that are still pending and show their events
echo "🔍 Checking for any pending pods and their events..."
PENDING_PODS=$$(kubectl get pods -A --field-selector=status.phase=Pending -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | head -5)

if [ -n "$$PENDING_PODS" ]; then
    echo "⚠️ Found pending pods, showing events:"
    for pod in $$PENDING_PODS; do
        echo "Events for pod $$pod:"
        kubectl describe pod "$$pod" -A | grep -A 10 "Events:" || echo "No events found"
        echo "---"
    done
else
    echo "✅ No pending pods found"
fi

# 10. Store a fresh join command in AWS Secrets Manager
echo "🔐 Creating and storing new Kubeadm join command in AWS Secrets Manager..."
JOIN_COMMAND=$$(kubeadm token create --print-join-command)
if [ -z "$$JOIN_COMMAND" ]; then
    error_exit "Failed to create a new join command with kubeadm"
fi

echo "📤 Storing join command in secrets..."
if aws secretsmanager put-secret-value --secret-id "${JOIN_COMMAND_SECRET}" --secret-string "$$JOIN_COMMAND" --region "${region}"; then
    echo "✅ Successfully stored join command in ${JOIN_COMMAND_SECRET}"
else
    echo "❌ ERROR: Failed to store join command in ${JOIN_COMMAND_SECRET}"
fi

if aws secretsmanager put-secret-value --secret-id "${JOIN_COMMAND_LATEST_SECRET}" --secret-string "$$JOIN_COMMAND" --region "${region}"; then
    echo "✅ Successfully stored join command in ${JOIN_COMMAND_LATEST_SECRET}"
else
    echo "❌ ERROR: Failed to store join command in ${JOIN_COMMAND_LATEST_SECRET}"
fi

# Final success verification
echo "========================================================="
echo "= CONTROL PLANE INITIALIZATION COMPLETED SUCCESSFULLY ="
echo "= Date: $$(date)                                        ="
echo "= Duration: $$SECONDS seconds                           ="
echo "========================================================="

# Final cluster verification
echo "🎉 Final cluster status:"
kubectl get nodes -o wide
kubectl get pods --all-namespaces | head -20
echo ""
echo "✅ admin.conf location: /etc/kubernetes/admin.conf"
echo "✅ Log location: $$LOGFILE"
echo "✅ Kubeadm init log: /var/log/kubeadm-init.log"
echo ""
echo "🎯 Control plane initialization completed successfully!"