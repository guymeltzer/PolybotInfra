#!/bin/bash
# Refactored control plane initialization script with modular approach and robust error handling

# Define log file and set up logging
LOGFILE="/var/log/control-plane-setup.log"
CLOUD_INIT_LOGFILE="/var/log/cloud-init-output.log"
INIT_MARKER="/var/lib/k8s-setup/.init_completed"
mkdir -p $(dirname $${INIT_MARKER})

# Redirect output to multiple logs
exec > >(tee -a $${LOGFILE} $${CLOUD_INIT_LOGFILE}) 2>&1

echo "$(date +"%Y-%m-%d %H:%M:%S") [INFO] Starting Kubernetes control plane initialization"

# Error handling
set -e
trap 'echo "$(date +"%Y-%m-%d %H:%M:%S") [ERROR] Error at line $LINENO: Command \"$BASH_COMMAND\" failed with exit code $?"' ERR

# Function to report progress to CloudWatch
report_progress() {
  local stage="$1"
  local status="$2"
  local message="$3"
  
  # Log locally
  echo "$(date +"%Y-%m-%d %H:%M:%S") [$status] $stage: $message"
  
  # Log to CloudWatch if aws cli is available
  if command -v aws &> /dev/null; then
    local instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
    aws cloudwatch put-metric-data --namespace "KubernetesSetup" \
      --metric-name "ControlPlaneInitProgress" \
      --dimensions "Stage=$stage,InstanceID=$instance_id" \
      --value 1 \
      --region ${region} &>/dev/null || true
  fi
}

# Function to check if a step has already been completed
step_completed() {
  local step="$1"
  [ -f "/var/lib/k8s-setup/.${step}_completed" ]
}

# Function to mark a step as completed
mark_step_completed() {
  local step="$1"
  mkdir -p /var/lib/k8s-setup
  touch "/var/lib/k8s-setup/.${step}_completed"
}

# Function to install essential packages
install_essential_packages() {
  if step_completed "essential_packages"; then
    report_progress "Packages" "INFO" "Essential packages already installed, skipping"
    return 0
  fi
  
  report_progress "Packages" "INFO" "Installing essential packages"
  export DEBIAN_FRONTEND=noninteractive
  
  # Install prerequisites in order of importance
  apt-get update
  apt-get install -y apt-transport-https ca-certificates curl jq unzip
  
  # Install AWS CLI for logging and metadata
  if ! command -v aws &> /dev/null; then
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    ./aws/install
    rm -rf awscliv2.zip aws/
  fi
  
  mark_step_completed "essential_packages"
}

# Function to set up SSH access
setup_ssh_access() {
  if step_completed "ssh_setup"; then
    report_progress "SSH" "INFO" "SSH already configured, skipping"
    return 0
  fi
  
  report_progress "SSH" "INFO" "Setting up SSH access"
  
  # Ensure SSH directory exists with proper permissions
  mkdir -p /home/ubuntu/.ssh
  chmod 700 /home/ubuntu/.ssh
  
  # Add the SSH key
  cat > /home/ubuntu/.ssh/authorized_keys << 'EOF'
${ssh_public_key}
EOF
  
  chmod 600 /home/ubuntu/.ssh/authorized_keys
  chown -R ubuntu:ubuntu /home/ubuntu/.ssh
  
  # Copy to root for emergency access
  mkdir -p /root/.ssh
  cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/
  chmod 700 /root/.ssh
  chmod 600 /root/.ssh/authorized_keys
  
  mark_step_completed "ssh_setup"
}

# Function to configure Kubernetes prerequisites
configure_kubernetes_prereqs() {
  if step_completed "k8s_prereqs"; then
    report_progress "K8sPrereqs" "INFO" "Kubernetes prerequisites already configured, skipping"
    return 0
  fi
  
  report_progress "K8sPrereqs" "INFO" "Configuring Kubernetes prerequisites"
  
  # Configure kernel modules
  cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
  
  modprobe overlay
  modprobe br_netfilter
  
  # Configure sysctl
  cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
  
  sysctl --system
  
  # Disable swap
  swapoff -a
  sed -i '/swap/d' /etc/fstab
  
  mark_step_completed "k8s_prereqs"
}

# Function to install container runtime
install_container_runtime() {
  if step_completed "container_runtime"; then
    report_progress "ContainerRuntime" "INFO" "Container runtime already installed, skipping"
    return 0
  fi
  
  report_progress "ContainerRuntime" "INFO" "Installing containerd runtime"
  
  # Install containerd
  apt-get update
  apt-get install -y containerd
  
  # Configure containerd to use systemd cgroup driver
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
  
  # Restart and enable
  systemctl restart containerd
  systemctl enable containerd
  
  mark_step_completed "container_runtime"
}

# Function to install Kubernetes components
install_kubernetes_components() {
  if step_completed "k8s_components"; then
    report_progress "K8sComponents" "INFO" "Kubernetes components already installed, skipping"
    return 0
  fi
  
  report_progress "K8sComponents" "INFO" "Installing Kubernetes components"
  
  # Add Kubernetes repository
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list
  
  # Install specific versions of Kubernetes components
  apt-get update
  apt-get install -y kubeadm=1.28.3-1.1 kubelet=1.28.3-1.1 kubectl=1.28.3-1.1
  apt-mark hold kubeadm kubelet kubectl
  
  mark_step_completed "k8s_components"
}

# Function to retrieve metadata and set hostname
configure_instance_metadata() {
  if step_completed "instance_metadata"; then
    report_progress "Metadata" "INFO" "Instance metadata already configured, skipping"
    return 0
  fi
  
  report_progress "Metadata" "INFO" "Retrieving instance metadata"
  
  # Use IMDSv2 token method with fallback
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || echo "")
  
  if [ -n "$${TOKEN}" ]; then
    # Use token for metadata retrieval
    REGION=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/placement/region || echo "${region}")
    INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
    PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
    PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  else
    # Fallback to direct metadata access
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region || echo "${region}")
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")
    PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  fi
  
  # Fallback to hostname if metadata service failed
  if [ -z "$${PRIVATE_IP}" ]; then
    HOSTNAME=$(hostname -f)
    if [[ $HOSTNAME =~ ip-([0-9]+-[0-9]+-[0-9]+-[0-9]+) ]]; then
      PRIVATE_IP=$(echo $${BASH_REMATCH[1]} | tr '-' '.')
      echo "Extracted private IP $${PRIVATE_IP} from hostname"
    fi
  fi
  
  # Log the metadata
  echo "Instance metadata:"
  echo "  Instance ID: $${INSTANCE_ID}"
  echo "  Private IP: $${PRIVATE_IP}"
  echo "  Public IP: $${PUBLIC_IP}"
  echo "  Region: $${REGION}"
  
  # Store metadata for future use
  mkdir -p /etc/kubernetes/metadata
  cat > /etc/kubernetes/metadata/instance.env << EOF
INSTANCE_ID=$${INSTANCE_ID}
PRIVATE_IP=$${PRIVATE_IP}
PUBLIC_IP=$${PUBLIC_IP}
REGION=$${REGION}
EOF
  
  # Set the hostname based on private IP
  if [ -n "$${PRIVATE_IP}" ]; then
    hostnamectl set-hostname "ip-$${PRIVATE_IP//./-}.ec2.internal"
    echo "127.0.0.1 $(hostname -f)" >> /etc/hosts
  fi
  
  mark_step_completed "instance_metadata"
}

# Function to initialize Kubernetes control plane
initialize_kubernetes() {
  if step_completed "k8s_init"; then
    report_progress "K8sInit" "INFO" "Kubernetes already initialized, skipping"
    return 0
  fi
  
  report_progress "K8sInit" "INFO" "Initializing Kubernetes control plane"
  
  # Load metadata
  source /etc/kubernetes/metadata/instance.env
  
  # Build certSANs list with all IPs
  CERT_SANS=""
  if [ -n "$${PRIVATE_IP}" ]; then
    CERT_SANS="  - \"$${PRIVATE_IP}\""
  fi
  CERT_SANS="$${CERT_SANS}\n  - \"127.0.0.1\"\n  - \"localhost\""
  if [ -n "$${PUBLIC_IP}" ]; then
    CERT_SANS="$${CERT_SANS}\n  - \"$${PUBLIC_IP}\""
  fi
  
  # Create kubeadm config
  cat > /tmp/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${token_formatted}"
  description: "initial token for worker join"
  ttl: "24h"
nodeRegistration:
  kubeletExtraArgs:
    cloud-provider: external
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
networking:
  podSubnet: "${POD_CIDR}"
apiServer:
  certSANs:
$(echo -e "$${CERT_SANS}")
controllerManager:
  extraArgs:
    cloud-provider: external
EOF
  
  # Initialize the cluster with retries
  MAX_ATTEMPTS=3
  for attempt in $(seq 1 $MAX_ATTEMPTS); do
    report_progress "K8sInit" "INFO" "Attempt $attempt/$MAX_ATTEMPTS to initialize Kubernetes"
    
    if kubeadm init --config=/tmp/kubeadm-config.yaml --v=5 --skip-phases=addon/kube-proxy; then
      report_progress "K8sInit" "INFO" "Kubernetes initialization successful"
      break
    else
      if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
        report_progress "K8sInit" "ERROR" "Failed to initialize Kubernetes after $MAX_ATTEMPTS attempts"
        exit 1
      fi
      report_progress "K8sInit" "WARN" "Initialization failed, resetting and retrying..."
      kubeadm reset -f
      sleep 10
    fi
  done
  
  # Set up kubeconfig for root and ubuntu users
  mkdir -p /root/.kube
  cp -i /etc/kubernetes/admin.conf /root/.kube/config
  mkdir -p /home/ubuntu/.kube
  cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
  chown -R ubuntu:ubuntu /home/ubuntu/.kube
  export KUBECONFIG=/etc/kubernetes/admin.conf
  
  # Create a copy for external use
  mkdir -p /etc/kubernetes/deployment
  cp /etc/kubernetes/admin.conf /etc/kubernetes/deployment/kubeconfig.yaml
  chmod 644 /etc/kubernetes/deployment/kubeconfig.yaml
  
  # Store the join command with token in a file and AWS Secrets Manager
  REGION=${region}
  JOIN_COMMAND=$(kubeadm token create --print-join-command 2>/dev/null || echo "Error generating join command")
  echo "$${JOIN_COMMAND}" > /etc/kubernetes/deployment/join-command.txt
  
  # Store join command in AWS Secrets Manager if AWS CLI is available
  if command -v aws &> /dev/null && [ -n "$${JOIN_COMMAND}" ] && [ "$${JOIN_COMMAND}" != "Error generating join command" ]; then
    SECRET_NAME="${JOIN_COMMAND_SECRET}"
    LATEST_SECRET_NAME="${JOIN_COMMAND_LATEST_SECRET}"
    
    # Put the join command in both secrets
    aws secretsmanager put-secret-value --secret-id "$${SECRET_NAME}" --secret-string "$${JOIN_COMMAND}" --region "$${REGION}" || true
    aws secretsmanager put-secret-value --secret-id "$${LATEST_SECRET_NAME}" --secret-string "$${JOIN_COMMAND}" --region "$${REGION}" || true
    
    report_progress "Secrets" "INFO" "Stored join command in Secrets Manager"
  else
    report_progress "Secrets" "WARN" "Could not store join command in Secrets Manager"
  fi
  
  mark_step_completed "k8s_init"
}

# Function to validate API server readiness
validate_api_server() {
  report_progress "APIServer" "INFO" "Validating API server readiness"
  
  # Wait for the API server to be ready
  MAX_ATTEMPTS=30
  SLEEP_TIME=10
  
  for ((i=1; i<=MAX_ATTEMPTS; i++)); do
    report_progress "APIServer" "INFO" "Attempt $i/$MAX_ATTEMPTS to verify API server"
    
    # Check if API server port is open
    if ss -tlnp | grep -q ":6443"; then
      report_progress "APIServer" "INFO" "API server is listening on port 6443"
      
      # Check if API server health endpoint is responding
      if kubectl get --raw=/healthz &>/dev/null; then
        report_progress "APIServer" "INFO" "API server health check passed"
        
        # Check if control plane pods are running
        RUNNING_PODS=$(kubectl get pods -n kube-system -l tier=control-plane --no-headers 2>/dev/null | grep -c "Running" || echo "0")
        if [ "$RUNNING_PODS" -ge 2 ]; then
          report_progress "APIServer" "INFO" "Control plane pods are running"
          return 0
        fi
      fi
    fi
    
    if [ "$i" -eq "$MAX_ATTEMPTS" ]; then
      report_progress "APIServer" "WARN" "API server validation timed out, but continuing"
      return 1
    fi
    
    sleep $SLEEP_TIME
  done
}

# Function to install CNI (Calico)
install_cni() {
  if step_completed "cni_installed"; then
    report_progress "CNI" "INFO" "CNI already installed, skipping"
    return 0
  fi
  
  report_progress "CNI" "INFO" "Installing Calico CNI"
  
  # Apply Calico manifest
  kubectl apply -f https://docs.projectcalico.org/v3.25/manifests/calico.yaml
  
  # Wait for Calico pods to be ready
  report_progress "CNI" "INFO" "Waiting for Calico pods to be ready"
  kubectl -n kube-system wait --for=condition=ready pod -l k8s-app=calico-node --timeout=300s || true
  
  mark_step_completed "cni_installed"
}

# Function to finalize setup and report success
finalize_setup() {
  report_progress "Finalize" "INFO" "Finalizing control plane setup"
  
  # Create a completion marker
  cat > /etc/kubernetes/control-plane-ready << EOF
Kubernetes control plane initialized successfully at $(date)
Kubeconfig: /etc/kubernetes/admin.conf
Join command: $(cat /etc/kubernetes/deployment/join-command.txt 2>/dev/null || echo "Not available")
EOF
  
  # Signal completion
  touch $${INIT_MARKER}
  
  # Report final status
  report_progress "Complete" "INFO" "Control plane initialization completed successfully"
}

# Main execution flow with timing and progress tracking
main() {
  START_TIME=$(date +%s)
  
  # Run each step and track timing
  time_step() {
    local step_name="$1"
    local step_func="$2"
    
    local step_start=$(date +%s)
    report_progress "$step_name" "START" "Beginning step"
    
    $step_func
    
    local step_end=$(date +%s)
    local step_duration=$((step_end - step_start))
    report_progress "$step_name" "COMPLETE" "Completed in $step_duration seconds"
  }
  
  # Sequential execution of setup steps
  time_step "EssentialPackages" install_essential_packages
  time_step "SSHAccess" setup_ssh_access
  time_step "KubernetesPrereqs" configure_kubernetes_prereqs
  time_step "ContainerRuntime" install_container_runtime
  time_step "KubernetesComponents" install_kubernetes_components
  time_step "InstanceMetadata" configure_instance_metadata
  time_step "KubernetesInit" initialize_kubernetes
  time_step "APIServerValidation" validate_api_server
  time_step "CNIInstallation" install_cni
  time_step "Finalization" finalize_setup
  
  # Calculate and report total time
  END_TIME=$(date +%s)
  TOTAL_TIME=$((END_TIME - START_TIME))
  report_progress "Setup" "COMPLETE" "Total initialization time: $TOTAL_TIME seconds"
}

# Run the main function and catch any errors
main || {
  EXIT_CODE=$?
  report_progress "Setup" "ERROR" "Control plane initialization failed with exit code $EXIT_CODE"
  exit $EXIT_CODE
}