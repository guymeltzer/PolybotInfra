#!/bin/bash
set -ex

# Log file for debugging
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a $${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Add SSH key for direct access
echo "$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
# The public key below is passed in from the Terraform template
cat <<EOF >> /home/ubuntu/.ssh/authorized_keys
${ssh_pub_key}
EOF
# Add your specific fallback/additional public key if needed:
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp" >> /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Trap errors
trap 'echo "Error occurred at line $${LINENO}. Command: $${BASH_COMMAND}"; echo "$(date) - ERROR at line $${LINENO}: $${BASH_COMMAND}" >> $${LOGFILE}; exit 1' ERR

# Set non-interactive mode for package installations
export DEBIAN_FRONTEND=noninteractive

# Update packages
echo "$(date) - Updating package lists and upgrading installed packages"
apt-get update && apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || {
  echo "$(date) - ERROR: Failed to update/upgrade packages"
  exit 1
}

# Install base dependencies
echo "$(date) - Installing base dependencies"
apt-get install -y \
  jq unzip ebtables ethtool apt-transport-https \
  ca-certificates curl gnupg lsb-release \
  software-properties-common \
  tcpdump net-tools telnet dnsutils || {
    echo "$(date) - ERROR: Failed to install base dependencies"
    exit 1
  }

# Pre-configure iptables-persistent to avoid interactive prompts
echo "$(date) - Pre-configuring iptables-persistent"
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
echo netfilter-persistent netfilter-persistent/autosave_v4 boolean true | debconf-set-selections
echo netfilter-persistent netfilter-persistent/autosave_v6 boolean true | debconf-set-selections

apt-get install -y iptables-persistent || {
    echo "$(date) - ERROR: Failed to install iptables-persistent"
    exit 1
}

# Install AWS CLI
echo "$(date) - Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" || { echo "$(date) - ERROR: Failed to download AWS CLI"; exit 1; }
unzip -q awscliv2.zip || { echo "$(date) - ERROR: Failed to unzip AWS CLI"; exit 1; }
./aws/install --update || { echo "$(date) - ERROR: Failed to install AWS CLI"; exit 1; }
rm -rf awscliv2.zip aws/
export PATH=$${PATH}:/usr/local/bin
aws --version || { echo "$(date) - ERROR: AWS CLI not installed correctly"; exit 1; }

# Disable swap
echo "$(date) - Disabling swap"
swapoff -a
sed -i '/swap/d' /etc/fstab
(crontab -l 2>/dev/null || echo "") | { cat; echo "@reboot /sbin/swapoff -a"; } | crontab -

# Load necessary kernel modules
echo "$(date) - Loading kernel modules"
modprobe overlay
modprobe br_netfilter

# Configure sysctl parameters for Kubernetes networking
echo "$(date) - Configuring sysctl parameters"
cat > /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
EOF

cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system

# Get instance metadata
echo "$(date) - Getting instance network details"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || true)
if [ -z "$TOKEN" ]; then # Fallback for IMDSv1 if token request fails
    echo "$(date) - WARNING: Failed to get IMDSv2 token, trying IMDSv1."
    PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "") # public IP might not exist
    HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
    AWS_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
else
    PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
    PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
    HOSTNAME=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/hostname)
    AWS_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
fi
export AWS_DEFAULT_REGION=$${AWS_REGION} # Set for AWS CLI calls

echo "Public IP: $${PUBLIC_IP}"
echo "Private IP: $${PRIVATE_IP}"
echo "Hostname: $${HOSTNAME}"
echo "AWS Region: $${AWS_REGION}"

# Add a host entry for API server
echo "$${PRIVATE_IP} $${HOSTNAME}" >> /etc/hosts

# Install CRI-O (as per latest user-data version)
# Using Kubernetes packages for CRI-O as per instructions: https://kubernetes.io/docs/setup/production-environment/container-runtimes/#cri-o
echo "$(date) - Installing CRI-O"
KUBERNETES_VERSION_CRIO_COMPATIBLE="1.28" # CRI-O versioning might be slightly different, use major.minor
OS="Debian_12" # Or your specific OS, e.g., Ubuntu_24.04 if pkgs.k8s.io has it, otherwise stick to a tested one like Debian
curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/stable:/v$${KUBERNETES_VERSION_CRIO_COMPATIBLE}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/stable:/v$${KUBERNETES_VERSION_CRIO_COMPATIBLE}/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

# Set up Kubernetes repositories (v1.28.3)
echo "$(date) - Setting up Kubernetes v1.28 repositories"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components and CRI-O
echo "$(date) - Installing CRI-O and Kubernetes components v1.28.3"
apt-get update
apt-get install -y cri-o kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1 || {
  echo "$(date) - ERROR: Failed to install CRI-O or Kubernetes components"
  exit 1
}
apt-mark hold kubelet kubeadm kubectl

# Start and enable CRI-O and kubelet
echo "$(date) - Starting and enabling CRI-O and kubelet services"
systemctl daemon-reload
systemctl enable --now crio
systemctl enable --now kubelet
systemctl status crio --no-pager || { echo "$(date) - CRI-O failed to start"; journalctl -xeu crio --no-pager; exit 1; }
systemctl status kubelet --no-pager || { echo "$(date) - Kubelet failed to start"; journalctl -xeu kubelet --no-pager; exit 1; }

# Create kubeadm config file
echo "$(date) - Creating kubeadm configuration"
cat <<EOF > /tmp/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${kubeadm_token}" # This token is passed from Terraform (e.g., local.kubeadm_token)
  description: "kubeadm bootstrap token"
  ttl: "0" # Makes the token valid forever
nodeRegistration:
  name: $${HOSTNAME}
  criSocket: "unix:///var/run/crio/crio.sock" # Specify CRI-O socket
  kubeletExtraArgs:
    cloud-provider: external # Important for AWS integration
    # provider-id: "aws:///$${AWS_REGION}/$${INSTANCE_ID}" # If using aws cloud controller manager
localAPIEndpoint:
  advertiseAddress: $${PRIVATE_IP}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v1.28.3
apiServer:
  certSANs:
  - $${PRIVATE_IP}
  - $${HOSTNAME}
  - localhost
  - 127.0.0.1
$( [ -n "$PUBLIC_IP" ] && echo "  - $PUBLIC_IP" ) # Add public IP only if it exists
  extraArgs:
    cloud-provider: external
    # bind-address: 0.0.0.0 # kubeadm default is to bind to advertiseAddress on HA clusters, otherwise all interfaces
controllerManager:
  extraArgs:
    cloud-provider: external
networking:
  podSubnet: 192.168.0.0/16 # Ensure this matches Calico's default or configuration
  serviceSubnet: 10.96.0.0/12
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd # Explicitly set cgroup driver
# cloudProvider: external # Already set via kubeletExtraArgs in InitConfiguration
EOF

echo "--- Kubeadm Config ---"
cat /tmp/kubeadm-config.yaml
echo "----------------------"

# Initialize Kubernetes control plane
echo "$(date) - Starting kubeadm init with config"
kubeadm init --config=/tmp/kubeadm-config.yaml --v=5 || {
  echo "$(date) - kubeadm init failed, checking errors"
  journalctl -xeu kubelet --no-pager
  exit 1
}
echo "$(date) - Kubernetes control plane initialized with kubeadm"

# Setup kubeconfig for root and ubuntu users
echo "$(date) - Setting up kubeconfig"
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

export KUBECONFIG=/etc/kubernetes/admin.conf # For subsequent kubectl commands in this script

# Allow kubectl for ubuntu user without sudo
echo "export KUBECONFIG=/home/ubuntu/.kube/config" >> /home/ubuntu/.bashrc

# Verify initial cluster status
echo "$(date) - Verifying initial cluster status"
kubectl get nodes -o wide
kubectl get pods -A

# Install Calico CNI (using the version from project instructions)
echo "$(date) - Installing Calico CNI networking (v3.26.1 as per project example)"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/custom-resources.yaml

# Wait for Calico pods to be ready (simplified loop)
echo "$(date) - Waiting for Calico pods to start..."
timeout 300 bash -c 'until kubectl get pods -n calico-system | grep Running; do sleep 10; done' || echo "$(date) - WARN: Timeout waiting for Calico, but continuing."

# Untaint control plane node to allow scheduling general workloads (optional, but common for single control-plane setups)
echo "$(date) - Untainting control plane node"
kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true # Allow failure if already untainted or no such taint

# Check API server is running properly
echo "$(date) - Checking API server status via netstat"
for attempt in {1..10}; do
  if netstat -tlpn | grep -q 6443; then
    echo "$(date) - API server is listening on port 6443"
    break
  fi
  if [ $attempt -eq 10 ]; then
    echo "$(date) - WARNING: API server is not listening on port 6443 after checks."
  fi
  echo "$(date) - Attempt $attempt: API server not yet listening on 6443, waiting..."
  sleep 10
done

# Install AWS SSM agent
echo "$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic
systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service

# Make certificates and kubeconfig accessible for potential remote fetching or debugging
echo "$(date) - Setting permissions for certs and kubeconfig"
chmod 644 /etc/kubernetes/pki/ca.crt
chmod 644 /etc/kubernetes/admin.conf # For non-root users to read if needed

# Configure admin.conf for remote access (using public IP if available)
echo "$(date) - Configuring admin.conf for remote access"
if [ -n "$${PUBLIC_IP}" ]; then
  sed -i "s|server: https://.*:6443|server: https://$${PUBLIC_IP}:6443|g" /etc/kubernetes/admin.conf
  sed -i "s|server: https://.*:6443|server: https://$${PUBLIC_IP}:6443|g" /home/ubuntu/.kube/config
  sed -i "s|server: https://.*:6443|server: https://$${PUBLIC_IP}:6443|g" /root/.kube/config
  echo "$(date) - Kubeconfigs updated to use Public IP: $${PUBLIC_IP}"
else
  echo "$(date) - No Public IP found, Kubeconfigs will use Private IP: $${PRIVATE_IP}"
fi

# Store join command in AWS Secrets Manager
JOIN_COMMAND_SECRET_NAME="kubernetes-join-command-${cluster_name}" # Using fixed name based on cluster_name
echo "$(date) - Generating Kubeadm join command"
JOIN_COMMAND=$(kubeadm token create --print-join-command)
echo "$(date) - Storing join command in Secrets Manager: $${JOIN_COMMAND_SECRET_NAME}"
aws secretsmanager put-secret-value \
  --secret-id "$${JOIN_COMMAND_SECRET_NAME}" \
  --secret-string "$${JOIN_COMMAND}" \
  --region "$${AWS_REGION}" \
  --version-stage AWSCURRENT || \
aws secretsmanager update-secret \
  --secret-id "$${JOIN_COMMAND_SECRET_NAME}" \
  --secret-string "$${JOIN_COMMAND}" \
  --region "$${AWS_REGION}"

# Upload kubeconfig to S3 (this should be done by Terraform ideally, or use a secure method)
echo "$(date) - Uploading admin kubeconfig to S3 bucket: s3://${s3_bucket_name}/kubeconfig/${cluster_name}/admin.config"
aws s3 cp /etc/kubernetes/admin.conf s3://${s3_bucket_name}/kubeconfig/${cluster_name}/admin.config --region "$${AWS_REGION}" || echo "Failed to upload kubeconfig to S3, continuing..."


# Final verification
echo "$(date) - Final verification of Kubernetes cluster"
kubectl get nodes -o wide
kubectl get pods -A -o wide
echo "$(date) - Network ports:"
netstat -tulpn | grep 6443

echo "$(date) - Control plane initialization completed successfully"
echo "$(date) - You can access the cluster using: KUBECONFIG=/home/ubuntu/.kube/config kubectl get nodes"