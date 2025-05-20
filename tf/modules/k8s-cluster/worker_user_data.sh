#!/bin/bash
# Script generated with static content

LOGFILE="/var/log/k8s-worker-init.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "$(date) - Starting Kubernetes worker node initialization"

set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> "$LOGFILE"; exit 1' ERR

export DEBIAN_FRONTEND=noninteractive

echo "$(date) - Waiting for metadata service"
until curl -s -m 5 http://169.254.169.254/latest/meta-data/ > /dev/null; do
  echo "Waiting for metadata service..."
  sleep 5
done

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || true)
if [ -z "$TOKEN" ]; then
  echo "$(date) - WARNING: Failed to get IMDSv2 token, trying IMDSv1."
  PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
  INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
  AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
  AWS_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
else
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
  AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
  AWS_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
fi
PROVIDER_ID="aws:///$AZ/$INSTANCE_ID"
export AWS_DEFAULT_REGION=$${AWS_REGION}

echo "$(date) - Updating package lists"
apt-get update
echo "$(date) - Fixing package manager state"
apt-get install -f -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
dpkg --configure -a

echo "$(date) - Installing base packages"
apt-get install -y apt-transport-https ca-certificates curl gnupg software-properties-common jq unzip ebtables ethtool

# Install AWS CLI if not already present or to ensure correct version
if ! command -v aws &> /dev/null; then
    echo "$(date) - Installing AWS CLI"
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    ./aws/install --update
    rm -rf awscliv2.zip aws
fi

echo "$(date) - Configuring kernel modules"
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

echo "$(date) - Setting sysctl parameters"
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system

echo "$(date) - Setting sequential hostname"
SSM_PARAM_NAME="/k8s/${cluster_name}/worker-node-counter" # Use cluster_name for uniqueness
COUNTER=$(aws ssm get-parameter --name "$SSM_PARAM_NAME" --region "$AWS_REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "0")
NEXT_COUNTER=$((COUNTER + 1))
aws ssm put-parameter --name "$SSM_PARAM_NAME" --value "$NEXT_COUNTER" --type String --overwrite --region "$AWS_REGION" 2>>"$LOGFILE"
NODE_NAME="${cluster_name}-worker-$NEXT_COUNTER" # Use cluster_name
hostnamectl set-hostname "$NODE_NAME"
echo "127.0.0.1 $NODE_NAME" | tee -a /etc/hosts
echo "$(date) - Set hostname to $NODE_NAME"

# Install CRI-O
echo "$(date) - Installing CRI-O"
KUBERNETES_VERSION_CRIO_COMPATIBLE="1.28"
curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/stable:/v$${KUBERNETES_VERSION_CRIO_COMPATIBLE}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/stable:/v$${KUBERNETES_VERSION_CRIO_COMPATIBLE}/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

# Install Kubernetes packages (v1.28.3)
echo "$(date) - Installing Kubernetes v1.28.3 packages"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y cri-o kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# Configure kubelet
echo "$(date) - Configuring kubelet"
mkdir -p /var/lib/kubelet /etc/kubernetes
cat > /var/lib/kubelet/kubeadm-flags.env <<EOF
KUBELET_EXTRA_ARGS=--cgroup-driver=systemd --cloud-provider=external --provider-id=$${PROVIDER_ID} --node-ip=$${PRIVATE_IP} --cri-socket=unix:///var/run/crio/crio.sock
EOF
# Kubelet config for CRI-O
cat > /etc/default/kubelet <<EOF
KUBELET_KUBEADM_ARGS="--container-runtime-endpoint=unix:///var/run/crio/crio.sock --image-service-endpoint=unix:///var/run/crio/crio.sock"
EOF


echo "$(date) - Disabling swap"
swapoff -a
sed -i '/swap/d' /etc/fstab
(crontab -l 2>/dev/null || echo "") | { cat; echo "@reboot /sbin/swapoff -a"; } | crontab -

echo "$(date) - Starting and enabling CRI-O and kubelet"
systemctl daemon-reload
systemctl enable --now crio
systemctl enable --now kubelet
systemctl status crio --no-pager || { echo "$(date) - CRI-O failed to start"; journalctl -xeu crio --no-pager; exit 1; }
systemctl status kubelet --no-pager || { echo "$(date) - Kubelet failed to start"; journalctl -xeu kubelet --no-pager; exit 1; }

# Fetch join command from Secrets Manager
JOIN_COMMAND_SECRET_NAME="kubernetes-join-command-${cluster_name}" # Use the same fixed name
echo "$(date) - Fetching join command from Secrets Manager: $${JOIN_COMMAND_SECRET_NAME}"
JOIN_COMMAND=$(aws secretsmanager get-secret-value --region "$AWS_REGION" --secret-id "$${JOIN_COMMAND_SECRET_NAME}" --query SecretString --output text 2>>"$LOGFILE")

if [ -z "$JOIN_COMMAND" ]; then
  echo "$(date) - ERROR: Failed to retrieve join command from Secrets Manager ($${JOIN_COMMAND_SECRET_NAME})" >> "$LOGFILE"
  exit 1
fi
echo "$(date) - Join command fetched successfully"

# Join cluster
echo "$(date) - Attempting to join cluster"
eval $JOIN_COMMAND --cri-socket=unix:///var/run/crio/crio.sock --v=5 || {
    echo "$(date) - ERROR: Failed to join cluster"
    exit 1
}
echo "$(date) - Successfully joined cluster"

echo "$(date) - Worker node setup complete"