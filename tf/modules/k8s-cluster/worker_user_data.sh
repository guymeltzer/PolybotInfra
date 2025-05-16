#!/bin/bash

# Log file for debugging
LOGFILE="/var/log/k8s-node-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes node initialization"

# Trap errors and exit the script with an error message
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; exit 1' ERR

# Wait for metadata and network
until curl -s -m 5 http://169.254.169.254/latest/meta-data/; do
  echo "Waiting for metadata service..."
  sleep 5
done

# Install base packages
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg \
                   software-properties-common jq unzip ebtables ethtool

# Install AWS CLI early
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install --update
rm -rf awscliv2.zip aws/

# Add AWS CLI to PATH
export PATH=$PATH:/usr/local/bin

# Get metadata token with retry
for attempt in {1..5}; do
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  if [ -n "$TOKEN" ]; then
    break
  fi
  echo "Attempt $attempt: Waiting for metadata token..." >> $LOGFILE
  sleep 5
done

if [ -z "$TOKEN" ]; then
  echo "Failed to retrieve metadata token after 5 attempts" >> $LOGFILE
  exit 1
fi

# Get region with retry
for attempt in {1..5}; do
  region=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
  if [ -n "$region" ]; then
    break
  fi
  echo "Attempt $attempt: Waiting for region from metadata..." >> $LOGFILE
  sleep 5
done

if [ -z "$region" ]; then
  echo "Failed to retrieve region after 5 attempts" >> $LOGFILE
  exit 1
fi

# Verify AWS CLI access
aws sts get-caller-identity --region "$region" >> $LOGFILE

# Get other instance metadata
PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
PROVIDER_ID="aws:///${AZ}/${INSTANCE_ID}"

# Set sequential hostname using SSM Parameter Store
SSM_PARAM_NAME="/k8s/worker-node-counter"
COUNTER=$(aws ssm get-parameter --name "$SSM_PARAM_NAME" --region "$region" --query "Parameter.Value" --output text 2>/dev/null || echo "0")
NEXT_COUNTER=$((COUNTER + 1))
aws ssm put-parameter --name "$SSM_PARAM_NAME" --value "$NEXT_COUNTER" --type String --overwrite --region "$region" 2>>$LOGFILE
NODE_NAME="guy-worker-node-$NEXT_COUNTER"
hostnamectl set-hostname "$NODE_NAME"
echo "127.0.0.1 $NODE_NAME" | tee -a /etc/hosts
echo "Set hostname to $NODE_NAME" | tee -a $LOGFILE

# Configure kernel modules
modprobe overlay
modprobe br_netfilter
cat <<EOF | tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

# Configure network settings
cat <<EOF | tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system

# Install containerd runtime
apt-get install -y containerd
mkdir -p /etc/containerd
rm -f /etc/containerd/config.toml
containerd config default | tee /etc/containerd/config.toml >/dev/null
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# Verify containerd socket
echo "Waiting for containerd socket..."
timeout 60 bash -c 'until [ -S /run/containerd/containerd.sock ]; do sleep 1; done'

# Add Kubernetes repository (version-agnostic for 1.32.x)
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components
apt-get update
apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

# Configure kubelet
mkdir -p /var/lib/kubelet /etc/kubernetes
echo "KUBELET_EXTRA_ARGS=--cgroup-driver=systemd" | tee /var/lib/kubelet/kubeadm-flags.env

# Clean previous configurations
kubeadm reset -f
rm -rf /etc/kubernetes/{bootstrap-kubelet.conf,kubelet.conf,pki}
rm -rf /var/lib/kubelet/pki
systemctl restart containerd

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab

# Restart kubelet with default config
systemctl daemon-reload
systemctl restart kubelet

# Fetch join command from Secrets Manager
JOIN_COMMAND=$(aws secretsmanager get-secret-value --region "$region" --secret-id kubernetes-join-command --query SecretString --output text 2>>$LOGFILE)
echo "Join command fetched: $JOIN_COMMAND" >> $LOGFILE

# Join cluster with retry logic and labels
MAX_ATTEMPTS=15
JOIN_SUCCESS=false
RETRY_DELAY=30

for ((ATTEMPT=1; ATTEMPT<=MAX_ATTEMPTS; ATTEMPT++)); do
  echo "Attempt $ATTEMPT/$MAX_ATTEMPTS to join cluster" | tee -a $LOGFILE
  
  $JOIN_COMMAND --v=5 2>&1 | tee -a $LOGFILE
  if [ ${PIPESTATUS[0]} -eq 0 ]; then
    JOIN_SUCCESS=true
    echo "Successfully joined cluster" | tee -a $LOGFILE
    systemctl restart kubelet
    break
  else
    echo "Join failed. Retrying in $RETRY_DELAY seconds..." | tee -a $LOGFILE
    sleep $RETRY_DELAY
    RETRY_DELAY=$((RETRY_DELAY * 2))
  fi
done

if [ "$JOIN_SUCCESS" = false ]; then
  echo "Failed to join cluster after $MAX_ATTEMPTS attempts" | tee -a $LOGFILE
  exit 1
fi

# After successfully joining the cluster
if [ "$JOIN_SUCCESS" = true ]; then
  echo "Successfully joined cluster" | tee -a $LOGFILE
  
  # Set providerID for this node
  echo "Setting providerID to $PROVIDER_ID for node $NODE_NAME" | tee -a $LOGFILE
  echo "Patching node $NODE_NAME with providerID $PROVIDER_ID" | tee -a $LOGFILE
kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" --kubeconfig=/etc/kubernetes/kubelet.conf 2>>$LOGFILE
if [ $? -eq 0 ]; then
  echo "providerID set successfully" | tee -a $LOGFILE
else
  echo "Failed to set providerID" | tee -a $LOGFILE
  exit 1
fi
  echo "providerID set successfully" | tee -a $LOGFILE

  # Signal lifecycle hook completion
  aws autoscaling complete-lifecycle-action \
    --lifecycle-hook-name "guy-scale-up-hook" \
    --auto-scaling-group-name "guy-polybot-asg" \
    --lifecycle-action-result "CONTINUE" \
    --instance-id "$INSTANCE_ID" \
    --region "$region" 2>>$LOGFILE || {
      echo "Failed to signal lifecycle hook" | tee -a $LOGFILE
      aws autoscaling complete-lifecycle-action \
        --lifecycle-hook-name "guy-scale-up-hook" \
        --auto-scaling-group-name "guy-polybot-asg" \
        --lifecycle-action-result "ABANDON" \
        --instance-id "$INSTANCE_ID" \
        --region "$region" 2>>$LOGFILE
      exit 1
    }
fi

# Set EC2 tags
aws ec2 create-tags --region "$region" --resources "$INSTANCE_ID" \
  --tags Key=node-role.kubernetes.io/worker,Value=true Key=k8s.io/autoscaled-node,Value=true Key=Name,Value="$NODE_NAME" 2>>$LOGFILE

echo "$(date) - Node setup complete" | tee -a $LOGFILE