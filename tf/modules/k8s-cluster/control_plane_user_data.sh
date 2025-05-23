#!/bin/bash

# Define log file
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a $${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Add error handling
set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"; echo "$(date) - ERROR at line $LINENO: $BASH_COMMAND" >> $${LOGFILE}; exit 1' ERR

# Set non-interactive frontend
export DEBIAN_FRONTEND=noninteractive

# Update package lists
echo "$(date) - Updating package lists"
apt-get update
echo "$(date) - Fixing package manager state"
apt-get install -f -y
dpkg --configure -a

# Install necessary packages first
echo "$(date) - Installing base packages"
apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg jq unzip

# Install AWS CLI early in the process
echo "$(date) - Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
export PATH=$PATH:/usr/local/bin
rm -rf awscliv2.zip aws/

# Verify AWS CLI installation
echo "$(date) - Verifying AWS CLI installation"
aws --version

# Set up SSH access (using dynamic key from Terraform).
echo "$(date) - Setting up SSH access with Terraform-provided key"
mkdir -p /home/ubuntu/.ssh
cat >> /home/ubuntu/.ssh/authorized_keys << 'EOF'
${ssh_public_key}
EOF
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Configure kernel modules for Kubernetes
echo "$(date) - Configuring kernel modules"
cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

# Set up required sysctl parameters
echo "$(date) - Setting sysctl parameters"
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system

# Install containerd
echo "$(date) - Installing containerd"
apt-get update
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# Install Kubernetes packages
echo "$(date) - Installing Kubernetes packages"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y kubeadm=1.28.3-1.1 kubelet=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubeadm kubelet kubectl

# Disable swap
echo "$(date) - Disabling swap"
swapoff -a
sed -i '/swap/d' /etc/fstab

# Retrieve instance metadata with IMDSv2 token method with fallback
echo "$(date) - Retrieving instance metadata"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || echo "")
if [ -n "$${TOKEN}" ]; then
  # Use token for metadata retrieval
  REGION=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/placement/region || echo "")
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/instance-id || echo "")
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
  PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $${TOKEN}" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
else
  # Fallback to direct metadata access
  REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region || echo "")
  INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id || echo "")
  PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
  PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
fi

# Fallback to extracting IP from hostname if metadata service failed
if [ -z "$${PRIVATE_IP}" ]; then
  # Extract from hostname (hostname format is typically ip-10-0-0-99.ec2.internal)
  HOSTNAME=$(hostname -f)
  if [[ $HOSTNAME =~ ip-([0-9]+-[0-9]+-[0-9]+-[0-9]+) ]]; then
    # Convert from ip-10-0-0-99 format to 10.0.0.99
    PRIVATE_IP=$(echo $${BASH_REMATCH[1]} | tr '-' '.')
    echo "$(date) - Extracted private IP $${PRIVATE_IP} from hostname"
  fi
fi

echo "Instance ID: $${INSTANCE_ID}"
echo "Private IP: $${PRIVATE_IP}"
echo "Public IP: $${PUBLIC_IP}"
echo "Hostname: $(hostname -f)"
#
# Set up hostname if not already done
if [ -n "$${PRIVATE_IP}" ]; then
  hostnamectl set-hostname "ip-$${PRIVATE_IP//./-}.ec2.internal"
  echo "127.0.0.1 $(hostname -f)" >> /etc/hosts
fi

# Initialize Kubernetes cluster
echo "$(date) - Initializing Kubernetes control plane with kubeadm"

# Build certSANs array dynamically with only non-empty values
CERT_SANS=""
if [ -n "$${PRIVATE_IP}" ]; then
  CERT_SANS="  - \"$${PRIVATE_IP}\""
fi
CERT_SANS="$${CERT_SANS}\n  - \"127.0.0.1\"\n  - \"localhost\""
if [ -n "$${PUBLIC_IP}" ]; then
  CERT_SANS="$${CERT_SANS}\n  - \"$${PUBLIC_IP}\""
fi

cat > /tmp/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
nodeRegistration:
  kubeletExtraArgs:
    cloud-provider: "external"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
networking:
  podSubnet: "192.168.0.0/16"
apiServer:
  certSANs:
$(echo -e "$${CERT_SANS}")
controllerManager:
  extraArgs:
    cloud-provider: "external"
EOF

# Print the kubeadm config for debugging
echo "$(date) - Kubeadm config contents:"
cat /tmp/kubeadm-config.yaml

kubeadm init --config=/tmp/kubeadm-config.yaml --v=5

# Set up kubeconfig
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
export KUBECONFIG=/etc/kubernetes/admin.conf

# Untaint the control plane if we have a single-node cluster
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Install Calico networking
echo "$(date) - Installing Calico CNI"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml

# Wait for calico pods to be ready
echo "$(date) - Waiting for Calico pods to become ready"
kubectl get pods -n kube-system -l k8s-app=calico-node --no-headers 2>/dev/null || true

# Disable the error trap for this section
set +e

# Wait for Calico pods to be ready
for i in {1..10}; do
  echo "$(date) - Waiting for Calico to be ready (attempt $i/10)"
  
  # Get pods and check for Running status - capture output to variable with no error exit
  PODS=$(kubectl get pods -n kube-system -l k8s-app=calico-node --no-headers 2>/dev/null || echo "")
  echo "$(date) - Current Calico pods: $${PODS}"
  
  if echo "$${PODS}" | grep -q "Running"; then
    echo "$(date) - ✅ Calico is ready!"
    CALICO_READY=true
    break
  else
    echo "$(date) - Calico not ready yet, waiting 15 seconds..."
    sleep 15
  fi
done

# Re-enable error handling
set -e

# Even if Calico isn't fully ready, continue with the script
echo "$(date) - Continuing with setup - Calico initialization will complete in the background"

# Create a service that runs every 10 minutes to ensure there's always a valid token AND updates the secret
echo "$(date) - Setting up kubernetes token creation service"
cat > /etc/systemd/system/k8s-token-creator.service << EOF
[Unit]
Description=Kubernetes Token Creator Service
After=network.target kubelet.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/refresh-join-token.sh
User=root
Group=root
EOF

# Create the refresh token script separately to avoid shell escaping issues
cat > /usr/local/bin/refresh-join-token.sh << 'EOF'
#!/bin/bash
set -e

# Get latest instance metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || echo "")
if [ -n "$TOKEN" ]; then
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
  PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || echo "")
else
  PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 || echo "")
  PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region || echo "")
fi

# Default region if not found
if [ -z "$REGION" ]; then
  REGION="us-east-1"
fi

# Determine which IP to use (prefer public if available)
API_SERVER_IP="${PRIVATE_IP}"
if [ -n "${PUBLIC_IP}" ]; then
  API_SERVER_IP="${PUBLIC_IP}"
fi

# Create new token
TOKEN=$(kubeadm token create --ttl 24h)
echo "Created token: $TOKEN at $(date)" >> /var/log/k8s-token-creator.log

# Get hash
DISCOVERY_HASH=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //')
echo "Discovery hash: $DISCOVERY_HASH" >> /var/log/k8s-token-creator.log

# Generate join command
JOIN_COMMAND="kubeadm join ${API_SERVER_IP}:6443 --token ${TOKEN} --discovery-token-ca-cert-hash sha256:${DISCOVERY_HASH}"
echo "Join command: $JOIN_COMMAND" >> /var/log/k8s-token-creator.log

# Update secrets using variable substitution
aws secretsmanager update-secret --secret-id ##KUBERNETES_JOIN_COMMAND_SECRET## --secret-string "$JOIN_COMMAND" --region ##REGION## || true
aws secretsmanager update-secret --secret-id ##KUBERNETES_JOIN_COMMAND_LATEST_SECRET## --secret-string "$JOIN_COMMAND" --region ##REGION## || true

# Create a new timestamped secret as backup
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
aws secretsmanager create-secret --name "##KUBERNETES_JOIN_COMMAND_SECRET##-$TIMESTAMP" --secret-string "$JOIN_COMMAND" --description "Kubernetes join command for worker nodes" --region ##REGION## || true

exit 0
EOF

chmod +x /usr/local/bin/refresh-join-token.sh

cat > /etc/systemd/system/k8s-token-creator.timer << EOF
[Unit]
Description=Run Kubernetes Token Creator every 10 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer
systemctl daemon-reload
systemctl enable k8s-token-creator.timer
systemctl start k8s-token-creator.timer

# Start the service - if it fails, try running the script directly
if ! systemctl start k8s-token-creator.service; then
  echo "$(date) - Service failed to start, running script directly"
  /usr/local/bin/refresh-join-token.sh
fi

echo "$(date) - Token creator service started"

# Also allow unsafe authentication for 24 hours to help nodes connect initially
echo "$(date) - Setting unsafe authentication for initial node joins"
sed -i '/^\s*authentication:/,/^\s*[^[:space:]]/s/anonymous:\s*false/anonymous: true/' /etc/kubernetes/manifests/kube-apiserver.yaml
echo "$(date) - Will restore secure settings after 24 hours automatically"

# Create a cleanup service to restore security after 24 hours
cat > /etc/systemd/system/k8s-security-restore.service << EOF
[Unit]
Description=Kubernetes Security Restoration Service
After=network.target kubelet.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'sed -i "/^\s*authentication:/,/^\s*[^[:space:]]/s/anonymous:\s*true/anonymous: false/" /etc/kubernetes/manifests/kube-apiserver.yaml; echo "Restored secure authentication settings at \$(date)" >> /var/log/k8s-security.log'
User=root
Group=root
EOF

cat > /etc/systemd/system/k8s-security-restore.timer << EOF
[Unit]
Description=Restore Kubernetes Security after 24 hours

[Timer]
OnBootSec=24h
OnUnitActiveSec=24h

[Install]
WantedBy=timers.target
EOF

# Enable the security restoration timer
systemctl daemon-reload
systemctl enable k8s-security-restore.timer
systemctl start k8s-security-restore.timer
echo "$(date) - Security restoration timer started"

# Generate join command with a long TTL token for reliability (7 days)
STABLE_TOKEN=$(kubeadm token create --ttl 168h)
DISCOVERY_HASH=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //')

# Determine which IP to use for the join command (prefer public IP if available)
API_SERVER_IP="$${PRIVATE_IP}"
if [ -n "$${PUBLIC_IP}" ]; then
  API_SERVER_IP="$${PUBLIC_IP}"
  echo "$(date) - Using public IP for join command: $${PUBLIC_IP}"
else
  echo "$(date) - Using private IP for join command: $${PRIVATE_IP}"
fi

JOIN_COMMAND="kubeadm join $${API_SERVER_IP}:6443 --token $${STABLE_TOKEN} --discovery-token-ca-cert-hash sha256:$${DISCOVERY_HASH}"

echo "$(date) - Generated join command: $${JOIN_COMMAND}"

# Print token info for debugging
echo "$(date) - Token information:"
kubeadm token list

# Also print the hash so it's in the logs for debugging
echo "$(date) - CA cert hash: sha256:$${DISCOVERY_HASH}"

# For workers using the unsafe-skip-ca-verification option
ALT_JOIN_COMMAND="kubeadm join $${API_SERVER_IP}:6443 --token $${STABLE_TOKEN} --discovery-token-unsafe-skip-ca-verification"
echo "$(date) - Alternative join command: $${ALT_JOIN_COMMAND}" 

# Store join command in AWS Secrets Manager - first create with a simple name
MAIN_SECRET="##KUBERNETES_JOIN_COMMAND_SECRET##"
LATEST_SECRET="##KUBERNETES_JOIN_COMMAND_LATEST_SECRET##"
REGION="##REGION##"
TOKEN_FORMATTED="##TOKEN_FORMATTED##"
WORKER_LOGS_BUCKET="##WORKER_LOGS_BUCKET##"
TIMESTAMP="##TIMESTAMP##"

echo "$(date) - Creating Secret Manager secret $${MAIN_SECRET}"
aws secretsmanager describe-secret --secret-id "$${MAIN_SECRET}" --region "$${REGION}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  # Secret exists, update it
  aws secretsmanager update-secret --secret-id "$${MAIN_SECRET}" --secret-string "$${JOIN_COMMAND}" --region "$${REGION}"
else
  # Secret doesn't exist, create it
  aws secretsmanager create-secret --name "$${MAIN_SECRET}" --secret-string "$${JOIN_COMMAND}" --description "Kubernetes join command for worker nodes" --region "$${REGION}"
fi

# Also create a timestamped secret as backup
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
SECRET_NAME="$${MAIN_SECRET}-$${TIMESTAMP}"

echo "$(date) - Creating timestamped Secret Manager secret $${SECRET_NAME}"
aws secretsmanager create-secret --name "$${SECRET_NAME}" --secret-string "$${JOIN_COMMAND}" --description "Kubernetes join command for worker nodes" --region "$${REGION}"

# Also create a fixed-name secret that's easier to find
echo "$(date) - Creating/updating fixed name secret $${LATEST_SECRET}"
aws secretsmanager describe-secret --secret-id "$${LATEST_SECRET}" --region "$${REGION}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  # Secret exists, update it
  aws secretsmanager update-secret --secret-id "$${LATEST_SECRET}" --secret-string "$${JOIN_COMMAND}" --region "$${REGION}"
else
  # Secret doesn't exist, create it
  aws secretsmanager create-secret --name "$${LATEST_SECRET}" --secret-string "$${JOIN_COMMAND}" --description "Latest Kubernetes join command" --region "$${REGION}"
fi

# Verify the secrets are accessible
echo "$(date) - Verifying secrets are accessible"
sleep 5  # Give AWS some time to propagate the secrets

for CHECK_SECRET in "$${MAIN_SECRET}" "$${LATEST_SECRET}" "$${SECRET_NAME}"; do
  echo "$(date) - Verifying secret: $${CHECK_SECRET}"
  STORED_JOIN_COMMAND=$(aws secretsmanager get-secret-value --secret-id "$${CHECK_SECRET}" --region "$${REGION}" --query SecretString --output text)
  if [ -z "$${STORED_JOIN_COMMAND}" ]; then
    echo "$(date) - WARNING: Secret $${CHECK_SECRET} verification failed, will retry once"
    sleep 5
    STORED_JOIN_COMMAND=$(aws secretsmanager get-secret-value --secret-id "$${CHECK_SECRET}" --region "$${REGION}" --query SecretString --output text)
    if [ -z "$${STORED_JOIN_COMMAND}" ]; then
      echo "$(date) - ERROR: Secret $${CHECK_SECRET} still not accessible after retry"
    else
      echo "$(date) - Secret $${CHECK_SECRET} verified and accessible: $${STORED_JOIN_COMMAND}"
    fi
  else
    echo "$(date) - Secret $${CHECK_SECRET} verified and accessible: $${STORED_JOIN_COMMAND}"
  fi
done

# Update admin kubeconfig to use public IP
echo "$(date) - Configuring kubeconfig with public IP"
sed -i "s#server: https://.*:6443#server: https://$${PUBLIC_IP}:6443#" /etc/kubernetes/admin.conf
cp -f /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config

# Secure the Kubernetes certificates
echo "$(date) - Setting secure permissions on Kubernetes certificates"
chmod 600 /etc/kubernetes/admin.conf
chmod -R 600 /etc/kubernetes/pki/

# Verify kubectl works
echo "$(date) - Verifying kubectl works with updated kubeconfig"
kubectl get nodes

# Install and configure AWS SSM agent
echo "$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic

# Verify autoscaling group and SNS
echo "$(date) - Verifying ASG and SNS service integration"
aws autoscaling describe-auto-scaling-groups --region "$${REGION}"
aws sns list-topics --region "$${REGION}"

# Publish a message to SNS to notify of control plane readiness
TOPIC_ARN=$(aws sns list-topics --region "$${REGION}" --query 'Topics[0].TopicArn' --output text)
if [ -n "$${TOPIC_ARN}" ]; then
  echo "$(date) - Sending notification to SNS topic: $${TOPIC_ARN}"
  aws sns publish --topic-arn "$${TOPIC_ARN}" --message "Kubernetes control plane is ready at $${PUBLIC_IP}" --region "$${REGION}"
fi

# Create a summary log file in ubuntu's home directory for easy access
echo "$(date) - Creating log summary file"
cat $${LOGFILE} > /home/ubuntu/init_summary.log
chown ubuntu:ubuntu /home/ubuntu/init_summary.log
chmod 644 /home/ubuntu/init_summary.log
echo "$(date) - Log summary created at /home/ubuntu/init_summary.log"