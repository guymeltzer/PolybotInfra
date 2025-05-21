#!/bin/bash
# Script for Kubernetes control plane initialization
set -e

# Log file for debugging
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a $${LOGFILE}) 2>&1
echo "$(date) - Starting Kubernetes control plane initialization"

# Define AWS region (required for all AWS CLI calls)
AWS_REGION="us-east-1"
export AWS_DEFAULT_REGION=$${AWS_REGION}

# Add SSH key for direct access
mkdir -p /home/ubuntu/.ssh
cat <<EOF >> /home/ubuntu/.ssh/authorized_keys
${ssh_pub_key}
EOF
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp" >> /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Update packages
apt-get update
apt-get install -y jq unzip ebtables ethtool apt-transport-https \
                   ca-certificates curl gnupg lsb-release \
                   tcpdump net-tools telnet dnsutils

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install --update
rm -rf awscliv2.zip aws/

# Verify AWS CLI works with the instance IAM role
echo "$(date) - Verifying AWS CLI and IAM role configuration"
aws sts get-caller-identity || {
  echo "$(date) - ERROR: AWS CLI cannot authenticate using instance profile"
  exit 1
}

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab
(crontab -l 2>/dev/null || echo "") | { cat; echo "@reboot /sbin/swapoff -a"; } | crontab -

# Enable IPv4 packet forwarding
cat <<EOF | tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
sysctl --system

# Load necessary modules
modprobe overlay
modprobe br_netfilter

# Get the instance metadata
echo "$(date) - Retrieving instance metadata"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
if [ -z "$TOKEN" ]; then
  echo "$(date) - Failed to get token for instance metadata service"
  # Fallback to IMDSv1
  PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
  PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
  INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
else
  # Use IMDSv2 with token
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
  PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
  HOSTNAME=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/hostname)
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
fi

# Fallback if metadata service fails
if [ -z "$${PRIVATE_IP}" ]; then
  echo "$(date) - WARNING: Could not get instance metadata from AWS, using fallback methods"
  PRIVATE_IP=$(hostname -I | awk '{print $1}')
  HOSTNAME=$(hostname)
  INSTANCE_ID=$(hostname)
fi

echo "Instance ID: $${INSTANCE_ID}"
echo "Private IP: $${PRIVATE_IP}"
if [ -n "$${PUBLIC_IP}" ]; then
  echo "Public IP: $${PUBLIC_IP}"
else
  echo "No public IP found"
fi
echo "Hostname: $${HOSTNAME}"

# Add host entry
echo "$${PRIVATE_IP} $${HOSTNAME}" >> /etc/hosts

# Install CRI-O container runtime (newer approach like in the guide)
curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

# Set up Kubernetes repositories (v1.28)
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components and CRI-O
apt-get update
apt-get install -y cri-o kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# Start and enable CRI-O and kubelet
systemctl start crio.service
systemctl enable crio.service
systemctl enable --now kubelet

# Verify services are running
echo "$(date) - Verifying CRI-O and kubelet services"
systemctl status crio.service --no-pager
systemctl status kubelet.service --no-pager || {
  echo "$(date) - ERROR: kubelet service failed to start, checking logs"
  journalctl -xeu kubelet --no-pager | tail -n 50
  exit 1
}

# Configure firewall rules (keep this for security)
iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
iptables -A INPUT -p tcp --dport 179 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Verify AWS Secrets Manager access
echo "$(date) - Verifying AWS Secrets Manager access"
aws secretsmanager list-secrets --max-items 1 || {
  echo "$(date) - ERROR: Cannot access AWS Secrets Manager"
  exit 1
}

# Create a simple kubeadm config with AWS integration
cat <<EOF > /tmp/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${token_formatted}"
  description: "default bootstrap token"
  ttl: "0s"
nodeRegistration:
  name: $${HOSTNAME}
  kubeletExtraArgs:
    cloud-provider: external
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v1.28.3
apiServer:
  certSANs:
EOF

# Add certSANs carefully to avoid empty entries
if [ -n "$${PUBLIC_IP}" ]; then
  echo "  - $${PUBLIC_IP}" >> /tmp/kubeadm-config.yaml
fi

cat <<EOF >> /tmp/kubeadm-config.yaml
  - $${PRIVATE_IP}
  - $${HOSTNAME}
  - localhost
  - 127.0.0.1
  extraArgs:
    cloud-provider: external
controllerManager:
  extraArgs:
    cloud-provider: external
networking:
  podSubnet: 192.168.0.0/16
  serviceSubnet: 10.96.0.0/12
EOF

# Initialize the cluster
echo "$(date) - Initializing Kubernetes control plane with kubeadm"
kubeadm init --config=/tmp/kubeadm-config.yaml --v=5 || {
  echo "$(date) - kubeadm init failed, checking errors"
  journalctl -xeu kubelet
  exit 1
}

# Setup kubeconfig
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

# Explicitly set KUBECONFIG for the current shell
export KUBECONFIG=/etc/kubernetes/admin.conf

# Verify kubectl can connect to the API server
echo "$(date) - Verifying kubectl connectivity to API server"
kubectl get nodes || {
  echo "$(date) - ERROR: kubectl cannot connect to API server, checking component status"
  kubectl get componentstatuses
  echo "$(date) - Checking API server pods"
  crictl ps | grep kube-apiserver
  echo "$(date) - Checking API server logs"
  crictl logs $(crictl ps -q --name kube-apiserver) | tail -n 50
  exit 1
}

# Install Calico CNI (like in the guide)
echo "$(date) - Installing Calico CNI"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/calico.yaml

# Wait for the Calico CNI to be ready
echo "$(date) - Waiting for Calico pods to become ready"
for i in {1..10}; do
  if kubectl get pods -n kube-system -l k8s-app=calico-node --field-selector=status.phase=Running | grep -q Running; then
    echo "$(date) - Calico is ready"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "$(date) - WARNING: Timed out waiting for Calico, continuing anyway"
  fi
  echo "$(date) - Waiting for Calico to be ready (attempt $i/10)"
  sleep 15
done

# Allow control plane to run pods (remove taint)
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Create the join command with appropriate IP address
if [ -n "$${PUBLIC_IP}" ]; then
  JOIN_COMMAND=$(kubeadm token create --print-join-command --description "Kubernetes bootstrap token" | sed "s/join .* --/join $${PUBLIC_IP}:6443 --/")
  echo "$(date) - Generated join command with public IP: $${JOIN_COMMAND}"
else
  JOIN_COMMAND=$(kubeadm token create --print-join-command --description "Kubernetes bootstrap token")
  echo "$(date) - Generated join command with private IP: $${JOIN_COMMAND}"
fi

# Verify secret ID exists or can be created before attempting to use it
SECRET_NAME="kubernetes-join-command-${token_formatted}"
echo "$(date) - Checking if Secret Manager secret $SECRET_NAME exists"
if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" 2>/dev/null; then
  # Secret exists, update it
  echo "$(date) - Updating existing Secret Manager secret"
  aws secretsmanager put-secret-value \
    --secret-id "$SECRET_NAME" \
    --secret-string "$${JOIN_COMMAND}" \
    --region $${AWS_REGION} \
    --version-stage AWSCURRENT
else
  # Secret doesn't exist, create it
  echo "$(date) - Creating new Secret Manager secret"
  aws secretsmanager create-secret \
    --name "$SECRET_NAME" \
    --description "Kubernetes join command for worker nodes" \
    --secret-string "$${JOIN_COMMAND}" \
    --region $${AWS_REGION}
fi

# Configure kubeconfig with the appropriate IP for external access
if [ -n "$${PUBLIC_IP}" ]; then
  echo "$(date) - Configuring kubeconfig with public IP"
  for config_file in /etc/kubernetes/admin.conf /root/.kube/config /home/ubuntu/.kube/config; do
    if [ -f "$config_file" ]; then
      sed -i "s/server: https:\/\/[^:]*:/server: https:\/\/$${PUBLIC_IP}:/g" "$config_file"
    fi
  done
else
  echo "$(date) - Configuring kubeconfig with private IP"
  for config_file in /etc/kubernetes/admin.conf /root/.kube/config /home/ubuntu/.kube/config; do
    if [ -f "$config_file" ]; then
      sed -i "s/server: https:\/\/[^:]*:/server: https:\/\/$${PRIVATE_IP}:/g" "$config_file"
    fi
  done
fi

# Set secure permissions on certificates (tighten security)
echo "$(date) - Setting secure permissions on Kubernetes certificates"
chmod 644 /etc/kubernetes/pki/ca.crt
chmod 600 /etc/kubernetes/pki/ca.key
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.crt
chmod 600 /etc/kubernetes/pki/apiserver-kubelet-client.key

# Verify kubectl works with updated kubeconfig
echo "$(date) - Verifying kubectl works with updated kubeconfig"
kubectl get nodes

# Install and configure AWS SSM agent for remote management
echo "$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

# Verify worker ASG and SNS integration
echo "$(date) - Verifying ASG and SNS service integration"
aws autoscaling describe-auto-scaling-groups --max-items 1
aws sns list-topics --max-items 1

# Notify completion via SNS (if available)
SNS_TOPIC_ARN=$(aws sns list-topics --query 'Topics[0].TopicArn' --output text 2>/dev/null || echo "")
if [ -n "$${SNS_TOPIC_ARN}" ] && [[ "$${SNS_TOPIC_ARN}" == arn:aws:sns:* ]]; then
  # Ensure we have the instance ID
  if [ -z "$${INSTANCE_ID}" ]; then
    INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || 
                  curl -s http://169.254.169.254/latest/meta-data/instance-id || 
                  hostname || 
                  echo "unknown-instance")
  fi

  echo "$(date) - Sending notification to SNS topic: $${SNS_TOPIC_ARN}"
  aws sns publish \
    --topic-arn "$${SNS_TOPIC_ARN}" \
    --message "Kubernetes control plane $${INSTANCE_ID} initialization completed at $(date)" \
    --subject "Kubernetes Cluster Initialization Complete"
fi

# Tag instance with completion status for external monitoring
# Ensure we have the instance ID
if [ -z "$${INSTANCE_ID}" ]; then
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || 
                curl -s http://169.254.169.254/latest/meta-data/instance-id || 
                hostname || 
                echo "unknown-instance")
fi

if [ "$${INSTANCE_ID}" != "unknown-instance" ]; then
  aws ec2 create-tags \
    --resources "$${INSTANCE_ID}" \
    --tags "Key=KubernetesInitStatus,Value=Complete" \
    --region $${AWS_REGION}
else
  echo "$(date) - WARNING: Could not determine instance ID for tagging"
fi

echo "$(date) - Kubernetes control plane initialization completed successfully"
echo "$(date) - You can check the cluster status using: kubectl get nodes"

# Also set up KUBECONFIG in bash profile for all users
echo "export KUBECONFIG=/etc/kubernetes/admin.conf" >> /home/ubuntu/.bashrc
echo "export KUBECONFIG=/etc/kubernetes/admin.conf" >> /root/.bashrc

# Set up KUBECONFIG for ssm-user
mkdir -p /var/snap/amazon-ssm-agent/common/
cat << EOF > /var/snap/amazon-ssm-agent/common/.bashrc
export KUBECONFIG=/etc/kubernetes/admin.conf
EOF

# Add explicit permissions to allow non-root users to read the kubeconfig
chmod 644 /etc/kubernetes/admin.conf

# Verify kubectl works with updated kubeconfig
echo "$(date) - Verifying kubectl works with updated kubeconfig"
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl get nodes

# Install AWS CLI early to ensure it's available for all subsequent steps
echo "$(date) - Installing AWS CLI"
apt-get install -y unzip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
export PATH=$PATH:/usr/local/bin
rm -rf awscliv2.zip aws/

# Configure AWS CLI
export AWS_DEFAULT_REGION="${region}"
aws --version

# Set up error logging to S3
upload_logs_to_s3() {
  LOG_STATUS=$1
  echo "$(date) - $LOG_STATUS - Uploading logs to S3"
  
  # Get instance ID if not already set
  if [ -z "$${INSTANCE_ID}" ]; then
    # Try to get instance ID from metadata
    INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || echo "unknown-instance")
    # Add fallback for older IMDSv1
    if [ -z "$${INSTANCE_ID}" ] || [ "$${INSTANCE_ID}" == "unknown-instance" ]; then
      INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id || hostname || echo "unknown-instance")
    fi
  fi
  
  LOG_FILENAME="control-plane-init-$${INSTANCE_ID}-$${LOG_STATUS}-$(date +%Y%m%d-%H%M%S).log"
  aws s3 cp "$${LOGFILE}" "s3://${worker_logs_bucket}/$${LOG_FILENAME}" --region "${region}" || echo "Failed to upload logs to S3"
}

# Set up trap to upload logs on exit
trap 'upload_logs_to_s3 "ERROR_TRAP"; echo "Error occurred at line $${LINENO}. Command: $${BASH_COMMAND}"' ERR

# Upload initial logs
upload_logs_to_s3 "INIT"

# Create kubeadm join command and store in Secrets Manager
echo "$(date) - Creating join command and storing in Secrets Manager"
JOIN_COMMAND=$(kubeadm token create --print-join-command)
if [ -z "$JOIN_COMMAND" ]; then
  echo "$(date) - Failed to create join command, retrying..."
  sleep 10
  JOIN_COMMAND=$(kubeadm token create --print-join-command)
fi

if [ -n "$JOIN_COMMAND" ]; then
  echo "$(date) - Join command created: $JOIN_COMMAND"
  # Create a new secret with timestamp and token parts to make it unique
  SECRET_NAME="${kubernetes_join_command_secret}"
  aws secretsmanager put-secret-value \
    --secret-id "$SECRET_NAME" \
    --secret-string "$JOIN_COMMAND" \
    --region "${region}" || echo "Failed to update join command secret"
  
  echo "$(date) - Join command stored in Secrets Manager"
else
  echo "$(date) - CRITICAL ERROR: Failed to create join command after retry"
fi

# Upload final logs
upload_logs_to_s3 "COMPLETE"