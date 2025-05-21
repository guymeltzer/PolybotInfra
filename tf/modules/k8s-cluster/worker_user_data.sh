#!/bin/bash
# Compact worker initialization script for AWS EC2
LOGFILE="/var/log/k8s-worker-init.log"
exec > >(tee -a ${LOGFILE}) 2>&1
set -e
trap 'echo "ERROR $LINENO: $BASH_COMMAND" >> ${LOGFILE}; exit 1' ERR
export DEBIAN_FRONTEND=noninteractive

# Setup core services
setup_core() {
  apt-get update && apt-get install -y curl unzip jq apt-transport-https ca-certificates gnupg
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip aws/
  
  # Get AWS metadata
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
  PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
  AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
  PROVIDER_ID="aws:///${AZ}/${INSTANCE_ID}"
  export AWS_DEFAULT_REGION="$REGION"
  
  # Setup SSH access
  mkdir -p /home/ubuntu/.ssh
  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp" > /home/ubuntu/.ssh/authorized_keys
  chmod 600 /home/ubuntu/.ssh/authorized_keys && chown -R ubuntu:ubuntu /home/ubuntu/.ssh
  
  # Save important vars to a file that can be sourced later
  cat > /etc/profile.d/k8s-vars.sh << EOF
export REGION="$REGION"
export PRIVATE_IP="$PRIVATE_IP"
export INSTANCE_ID="$INSTANCE_ID"
export AZ="$AZ"
export PROVIDER_ID="$PROVIDER_ID"
EOF
  
  # S3 log upload helper
  upload_logs_to_s3() {
    [ -n "$INSTANCE_ID" ] && aws s3 cp "$LOGFILE" "s3://guy-polybot-logs/worker-init-${INSTANCE_ID}-$1-$(date +%Y%m%d-%H%M%S).log" --region "$REGION" 2>/dev/null || true
  }
  
  # Upload init logs
  upload_logs_to_s3 "INIT"
}

# Install and configure Kubernetes prerequisites
setup_kube() {
  # Setup networking
  cat > /etc/modules-load.d/k8s.conf << EOF
overlay
br_netfilter
EOF
  modprobe overlay && modprobe br_netfilter
  cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
  sysctl --system
  
  # Set hostname
  COUNTER=$(aws ssm get-parameter --name "/k8s/worker-node-counter" --region "$REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "0")
  NEXT_COUNTER=$((COUNTER + 1))
  aws ssm put-parameter --name "/k8s/worker-node-counter" --value "$NEXT_COUNTER" --type String --overwrite --region "$REGION" 2>/dev/null
  NODE_NAME="guy-worker-node-$NEXT_COUNTER"
  hostnamectl set-hostname "$NODE_NAME"
  echo "127.0.0.1 $NODE_NAME" >> /etc/hosts
  
  # Install containerd
  apt-get install -y containerd
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
  systemctl restart containerd && systemctl enable containerd
  
  # Install Kubernetes
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" > /etc/apt/sources.list.d/kubernetes.list
  apt-get update && apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
  apt-mark hold kubelet kubeadm kubectl
  
  # Configure kubelet
  mkdir -p /var/lib/kubelet /etc/kubernetes
  echo "KUBELET_EXTRA_ARGS=--cgroup-driver=systemd --cloud-provider=external --provider-id=${PROVIDER_ID}" > /var/lib/kubelet/kubeadm-flags.env
  
  # Disable swap
  swapoff -a && sed -i '/swap/d' /etc/fstab
  systemctl daemon-reload && systemctl restart kubelet
}

# Join the Kubernetes cluster
join_cluster() {
  # Define secret names
  MAIN_SECRET="##KUBERNETES_JOIN_COMMAND_SECRET##"
  LATEST_SECRET="##KUBERNETES_JOIN_COMMAND_LATEST_SECRET##"
  SECRET_NAMES=("$MAIN_SECRET" "$LATEST_SECRET")
  
  # Try to get join command from secrets manager
  for ((ATTEMPT=1; ATTEMPT<=15; ATTEMPT++)); do
    # Try known secrets
    for SECRET_NAME in "${SECRET_NAMES[@]}"; do
      JOIN_COMMAND=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_NAME" --query SecretString --output text 2>/dev/null || echo "")
      if [[ -n "$JOIN_COMMAND" && "$JOIN_COMMAND" =~ ^kubeadm\ join ]]; then
        if [[ ! "$JOIN_COMMAND" =~ --token ]]; then
          SERVER_ADDR=$(echo "$JOIN_COMMAND" | grep -oP '^kubeadm join \K[^[:space:]]+')
          if [ -n "$SERVER_ADDR" ]; then
            JOIN_COMMAND="kubeadm join $SERVER_ADDR --token $(kubeadm token generate) --discovery-token-unsafe-skip-ca-verification"
          fi
        fi
        break 2
      fi
    done
    
    # Try to find through listing
    if [ $ATTEMPT -gt 10 ]; then
      CONTROL_PLANE_IP=$(aws ec2 describe-instances --region "$REGION" --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)
      if [ -n "$CONTROL_PLANE_IP" ] && [ "$CONTROL_PLANE_IP" != "None" ]; then
        JOIN_COMMAND="kubeadm join ${CONTROL_PLANE_IP}:6443 --token $(kubeadm token generate) --discovery-token-unsafe-skip-ca-verification"
        break
      fi
    fi
    
    sleep 15
  done
  
  # Exit if we can't get a join command
  if [ -z "$JOIN_COMMAND" ]; then
    echo "Failed to retrieve join command" >> "$LOGFILE"
    upload_logs_to_s3 "JOIN_COMMAND_FAILED"
    exit 1
  fi
  
  # Join with retries
  for ((ATTEMPT=1; ATTEMPT<=5; ATTEMPT++)); do
    if eval $JOIN_COMMAND --v=5; then
      systemctl restart kubelet
      # Signal success after joining
      [ -f "/etc/kubernetes/kubelet.conf" ] && kubectl patch node "$NODE_NAME" -p "{\"spec\":{\"providerID\":\"$PROVIDER_ID\"}}" --kubeconfig=/etc/kubernetes/kubelet.conf || true
      aws autoscaling complete-lifecycle-action --lifecycle-hook-name "guy-scale-up-hook" --auto-scaling-group-name "guy-polybot-asg" --lifecycle-action-result "CONTINUE" --instance-id "$INSTANCE_ID" --region "$REGION" 2>/dev/null || true
      aws ec2 create-tags --region "$REGION" --resources "$INSTANCE_ID" --tags Key=node-role.kubernetes.io/worker,Value=true Key=k8s.io/autoscaled-node,Value=true Key=Name,Value="$NODE_NAME" 2>/dev/null || true
      upload_logs_to_s3 "COMPLETE"
      echo "Kubernetes worker node initialization completed successfully"
      return 0
    else
      sleep $((ATTEMPT * 30))
    fi
  done
  
  upload_logs_to_s3 "JOIN_FAILED"
  exit 1
}

# Main execution
setup_core
setup_kube
join_cluster 