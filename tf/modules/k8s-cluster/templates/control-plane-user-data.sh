#!/bin/bash
set -ex

# Log file for debugging
LOGFILE="/var/log/k8s-control-plane-init.log"
exec > >(tee -a $${LOGFILE}) 2>&1
echo "$$(date) - Starting Kubernetes control plane initialization"

# Add SSH key for direct access (bypassing AWS credential expiration issues)
echo "$$(date) - Setting up SSH access"
mkdir -p /home/ubuntu/.ssh
# Use the SSH key specified in the template
cat <<EOF >> /home/ubuntu/.ssh/authorized_keys
${ssh_pub_key}
EOF
# Also add additional public key if needed
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDArp5UgxdxwpyDGbsLpvbgXQev0fG6DQj15P/SVdCGlnxLkYJwYhAoI58xI7V5rpnbO3bDvXzKt/59B0ZVKu1xvvXVUBXGIcHHaWYi/IKO8G+vWgHDXVCGCq4HFG2fJPHwkRNDc5kkOEjthn4s+TlRIJZpvbXRXwHFDJbA/4zE5XuThUwpZROM/MwGEYUjWCnRwYS5bGAglHGnEEA8YGbnCRc9aAeRk8OFEEmSQGp9SSvOEKUiQ3lqMQZP1Qh3WI+GH8D+pHnRDLvQeYxBMwSgFwlILTvp0LMUx9N7hugtFg2FAHnKsD6fRTKwJfTgNLLMYlXqCWVUoJtY+M18YRrZ7niLMZFSSVVWbcJbHXPJ+g3I+n/4nkdxiXQOMYkYcPWCFrzYoZA8/FfHgODZ2Mxx48PR0LXIcj0nYnNY0bJ8+pU9ZPZUilfTQc5Mu5GXXCXe8KwKUxDjcS1JNUXyxTvn+mvMESR/AUFKQNzgXz15J6N0jNfRs5fLeZMNa/YJdkk= gmeltzer@gmeltzer-mbp" >> /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Trap errors and exit the script with an error message
trap 'echo "Error occurred at line $${LINENO}. Command: $${BASH_COMMAND}"; echo "$$(date) - ERROR at line $${LINENO}: $${BASH_COMMAND}" >> $${LOGFILE}; exit 1' ERR

# Update packages
apt-get update

# Install required packages as per course instructions
apt-get install -y jq unzip ebtables ethtool
apt-get install -y software-properties-common apt-transport-https ca-certificates curl gpg
apt-get install -y tcpdump net-tools telnet dnsutils iptables-persistent

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install --update
rm -rf awscliv2.zip aws/

# Add AWS CLI to PATH
export PATH=$${PATH}:/usr/local/bin

# Enable IPv4 packet forwarding. sysctl params required by setup, params persist across reboots
cat <<EOF | tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

# Apply sysctl params without reboot
sysctl --system

# Set Kubernetes version
KUBERNETES_VERSION="v1.32.0"  # Use specific patch version
echo "$$(date) - Using Kubernetes version: $KUBERNETES_VERSION"

# Install CRI-O, kubelet, kubeadm, kubectl using modern repository approach
echo "$$(date) - Installing CRI-O and Kubernetes components"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update
apt-get install -y cri-o kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

# Start the CRI-O container runtime and kubelet
echo "$$(date) - Starting CRI-O and kubelet services"
systemctl enable --now crio
systemctl status crio || { echo "CRI-O service failed to start"; journalctl -xeu crio; exit 1; }
systemctl enable --now kubelet
systemctl status kubelet || { echo "Kubelet service failed to start"; journalctl -xeu kubelet; exit 1; }

# Disable swap memory
swapoff -a
# Simple crontab addition to disable swap on reboot
echo "@reboot /sbin/swapoff -a" | crontab -

# Get the public and private IPs
echo "$$(date) - Getting instance network details"
PUBLIC_IP=$$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PRIVATE_IP=$$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
HOSTNAME=$$(curl -s http://169.254.169.254/latest/meta-data/hostname)

echo "Public IP: $${PUBLIC_IP}"
echo "Private IP: $${PRIVATE_IP}"
echo "Hostname: $${HOSTNAME}"

# Create kubeadm config file
echo "$$(date) - Creating kubeadm configuration"
cat <<EOF > /tmp/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
nodeRegistration:
  name: $${HOSTNAME}
  kubeletExtraArgs:
    cloud-provider: external
localAPIEndpoint:
  advertiseAddress: $${PRIVATE_IP}  # Use private IP
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: $${KUBERNETES_VERSION}
apiServer:
  certSANs:
  - $${PUBLIC_IP}
  - $${PRIVATE_IP}
  - $${HOSTNAME}
  - localhost
  - 127.0.0.1
  extraArgs:
    bind-address: 0.0.0.0
    advertise-address: $${PRIVATE_IP}  # Use private IP
networking:
  podSubnet: 192.168.0.0/16  # Calico default subnet
  serviceSubnet: 10.96.0.0/12
controllerManager:
  extraArgs:
    cloud-provider: external
EOF

cat /tmp/kubeadm-config.yaml

# Enable IP forwarding and allow port 6443 traffic
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
iptables -A INPUT -p tcp --dport 179 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Check that CRI-O is functioning properly
echo "$$(date) - Verifying CRI-O status"
crictl version || { echo "CRI-O not responding properly"; systemctl restart crio; sleep 5; }
crictl info || { echo "CRI-O information not available"; systemctl restart crio; sleep 5; }

# Check network connectivity - dump interfaces and routes
echo "$$(date) - Network configuration dump"
ip a
ip route

# Initialize Kubernetes control plane with the config file
echo "$$(date) - Starting kubeadm init with config"
kubeadm init --config=/tmp/kubeadm-config.yaml --token ${token} --token-ttl 0 --v=5 || {
  echo "$$(date) - kubeadm init failed, checking errors"
  journalctl -xeu kubelet
  exit 1
}

echo "$$(date) - Kubernetes control plane initialized with kubeadm"

# Setup kubeconfig for root user and ubuntu user
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

# Verify initial cluster status
kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes -o wide
kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods -A

# Install Calico CNI
echo "$$(date) - Installing Calico CNI networking..." | tee -a $${LOGFILE}
kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f https://docs.projectcalico.org/v3.25/manifests/calico.yaml

# Verify Calico pods are running
echo "$$(date) - Waiting for Calico pods to start..." | tee -a $${LOGFILE}
for i in {1..30}; do
  echo "$$(date) - Calico status check attempt $i/30" | tee -a $${LOGFILE}
  RUNNING_PODS=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods -n kube-system -l k8s-app=calico-node --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
  
  if [ "$RUNNING_PODS" -gt 0 ]; then
    echo "$$(date) - Calico node pod(s) are running" | tee -a $${LOGFILE}
    break
  fi
  
  if [ $i -eq 30 ]; then
    echo "$$(date) - Calico pods failed to start in time. Checking pods..." | tee -a $${LOGFILE}
    kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods -n kube-system -o wide | tee -a $${LOGFILE}
    echo "$$(date) - Checking Calico pod logs..." | tee -a $${LOGFILE}
    kubectl --kubeconfig=/etc/kubernetes/admin.conf logs -n kube-system -l k8s-app=calico-node --tail=50 | tee -a $${LOGFILE}
  fi
  
  sleep 10
done

# Install AWS SSM agent
echo "$$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl status snap.amazon-ssm-agent.amazon-ssm-agent.service

# Allow control plane to run pods (remove taint)
kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane-

# Make certificates accessible for Terraform
chmod 644 /etc/kubernetes/pki/ca.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.key

# Add a host entry for API server
echo "$${PRIVATE_IP} $${HOSTNAME}" >> /etc/hosts

# Configure kubeconfig with public IP for remote access
echo "$$(date) - Configuring kubeconfig for remote access"
cp /etc/kubernetes/admin.conf /etc/kubernetes/admin.conf.bak
sed -i "s/server: https:\/\/.*:6443/server: https:\/\/$${PUBLIC_IP}:6443/g" /etc/kubernetes/admin.conf
kubectl config set clusters.kubernetes.server https://$${PUBLIC_IP}:6443

# Store join command in AWS Secrets Manager for workers to use
JOIN_COMMAND=$$(kubeadm token create --print-join-command)
echo "$$(date) - Generated join command: $${JOIN_COMMAND}"
aws secretsmanager put-secret-value \
  --secret-id kubernetes-join-command-${token} \
  --secret-string "$${JOIN_COMMAND}" \
  --region us-east-1 \
  --version-stage AWSCURRENT

# Verify the API server is accessible
echo "$$(date) - Verifying API server is accessible"
for i in {1..10}; do
  if kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes; then
    echo "$$(date) - API server is accessible"
    break
  fi
  
  if [ $i -eq 10 ]; then
    echo "$$(date) - API server is not accessible after 10 attempts"
    echo "$$(date) - Checking API server status" | tee -a $${LOGFILE}
    systemctl status kubelet | tee -a $${LOGFILE}
    journalctl -xeu kubelet | tail -n 100 | tee -a $${LOGFILE}
  fi
  
  echo "$$(date) - Attempt $i: API server not yet accessible, waiting..."
  sleep 10
done

# Make sure API server is accessible from outside
echo "$$(date) - Ensuring external API server access"
for i in {1..10}; do
  API_ACCESS=$(curl -k -s https://$${PUBLIC_IP}:6443/healthz)
  if [ "$API_ACCESS" == "ok" ]; then
    echo "$$(date) - API server is accessible from the outside"
    break
  fi
  
  if [ $i -eq 10 ]; then
    echo "$$(date) - WARNING: API server is not accessible from the outside after 10 attempts"
    echo "$$(date) - Setting up socat port forwarding as fallback"
    apt-get install -y socat
    nohup socat TCP-LISTEN:6443,fork,reuseaddr TCP:127.0.0.1:6443 &
  fi
  
  echo "$$(date) - Attempt $i: External API access not yet working, waiting..."
  sleep 10
done

# Final verification
echo "$$(date) - Final verification of Kubernetes cluster"
kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes -o wide
kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods -A
netstat -tulpn | grep 6443

echo "$$(date) - Control plane initialization completed" | tee -a $${LOGFILE} 