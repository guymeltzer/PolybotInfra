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
apt-get update && apt-get upgrade -y

# Install required packages
apt-get install -y jq unzip ebtables ethtool apt-transport-https 
apt-get install -y ca-certificates curl gnupg lsb-release
apt-get install -y tcpdump net-tools telnet dnsutils iptables-persistent

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install --update
rm -rf awscliv2.zip aws/

# Add AWS CLI to PATH
export PATH=$${PATH}:/usr/local/bin

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab
echo "@reboot /sbin/swapoff -a" | crontab -

# Load necessary modules
modprobe overlay
modprobe br_netfilter

# Configure network settings
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

# Get the public and private IPs
echo "$$(date) - Getting instance network details"
PUBLIC_IP=$$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PRIVATE_IP=$$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
HOSTNAME=$$(curl -s http://169.254.169.254/latest/meta-data/hostname)

echo "Public IP: $${PUBLIC_IP}"
echo "Private IP: $${PRIVATE_IP}"
echo "Hostname: $${HOSTNAME}"

# Add a host entry for API server
echo "$${PRIVATE_IP} $${HOSTNAME}" >> /etc/hosts

# Install containerd
echo "$$(date) - Installing containerd"
apt-get update
apt-get install -y containerd
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd
systemctl status containerd || { echo "Containerd failed to start"; journalctl -xeu containerd; exit 1; }

# Set up Kubernetes repositories
echo "$$(date) - Setting up Kubernetes repositories"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components
echo "$$(date) - Installing Kubernetes components"
apt-get update
apt-get install -y kubelet=1.28.3-1.1 kubeadm=1.28.3-1.1 kubectl=1.28.3-1.1
apt-mark hold kubelet kubeadm kubectl

# Start the kubelet
echo "$$(date) - Starting kubelet service"
systemctl enable --now kubelet
systemctl status kubelet || { echo "Kubelet service failed to start"; journalctl -xeu kubelet; exit 1; }

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
  advertiseAddress: $${PRIVATE_IP}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v1.28.3
apiServer:
  certSANs:
  - $${PUBLIC_IP}
  - $${PRIVATE_IP}
  - $${HOSTNAME}
  - localhost
  - 127.0.0.1
  extraArgs:
    bind-address: 0.0.0.0
networking:
  podSubnet: 192.168.0.0/16
  serviceSubnet: 10.96.0.0/12
controllerManager:
  extraArgs:
    cloud-provider: external
EOF

cat /tmp/kubeadm-config.yaml

# Configure firewall rules
echo "$$(date) - Configuring firewall rules"
iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
iptables -A INPUT -p tcp --dport 179 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Initialize Kubernetes control plane
echo "$$(date) - Starting kubeadm init with config"
kubeadm init --config=/tmp/kubeadm-config.yaml --token ${token} --token-ttl 0 --v=5 || {
  echo "$$(date) - kubeadm init failed, checking errors"
  journalctl -xeu kubelet
  exit 1
}

echo "$$(date) - Kubernetes control plane initialized with kubeadm"

# Setup kubeconfig
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

# Verify initial cluster status
kubectl get nodes -o wide
kubectl get pods -A

# Install Calico CNI
echo "$$(date) - Installing Calico CNI networking..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/calico.yaml

# Wait for Calico pods to be ready
echo "$$(date) - Waiting for Calico pods to start..."
for i in {1..30}; do
  echo "$$(date) - Calico status check attempt $i/30"
  RUNNING_PODS=$(kubectl get pods -n kube-system -l k8s-app=calico-node --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
  
  if [ "$RUNNING_PODS" -gt 0 ]; then
    echo "$$(date) - Calico node pod(s) are running"
    break
  fi
  
  if [ $i -eq 30 ]; then
    echo "$$(date) - Calico pods failed to start in time. Checking pods status:"
    kubectl get pods -n kube-system -o wide
    echo "$$(date) - Checking Calico pod logs:"
    kubectl logs -n kube-system -l k8s-app=calico-node --tail=50
  fi
  
  sleep 10
done

# Check API server is running properly
echo "$$(date) - Checking API server status"
for attempt in {1..10}; do
  if netstat -tlpn | grep -q 6443; then
    echo "$$(date) - API server is listening on port 6443"
    break
  fi
  
  if [ $attempt -eq 10 ]; then
    echo "$$(date) - WARNING: API server is not listening on port 6443"
    echo "$$(date) - Checking API server pod logs:"
    kubectl logs -n kube-system -l component=kube-apiserver --tail=50
  fi
  
  echo "$$(date) - Attempt $attempt: API server not yet listening, waiting..."
  sleep 10
done

# Install AWS SSM agent
echo "$$(date) - Installing and configuring AWS SSM agent"
snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

# Allow control plane to run pods (remove taint)
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Make certificates accessible for Terraform
chmod 644 /etc/kubernetes/pki/ca.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.crt
chmod 644 /etc/kubernetes/pki/apiserver-kubelet-client.key

# Configure kubeconfig with public IP for remote access
echo "$$(date) - Configuring kubeconfig for remote access"
cp /etc/kubernetes/admin.conf /etc/kubernetes/admin.conf.bak
sed -i "s/server: https:\/\/.*:6443/server: https:\/\/$${PUBLIC_IP}:6443/g" /etc/kubernetes/admin.conf

# Store join command in AWS Secrets Manager for workers to use
JOIN_COMMAND=$$(kubeadm token create --print-join-command)
echo "$$(date) - Generated join command: $${JOIN_COMMAND}"
aws secretsmanager put-secret-value \
  --secret-id kubernetes-join-command-${token} \
  --secret-string "$${JOIN_COMMAND}" \
  --region us-east-1 \
  --version-stage AWSCURRENT

# Set up socat port forwarding
echo "$$(date) - Setting up socat port forwarding for API server"
apt-get install -y socat
cat <<EOF > /etc/systemd/system/apiserver-proxy.service
[Unit]
Description=Kubernetes API Server Proxy
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:6443,fork,reuseaddr TCP:127.0.0.1:6443
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable apiserver-proxy.service
systemctl start apiserver-proxy.service
systemctl status apiserver-proxy.service

# Final verification
echo "$$(date) - Final verification of Kubernetes cluster"
kubectl get nodes -o wide
kubectl get pods -A -o wide
echo "$$(date) - Network ports:"
netstat -tulpn | grep 6443

echo "$$(date) - Control plane initialization completed successfully"
echo "$$(date) - You can access the cluster using: kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes" 