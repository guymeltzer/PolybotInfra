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
trap 'echo "Error occurred at line $${LINENO}. Command: $${BASH_COMMAND}"; exit 1' ERR

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
KUBERNETES_VERSION="v1.32"
echo "$$(date) - Using Kubernetes version: $KUBERNETES_VERSION"

# Install CRI-O, kubelet, kubeadm, kubectl using modern repository approach
echo "$$(date) - Installing CRI-O and Kubernetes components"
curl -fsSL https://pkgs.k8s.io/core:/stable:/$${KUBERNETES_VERSION}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$${KUBERNETES_VERSION}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/prerelease:/main/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update
apt-get install -y cri-o kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

# Start the CRI-O container runtime and kubelet
echo "$$(date) - Starting CRI-O and kubelet services"
systemctl enable --now crio
systemctl status crio
systemctl enable --now kubelet
systemctl status kubelet

# Disable swap memory
swapoff -a
# Simple crontab addition to disable swap on reboot - fixed syntax error
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
  advertiseAddress: 0.0.0.0
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: stable
apiServer:
  certSANs:
  - $${PUBLIC_IP}
  - $${PRIVATE_IP}
  - $${HOSTNAME}
  - localhost
  - 127.0.0.1
  - "*"
  extraArgs:
    bind-address: 0.0.0.0
    advertise-address: $${PUBLIC_IP}
networking:
  podSubnet: 10.244.0.0/16
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
crictl version || echo "CRI-O not responding properly"
crictl info || echo "CRI-O information not available"

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

# Open up kube-apiserver endpoint in /etc/kubernetes/manifests
echo "$$(date) - Ensuring kube-apiserver is accessible"
MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"
if [ -f "$MANIFEST" ]; then
  sed -i "s/--bind-address=127.0.0.1/--bind-address=0.0.0.0/g" $MANIFEST
  sed -i "s/--advertise-address=$${PRIVATE_IP}/--advertise-address=$${PUBLIC_IP}/g" $MANIFEST
fi

# Install Calico CNI (as per course instructions)
echo "$$(date) - Installing Calico CNI networking..." | tee -a $${LOGFILE}
kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml

# Verify Calico pods are running
for i in {1..15}; do
  echo "$$(date) - Waiting for Calico pods to start (attempt $i)..." | tee -a $${LOGFILE}
  kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods -n kube-system | grep -q calico
  CALICO_RUNNING=$?
  if [ $CALICO_RUNNING -eq 0 ]; then
    echo "$$(date) - Calico pods are starting" | tee -a $${LOGFILE}
    break
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
kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes
kubectl --kubeconfig=/etc/kubernetes/admin.conf cluster-info

# Open firewall rules for Kubernetes API
echo "$$(date) - Configuring firewall rules"
iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Install socat to enable port forwarding
apt-get install -y socat
echo "$$(date) - Configuring port forwarding"
cat <<EOF | tee /etc/systemd/system/kube-apiserver-port-forward.service
[Unit]
Description=Kubernetes API Server Port Forward
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:6443,fork,reuseaddr TCP:127.0.0.1:6443
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kube-apiserver-port-forward.service
systemctl start kube-apiserver-port-forward.service

# Add a simple diagnostic endpoint to check API server status
cat <<EOF > /home/ubuntu/check-api.sh
#!/bin/bash
echo "Testing Kubernetes API server access..."
curl -k https://localhost:6443/healthz
echo ""
echo "API server status: \$?"
netstat -tulpn | grep 6443
echo "Done"
EOF
chmod +x /home/ubuntu/check-api.sh

# Final verification
echo "$$(date) - Final verification of Kubernetes cluster"
kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes -o wide
kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods -A
netstat -tulpn | grep 6443

echo "$$(date) - Control plane initialization completed" | tee -a $${LOGFILE} 