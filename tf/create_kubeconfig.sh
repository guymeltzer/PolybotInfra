#!/bin/bash

echo "Creating a valid kubeconfig.yml file for initial deployment"

cat > kubeconfig.yml << 'EOT'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://placeholder:6443
    insecure-skip-tls-verify: true
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
users:
- name: kubernetes-admin
  user:
    client-certificate-data: cGxhY2Vob2xkZXI=
    client-key-data: cGxhY2Vob2xkZXI=
EOT

echo "kubeconfig.yml created successfully"
echo "Run the following command before terraform apply:"
echo "chmod +x ./create_kubeconfig.sh && ./create_kubeconfig.sh" 