apiVersion: v1
kind: Config
clusters:
- name: ${cluster_name}
  cluster:
    server: https://${endpoint}:6443
    certificate-authority-data: ${cluster_ca}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: ${client_cert}
    client-key-data: ${client_key}
contexts:
- name: kubernetes-admin@${cluster_name}
  context:
    cluster: ${cluster_name}
    user: kubernetes-admin
current-context: kubernetes-admin@${cluster_name}
preferences: {} 