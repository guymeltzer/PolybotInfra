apiVersion: v1
kind: Config
clusters:
- name: ${cluster_name}
  cluster:
    server: https://${endpoint}:6443
    insecure-skip-tls-verify: true
users:
- name: kubernetes-admin
  user:
    token: ${token}
contexts:
- name: kubernetes-admin@${cluster_name}
  context:
    cluster: ${cluster_name}
    user: kubernetes-admin
current-context: kubernetes-admin@${cluster_name}
preferences: {} 