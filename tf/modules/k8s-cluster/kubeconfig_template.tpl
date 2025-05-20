apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: ${base64encode(ca_certificate)}
    server: https://${control_plane_ip}:6443
  name: ${cluster_name}
contexts:
- context:
    cluster: ${cluster_name}
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: ${base64encode(client_certificate)}
    client-key-data: ${base64encode(client_key)} 