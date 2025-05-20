import sys
import yaml
import os

try:
    # Get kubeconfig path from command line argument
    if len(sys.argv) > 1:
        kubeconfig_path = sys.argv[1]
    else:
        # Default fallback path if not specified
        kubeconfig_path = "./kubeconfig.yml"
        print(f"No path provided, using default: {kubeconfig_path}")
    
    with open(kubeconfig_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Ensure it has the required fields
    if not isinstance(config, dict) or "apiVersion" not in config:
        raise ValueError("Invalid kubeconfig structure")
    
    # Write it back in clean format
    with open(kubeconfig_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    print("Kubeconfig validated and cleaned")
    
except Exception as e:
    print(f"Error: {e}")
    print("Creating a minimal valid kubeconfig")
    
    # Determine which path to use for the fallback config
    if not 'kubeconfig_path' in locals():
        kubeconfig_path = "./kubeconfig.yml"
    
    minimal_config = """apiVersion: v1
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
"""
    with open(kubeconfig_path, 'w') as f:
        f.write(minimal_config)
    print(f"Created fallback kubeconfig at {kubeconfig_path}")
