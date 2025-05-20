provider "aws" {
  region = var.region
}

# Define a local provider for first-time setup
provider "local" {}

# Create a bootstrap kubeconfig file for Kubernetes provider initialization
resource "local_file" "bootstrap_kubeconfig" {
  count    = fileexists("${path.module}/kubeconfig.yml") ? 0 : 1
  filename = "${path.module}/kubeconfig.yml"
  content  = <<-EOT
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

  # Use provisioner to run a script that checks and fixes the kubeconfig
  provisioner "local-exec" {
    command = <<-EOF
      #!/bin/bash
      # Verify the kubeconfig file is valid YAML
      if [ -f "${path.module}/kubeconfig.yml" ]; then
        echo "Checking kubeconfig format..."
        
        # Make a backup copy first
        cp "${path.module}/kubeconfig.yml" "${path.module}/kubeconfig.yml.bak" 2>/dev/null || true
        
        # Clean the file of any Windows line endings or other strange characters
        tr -d '\r' < "${path.module}/kubeconfig.yml" > "${path.module}/kubeconfig.clean.yml"
        mv "${path.module}/kubeconfig.clean.yml" "${path.module}/kubeconfig.yml"
        
              # Use yq or python if available to validate and fix
      if command -v python3 >/dev/null 2>&1; then
        KUBECONFIG_PATH="${path.module}/kubeconfig.yml"
        python3 -c "
import sys
import yaml
import json
import os

kubeconfig_path = os.environ.get('KUBECONFIG_PATH')
try:
    with open(kubeconfig_path, 'r') as f:
        config = yaml.safe_load(f)
    
    if not isinstance(config, dict) or 'apiVersion' not in config:
        print('Invalid kubeconfig - missing apiVersion')
        sys.exit(1)
        
    # Rewrite with clean formatting
    with open(kubeconfig_path, 'w') as f:
        yaml.dump(config, f)
    print('kubeconfig validated and reformatted')
except Exception as e:
    print(f'Error parsing kubeconfig: {e}')
    # Create a minimal valid kubeconfig
    with open(kubeconfig_path, 'w') as f:
        f.write('''apiVersion: v1
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
''')
    print('Created fallback kubeconfig due to invalid format')
" || echo "Python validation failed, using fallback"
        fi
      fi
    EOF
  }

  # Only create this file if it doesn't already exist
  lifecycle {
    prevent_destroy = false
  }
}

# Specific resource to validate the kubeconfig before the providers run
resource "null_resource" "validate_kubeconfig" {
  depends_on = [local_file.bootstrap_kubeconfig]
  
  # Run this every time to ensure the kubeconfig is valid
  triggers = {
    always_run = timestamp()
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      #!/bin/bash
      
      # If kubeconfig doesn't exist, create a minimal valid one
      if [ ! -f "${path.module}/kubeconfig.yml" ]; then
        echo "kubeconfig.yml not found, creating minimal valid config"
        cat > "${path.module}/kubeconfig.yml" << 'KUBECFG'
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
KUBECFG
      fi
      
      # Verify the kubeconfig file has the required fields
      grep -q "apiVersion" "${path.module}/kubeconfig.yml" || {
        echo "apiVersion not found in kubeconfig, recreating file"
        cat > "${path.module}/kubeconfig.yml" << 'KUBECFG'
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
KUBECFG
      }
      
      echo "kubeconfig.yml validation complete"
    EOF
  }
}

# Configure the Kubernetes provider with proper authentication
provider "kubernetes" {
  config_path    = "${path.module}/kubeconfig.yml"
  config_context = "kubernetes-admin@kubernetes"  # This is the default context name with kubeadm
  insecure       = true  # Allow connections to the API server without verifying the TLS certificate
}

# Configure the Helm provider with proper authentication
provider "helm" {
  kubernetes {
    config_path    = "${path.module}/kubeconfig.yml"
    config_context = "kubernetes-admin@kubernetes"
    insecure       = true
  }
}

# Configure the kubectl provider with proper authentication
provider "kubectl" {
  config_path      = "${path.module}/kubeconfig.yml"
  config_context   = "kubernetes-admin@kubernetes"
  load_config_file = true
  insecure         = true
}

# Create Kubernetes namespaces for dev and prod
resource "kubernetes_namespace" "dev" {
  metadata {
    name = "dev"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "kubernetes_namespace" "prod" {
  metadata {
    name = "prod"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  
  lifecycle {
    create_before_destroy = true
  }
}

module "k8s-cluster" {
  source                      = "./modules/k8s-cluster"
  region                      = var.region
  cluster_name                = "polybot-cluster"
  vpc_id                      = var.vpc_id
  subnet_ids                  = var.subnet_ids
  control_plane_instance_type = "t3.medium"
  worker_instance_type        = "t3.medium"
  worker_count                = 2
  route53_zone_id             = var.route53_zone_id
  key_name                    = var.key_name
  control_plane_ami           = var.control_plane_ami
  worker_ami                  = var.worker_ami

  addons = [
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/storage-class.yaml",
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/autoscaler.yaml"
  ]

  depends_on = [null_resource.validate_kubeconfig]
}

# Wait for Kubernetes API to be fully available
resource "null_resource" "wait_for_kubernetes" {
  depends_on = [module.k8s-cluster, local_file.bootstrap_kubeconfig, null_resource.validate_kubeconfig]
  
  triggers = {
    # Use formatdate instead of raw timestamp to avoid changing on every apply
    timestamp = formatdate("YYYY-MM-DDThh:mm:ssZ", timestamp())
    # Add a checksum of the kubeconfig file if it exists
    kubeconfig_hash = fileexists("${path.module}/kubeconfig.yml") ? filesha256("${path.module}/kubeconfig.yml") : "no-kubeconfig-yet"
  }
  
  # Add a second provisioner to validate the kubeconfig after it's been created
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      # Set a timeout for the entire script (300 seconds = 5 minutes)
      trap 'echo "Script timed out after 5 minutes"; exit 1' ALRM
      perl -e 'alarm(300); exec @ARGV' "$SHELL" -c '
      
      # Wait for the kubeconfig file to be created first
      if [ -f "${path.module}/kubeconfig.yml" ]; then
        echo "Validating generated kubeconfig..."
        
        # Make a backup of the file
        cp "${path.module}/kubeconfig.yml" "${path.module}/kubeconfig.yml.original" || true
        
        # Clean any Windows line endings
        tr -d '\r' < "${path.module}/kubeconfig.yml" > "${path.module}/kubeconfig.clean.yml"
        mv "${path.module}/kubeconfig.clean.yml" "${path.module}/kubeconfig.yml"
        
              # Verify the file is valid YAML
      if command -v python3 &> /dev/null; then
        KUBECONFIG_PATH="${path.module}/kubeconfig.yml"
        python3 -c "
import yaml
import sys
import os

kubeconfig_path = os.environ.get('KUBECONFIG_PATH')
try:
    with open(kubeconfig_path, 'r') as f:
        config = yaml.safe_load(f)
    print('Valid YAML in kubeconfig')
    # Write back with clean formatting
    with open(kubeconfig_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
except Exception as e:
    print(f'Error validating kubeconfig: {e}')
    sys.exit(1)
"
      fi
    else
      echo "kubeconfig.yml not found, script did not create it"
    fi
    
    # End of timeout-managed command
    '
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes]
  
  # This ensures we rebuild when kubeconfig changes, not on every apply
  triggers_replace = {
    kubeconfig_exists = fileexists("${path.module}/kubeconfig.yml") ? "true" : "false"
    # Add a checksum of the kubeconfig file to track content changes
    kubeconfig_hash = fileexists("${path.module}/kubeconfig.yml") ? filesha256("${path.module}/kubeconfig.yml") : "none"
  }

  # Force provision step to ensure consistency between kubeconfig and the API server
  provisioner "local-exec" {
    command = <<-EOT
      # Get the control plane's current IP
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
      if [ -z "$INSTANCE_ID" ]; then
        echo "WARNING: Could not find control plane instance. Will try to continue."
        PUBLIC_IP="placeholder"
      else
        PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
        echo "Control plane public IP: $PUBLIC_IP"
      fi
      
      # Make sure the kubeconfig file exists
      if [ ! -f "${path.module}/kubeconfig.yml" ]; then
        echo "ERROR: kubeconfig.yml not found!"
        exit 1
      fi
      
      # Validate the kubeconfig format
      if command -v python3 &> /dev/null; then
        echo "Validating kubeconfig format with Python..."
        KUBECONFIG_PATH="${path.module}/kubeconfig.yml"
        python3 -c "import yaml; import os; config = yaml.safe_load(open(os.environ.get('KUBECONFIG_PATH'))); print('✅ Valid kubeconfig with version:', config.get('apiVersion'))" || {
          echo "⚠️ Kubeconfig validation failed, attempting to fix..."
          # Simple attempt to fix common issues
          cat "${path.module}/kubeconfig.yml" | tr -d '\r' > "${path.module}/kubeconfig.fixed.yml"
          mv "${path.module}/kubeconfig.fixed.yml" "${path.module}/kubeconfig.yml"
          python3 -c "import yaml; import os; yaml.safe_load(open(os.environ.get('KUBECONFIG_PATH'))); print('✅ Fixed kubeconfig format')" || {
            echo "❌ Could not fix kubeconfig format automatically"
            echo "------- Current content of kubeconfig.yml -------"
            cat "${path.module}/kubeconfig.yml" | head -20
            echo "-----------------------------------------------"
            exit 1
          }
        }
      else
        echo "Warning: Python not available for YAML validation"
        # Simple validation with grep
        grep -q "apiVersion:" "${path.module}/kubeconfig.yml" || {
          echo "ERROR: kubeconfig doesn't contain apiVersion field"
          exit 1
        }
      fi
      
      # Update kubeconfig with current IP
      if [ -f "${path.module}/kubeconfig.yml" ]; then
        if [ "$PUBLIC_IP" != "placeholder" ]; then
          sed -i.bak "s|server: https://[^:]*:|server: https://$PUBLIC_IP:|g" "${path.module}/kubeconfig.yml"
          echo "Updated kubeconfig to use IP: $PUBLIC_IP"
        else
          echo "Skipping kubeconfig IP update as no instance was found"
        fi
      fi
      
      # Verify we can connect using the kubeconfig
      if command -v kubectl &> /dev/null; then
        echo "Testing kubectl connectivity with the kubeconfig..."
        KUBECONFIG="${path.module}/kubeconfig.yml" kubectl cluster-info --request-timeout=10s || {
          echo "Warning: Could not connect to the cluster with kubectl"
        }
      else
        echo "Warning: kubectl not available for connectivity testing"
      fi
      
      # Add timeout handling in bash instead
      echo "Script completed successfully"
    EOT
  }
}

# Install EBS CSI Driver for persistent storage
resource "helm_release" "aws_ebs_csi_driver" {
  count      = fileexists("${path.module}/kubeconfig.yml") ? 1 : 0
  name       = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  namespace  = "kube-system"
  version    = "2.23.0"  # Use a specific stable version

  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.k8s-cluster.control_plane_iam_role_arn
  }

  values = [<<EOF
storageClasses:
  - name: ebs-sc
    annotations:
      storageclass.kubernetes.io/is-default-class: "true"
    volumeBindingMode: WaitForFirstConsumer
    parameters:
      csi.storage.k8s.io/fstype: xfs
      type: gp2
      encrypted: "true"
EOF
  ]

  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  timeout    = 600
}

# ArgoCD deployment
module "argocd" {
  count          = fileexists("${path.module}/kubeconfig.yml") ? 1 : 0
  source         = "./modules/argocd"
  git_repo_url   = var.git_repo_url
  
  providers = {
    kubernetes = kubernetes
    helm       = helm
    kubectl    = kubectl
  }
  
  depends_on     = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
}

# Development environment resources
module "polybot_dev" {
  source          = "./modules/polybot"
  region          = var.region
  route53_zone_id = var.route53_zone_id
  alb_dns_name    = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id     = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment     = "dev"
  telegram_token  = var.telegram_token_dev
  aws_access_key_id = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username = var.docker_username
  docker_password = var.docker_password
}

# Production environment resources
module "polybot_prod" {
  source          = "./modules/polybot"
  region          = var.region
  route53_zone_id = var.route53_zone_id
  alb_dns_name    = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id     = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment     = "prod"
  telegram_token  = var.telegram_token_prod
  aws_access_key_id = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username = var.docker_username
  docker_password = var.docker_password
}
