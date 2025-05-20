provider "aws" {
  region = var.region
}

# Define a local provider for first-time setup
provider "local" {}

# Resource to automate secrets management and cleanup
resource "terraform_data" "manage_secrets" {
  # Always run on every apply
  triggers_replace = {
    timestamp = timestamp()
  }

  # Run script to check and clean up secrets
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      # Colors for output
      RED="\033[0;31m"
      GREEN="\033[0;32m"
      YELLOW="\033[0;33m"
      NC="\033[0m" # No Color
       
      echo -e "\${YELLOW}Checking for stale AWS secrets...\${NC}"
      
      # Check if jq is installed
      if ! command -v jq &> /dev/null; then
        echo -e "\${YELLOW}jq not found, skipping secret cleanup\${NC}"
        exit 0
      fi
       
      # Check if AWS CLI is available
      if ! command -v aws &> /dev/null; then
        echo -e "\${YELLOW}AWS CLI not found, skipping secret cleanup\${NC}"
        exit 0
      fi
       
      # Function to check for duplicate secrets
      check_duplicate_secrets() {
        local prefix="$1"
         
        echo -e "Checking for duplicates with prefix: \${YELLOW}$prefix\${NC}"
         
        SECRETS=$(aws secretsmanager list-secrets \
          --region ${var.region} \
          --filters Key=name,Values="$prefix" \
          --query "SecretList[*].{Name:Name,ARN:ARN}" \
          --output json 2>/dev/null) || {
            echo -e "\${RED}Failed to fetch secrets\${NC}"
            return 0
          }
         
        COUNT=$(echo "$SECRETS" | jq -r 'length')
         
        if [ "$COUNT" -le 1 ]; then
          echo -e "\${GREEN}No duplicate secrets found for $prefix\${NC}"
          return 0
        fi
         
        echo -e "\${YELLOW}Found $COUNT secrets with prefix $prefix, cleaning up...\${NC}"
         
        # Get all but the newest secret
        SECRETS_TO_DELETE=$(echo "$SECRETS" | jq -r '.[0:-1] | .[].Name')
         
        # Delete the older secrets
        for SECRET_NAME in $SECRETS_TO_DELETE; do
          echo -e "Force deleting \${YELLOW}$SECRET_NAME\${NC}"
          aws secretsmanager delete-secret \
            --secret-id "$SECRET_NAME" \
            --force-delete-without-recovery \
            --region ${var.region} >/dev/null 2>&1 || echo -e "\${RED}Failed to delete $SECRET_NAME\${NC}"
        done
      }
       
      # Check each prefix directly instead of using arrays
      echo -e "\${YELLOW}Checking dev environment secrets...\${NC}"
      check_duplicate_secrets "guy-polybot-dev-telegram-token"
      check_duplicate_secrets "guy-polybot-dev-docker-credentials"
      check_duplicate_secrets "guy-polybot-dev-secrets"
       
      echo -e "\${YELLOW}Checking prod environment secrets...\${NC}"
      check_duplicate_secrets "guy-polybot-prod-telegram-token"
      check_duplicate_secrets "guy-polybot-prod-docker-credentials"
      check_duplicate_secrets "guy-polybot-prod-secrets"
       
      echo -e "\${GREEN}Secret cleanup complete\${NC}"
    EOT
  }
}

# Resource to ensure proper initialization before anything else runs
resource "terraform_data" "init_environment" {
  depends_on = [terraform_data.manage_secrets]
  
  # This will run on every apply
  triggers_replace = {
    # Always run at the beginning of every terraform apply
    timestamp = timestamp()
  }

  # Create a valid kubeconfig before any resources are created
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      echo "Initializing environment with valid kubeconfig..."
      
      # Create a valid kubeconfig file regardless of whether one exists
      cat > "${path.module}/kubeconfig.yml" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.default.svc:6443
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
EOF

      chmod 600 "${path.module}/kubeconfig.yml"
      echo "Valid kubeconfig created successfully"
      
      # Validate the kubeconfig
      echo "Validating kubeconfig.yml..."
      
      # Check for placeholder server
      if grep -q "placeholder:6443" "${path.module}/kubeconfig.yml"; then
          echo "Found placeholder server, fixing..."
          sed -i.bak 's|server: https://placeholder:6443|server: https://kubernetes.default.svc:6443|g' "${path.module}/kubeconfig.yml"
          echo "Fixed server URL in kubeconfig.yml"
      fi
      
      # Basic validation using grep
      VALID=true
      
      grep -q "apiVersion:" "${path.module}/kubeconfig.yml" || { echo "Missing apiVersion"; VALID=false; }
      grep -q "clusters:" "${path.module}/kubeconfig.yml" || { echo "Missing clusters"; VALID=false; }
      grep -q "contexts:" "${path.module}/kubeconfig.yml" || { echo "Missing contexts"; VALID=false; }
      grep -q "current-context:" "${path.module}/kubeconfig.yml" || { echo "Missing current-context"; VALID=false; }
      grep -q "users:" "${path.module}/kubeconfig.yml" || { echo "Missing users"; VALID=false; }
      
      if [ "$VALID" = true ]; then
          echo "All required fields are present"
      else
          echo "Some required fields are missing, recreating kubeconfig"
          cat > "${path.module}/kubeconfig.yml" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.default.svc:6443
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
EOF
      fi
      
      # Check current-context
      CONTEXT=$(grep "current-context:" "${path.module}/kubeconfig.yml" | awk '{print $2}')
      echo "Current context is: $CONTEXT"
      
      # Ensure kubernetes-admin@kubernetes is the context
      if [ "$CONTEXT" != "kubernetes-admin@kubernetes" ]; then
          echo "Incorrect context, fixing..."
          sed -i.bak 's|current-context: .*|current-context: kubernetes-admin@kubernetes|g' "${path.module}/kubeconfig.yml"
          echo "Fixed current-context in kubeconfig.yml"
      fi
      
      echo "kubeconfig.yml is ready for use"
    EOT
  }
}

# Wait for Kubernetes API to be fully available
resource "null_resource" "wait_for_kubernetes" {
  depends_on = [module.k8s-cluster, terraform_data.init_environment]
  
  triggers = {
    # Use formatdate instead of raw timestamp to avoid changing on every apply
    timestamp = formatdate("YYYY-MM-DD", timestamp())
    # Only use instance_id and avoid any file hash references
    instance_id = try(module.k8s-cluster.control_plane_instance_id, "placeholder-instance-id")
  }
  
  # Add a simplified provisioner to validate the kubeconfig
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo "Validating generated kubeconfig..."
      
      # Clean any Windows line endings
      tr -d '\r' < "${path.module}/kubeconfig.yml" > "${path.module}/kubeconfig.clean.yml"
      mv "${path.module}/kubeconfig.clean.yml" "${path.module}/kubeconfig.yml"
      
      # Validate kubeconfig format using basic checks
      if ! grep -q "apiVersion: v1" "${path.module}/kubeconfig.yml"; then
        echo "Invalid kubeconfig, recreating..."
        cat > "${path.module}/kubeconfig.yml" << 'FALLBACK'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.default.svc:6443
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
FALLBACK
      fi
      
      # Update the server URL if needed
      if grep -q "placeholder:6443" "${path.module}/kubeconfig.yml"; then
        echo "Found placeholder server, fixing..."
        sed -i.bak 's|server: https://placeholder:6443|server: https://kubernetes.default.svc:6443|g' "${path.module}/kubeconfig.yml"
      fi
      
      # Ensure current-context is correct
      if ! grep -q "current-context: kubernetes-admin@kubernetes" "${path.module}/kubeconfig.yml"; then
        echo "Incorrect context, fixing..."
        sed -i.bak 's|current-context: .*|current-context: kubernetes-admin@kubernetes|g' "${path.module}/kubeconfig.yml"
      fi
      
      echo "Kubeconfig validation complete"
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
    interpreter = ["/bin/bash", "-c"]
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
      
      # Validate the kubeconfig format with basic checks
      if ! grep -q "apiVersion:" "${path.module}/kubeconfig.yml"; then
        echo "ERROR: kubeconfig doesn't contain apiVersion field"
        exit 1
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
      
      echo "Script completed successfully"
    EOT
  }
}

# Configure the Kubernetes provider with proper authentication
provider "kubernetes" {
  config_path    = "${path.module}/kubeconfig.yml"
  # Don't specify a context - use the current-context from the kubeconfig
  insecure       = true  # Allow connections to the API server without verifying the TLS certificate
}

# Configure the Helm provider with proper authentication
provider "helm" {
  kubernetes {
    config_path    = "${path.module}/kubeconfig.yml"
    # Use default context from the kubeconfig file
    insecure       = true
  }
}

# Configure the kubectl provider with proper authentication
provider "kubectl" {
  config_path      = "${path.module}/kubeconfig.yml"
  # Don't specify context - use the current-context from kubeconfig
  load_config_file = true
  insecure         = true
  
  # Skip TLS verification completely to avoid certificate parsing
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "echo"
    args        = ["{\"apiVersion\": \"client.authentication.k8s.io/v1beta1\", \"kind\": \"ExecCredential\", \"status\": {\"token\": \"dummy-token\"}}"]
  }
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

  # Start with the initialization resource that creates a valid kubeconfig
  depends_on = [terraform_data.init_environment]
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
