provider "aws" {
  region = var.region
}

provider "tls" {}

# Resource to clean problematic resources from Terraform state
resource "terraform_data" "clean_kubernetes_state" {
  # Always run on every apply
  triggers_replace = {
    timestamp = timestamp()
  }

  provisioner "local-exec" {
    command = "bash -c 'RESOURCES=$(terraform state list 2>/dev/null | grep kubernetes_namespace || true); if [ -n \"$RESOURCES\" ]; then for resource in $RESOURCES; do echo \"Removing $resource from state...\"; terraform state rm \"$resource\" || echo \"Failed to remove $resource\"; done; else echo \"No kubernetes_namespace resources found in state.\"; fi'"
  }
}

# Define a local provider for first-time setup
provider "local" {}

# Resource to automate secrets management and cleanup
resource "terraform_data" "manage_secrets" {
  depends_on = [terraform_data.clean_kubernetes_state]
  
  # Always run on every apply
  triggers_replace = {
    timestamp = timestamp()
  }

  # Run script to check and clean up secrets
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      echo "Checking for stale AWS secrets..."
      
      # Check if jq is installed
      if ! command -v jq &> /dev/null; then
        echo "jq not found, skipping secret cleanup"
        exit 0
      fi
       
      # Check if AWS CLI is available
      if ! command -v aws &> /dev/null; then
        echo "AWS CLI not found, skipping secret cleanup"
        exit 0
      fi
       
      # Function to check for duplicate secrets
      check_duplicate_secrets() {
        local prefix="$1"
         
        echo "Checking for duplicates with prefix: $prefix"
         
        SECRETS=$(aws secretsmanager list-secrets \
          --region ${var.region} \
          --filters Key=name,Values="$prefix" \
          --query "SecretList[*].{Name:Name,ARN:ARN}" \
          --output json 2>/dev/null) || {
            echo "Failed to fetch secrets"
            return 0
          }
         
        COUNT=$(echo "$SECRETS" | jq -r 'length')
         
        if [ "$COUNT" -le 1 ]; then
          echo "No duplicate secrets found for $prefix"
          return 0
        fi
         
        echo "Found $COUNT secrets with prefix $prefix, cleaning up..."
         
        # Get all but the newest secret
        SECRETS_TO_DELETE=$(echo "$SECRETS" | jq -r '.[0:-1] | .[].Name')
         
        # Delete the older secrets
        for SECRET_NAME in $SECRETS_TO_DELETE; do
          echo "Force deleting $SECRET_NAME"
          aws secretsmanager delete-secret \
            --secret-id "$SECRET_NAME" \
            --force-delete-without-recovery \
            --region ${var.region} >/dev/null 2>&1 || echo "Failed to delete $SECRET_NAME"
        done
      }
       
      # Check each prefix directly instead of using arrays
      echo "Checking dev environment secrets..."
      check_duplicate_secrets "guy-polybot-dev-telegram-token"
      check_duplicate_secrets "guy-polybot-dev-docker-credentials"
      check_duplicate_secrets "guy-polybot-dev-secrets"
       
      echo "Checking prod environment secrets..."
      check_duplicate_secrets "guy-polybot-prod-telegram-token"
      check_duplicate_secrets "guy-polybot-prod-docker-credentials"
      check_duplicate_secrets "guy-polybot-prod-secrets"
       
      echo "Secret cleanup complete"
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
      echo "Initializing environment with placeholder kubeconfig..."
      
      # Create a minimal placeholder kubeconfig
      cat > "${path.module}/kubeconfig.yml" << EOF
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
    user: admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
users:
- name: admin
  user:
    token: placeholder
EOF

      chmod 600 "${path.module}/kubeconfig.yml"
      echo "Placeholder kubeconfig created successfully"
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
  
  # Add a simplified provisioner to just wait for the cluster
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo "Waiting for Kubernetes cluster to be ready..."
      
      # Wait for control plane to be available
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
      if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
        echo "Control plane instance not found yet, waiting..."
        sleep 60
      else
        echo "Control plane instance found: $INSTANCE_ID"
      fi
      
      echo "Wait for Kubernetes cluster complete"
EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes]
  
  # This ensures we rebuild when needed, not on every apply
  triggers_replace = {
    # Only trigger on instance changes, not on kubeconfig content
    instance_id = try(module.k8s-cluster.control_plane_instance_id, "placeholder-instance-id")
    # Add timestamp to ensure this always runs
    timestamp = timestamp()
  }

  # Step 1: Get the instance ID
  provisioner "local-exec" {
    command = "aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=k8s-control-plane Name=instance-state-name,Values=running --query Reservations[0].Instances[0].InstanceId --output text > /tmp/instance_id.txt"
  }

  # Step 2: Get the public IP
  provisioner "local-exec" {
    command = "aws ec2 describe-instances --region ${var.region} --instance-ids $(cat /tmp/instance_id.txt) --query Reservations[0].Instances[0].PublicIpAddress --output text > /tmp/public_ip.txt"
  }

  # Wait for SSM to be ready - add a retry mechanism
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      echo "Waiting for SSM to be ready on the instance..."
      MAX_ATTEMPTS=20
      WAIT_SECONDS=30
      
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "Attempt $i of $MAX_ATTEMPTS - Checking if SSM is ready..."
        
        if aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$(cat /tmp/instance_id.txt)" --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
          echo "SSM is ready!"
          break
        else
          echo "SSM not ready yet, waiting $WAIT_SECONDS seconds..."
          sleep $WAIT_SECONDS
        fi
        
        if [ $i -eq $MAX_ATTEMPTS ]; then
          echo "WARNING: Reached maximum attempts. Will try to continue but may encounter errors."
        fi
      done
    EOT
  }

  # Step 3: Get the admin.conf from the control plane
  provisioner "local-exec" {
    command = "aws ssm send-command --region ${var.region} --document-name AWS-RunShellScript --instance-ids $(cat /tmp/instance_id.txt) --parameters commands=\"sudo cat /etc/kubernetes/admin.conf\" --output text --query Command.CommandId > /tmp/command_id.txt"
  }

  # Step 4: Wait for the command to complete
  provisioner "local-exec" {
    command = "sleep 10"
  }

  # Step 5: Get the admin.conf content
  provisioner "local-exec" {
    command = "aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) --instance-id $(cat /tmp/instance_id.txt) --query StandardOutputContent --output text > /tmp/admin_conf.txt"
  }

  # Step 6: Create a copy with updated server URL and skip TLS verification
  provisioner "local-exec" {
    command = "cat /tmp/admin_conf.txt | sed \"s|server:.*|server: https://$(cat /tmp/public_ip.txt):6443|\" | sed \"s|certificate-authority-data:.*|insecure-skip-tls-verify: true|\" > /tmp/modified_admin.conf"
  }

  # Step 7: Create service account and role binding
  provisioner "local-exec" {
    command = <<-EOT
      kubectl --kubeconfig=/tmp/modified_admin.conf apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: terraform-admin
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: terraform-admin
subjects:
- kind: ServiceAccount
  name: terraform-admin
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
    EOT
  }

  # Step 8: Create token secret
  provisioner "local-exec" {
    command = <<-EOT
      kubectl --kubeconfig=/tmp/modified_admin.conf apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: terraform-admin-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: terraform-admin
type: kubernetes.io/service-account-token
EOF
    EOT
  }

  # Step 9: Wait for token to be generated
  provisioner "local-exec" {
    command = "sleep 10"
  }

  # Step 10: Get the token
  provisioner "local-exec" {
    command = "kubectl --kubeconfig=/tmp/modified_admin.conf -n kube-system get secret terraform-admin-token -o jsonpath='{.data.token}' | base64 --decode > /tmp/admin_token.txt"
  }

  # Step 11: Create the final kubeconfig
  provisioner "local-exec" {
    command = <<-EOT
      cat > ${path.module}/kubeconfig.yml <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://$(cat /tmp/public_ip.txt):6443
    insecure-skip-tls-verify: true
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: terraform-admin
  name: terraform-admin@kubernetes
current-context: terraform-admin@kubernetes
users:
- name: terraform-admin
  user:
    token: "$(cat /tmp/admin_token.txt)"
EOF
      chmod 600 ${path.module}/kubeconfig.yml
    EOT
  }

  # Step 12: Test connectivity
  provisioner "local-exec" {
    command = "kubectl --kubeconfig=${path.module}/kubeconfig.yml get nodes || echo 'Warning: Could not connect to cluster'"
  }

  # Step 13: Clean up temp files
  provisioner "local-exec" {
    command = "rm -f /tmp/instance_id.txt /tmp/public_ip.txt /tmp/command_id.txt /tmp/admin_conf.txt /tmp/modified_admin.conf /tmp/admin_token.txt"
  }
}

# Store the control plane IP locally so we can use it in provider configs
locals {
  control_plane_ip = try(
    module.k8s-cluster.control_plane_public_ip,
    "kubernetes.default.svc"
  )
  skip_argocd = true # Set to true to skip ArgoCD deployment temporarily
}

# Add a data source to ensure kubeconfig is ready
data "local_file" "kubeconfig" {
  depends_on = [terraform_data.kubectl_provider_config]
  filename   = "${path.module}/kubeconfig.yml"
}

# Configure the Kubernetes provider with proper authentication
provider "kubernetes" {
  config_path = data.local_file.kubeconfig.filename
  insecure    = true # Explicitly skip TLS verification
}

# Configure the Helm provider with proper authentication
provider "helm" {
  kubernetes {
    config_path = data.local_file.kubeconfig.filename
    insecure    = true # Explicitly skip TLS verification
  }
}

# Configure the kubectl provider with proper authentication
provider "kubectl" {
  config_path     = data.local_file.kubeconfig.filename
  load_config_file = true
}

# This is a workaround to ensure the providers are properly loaded with the kubeconfig
# We can't use depends_on in provider blocks, so we use this resource to simulate that
resource "null_resource" "providers_ready" {
  depends_on = [
    terraform_data.kubectl_provider_config,
    data.local_file.kubeconfig
  ]
  
  triggers = {
    # Use the instance_id instead of file hash to avoid inconsistency during apply
    instance_id = try(module.k8s-cluster.control_plane_instance_id, "placeholder-instance-id")
    # Add a timestamp component to ensure this runs when needed
    config_timestamp = terraform_data.kubectl_provider_config.id
  }
  
  provisioner "local-exec" {
    command = "echo 'Kubernetes providers ready with kubeconfig ${data.local_file.kubeconfig.filename}'"
  }
}

# Create Kubernetes namespaces directly with kubectl to avoid provider auth issues
resource "null_resource" "create_namespaces" {
  depends_on = [
    terraform_data.kubectl_provider_config,
    data.local_file.kubeconfig,
    null_resource.providers_ready
  ]

  # Use local-exec to create namespaces directly with kubectl
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      echo "Creating namespaces directly with kubectl..."
      
      # Use the kubeconfig generated by terraform_data.kubectl_provider_config
      export KUBECONFIG="${path.module}/kubeconfig.yml"
      
      # Create dev namespace if it doesn't exist
      echo "Creating dev namespace..."
      kubectl create namespace dev --dry-run=client -o yaml | kubectl apply -f -
      
      # Create prod namespace if it doesn't exist
      echo "Creating prod namespace..."
      kubectl create namespace prod --dry-run=client -o yaml | kubectl apply -f -
      
      # Create argocd namespace if it doesn't exist
      echo "Creating argocd namespace..."
      kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
      
      echo "Namespaces created successfully"
    EOT
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
# Commented out temporarily to avoid hanging issues
# resource "helm_release" "aws_ebs_csi_driver" {
#   count      = fileexists("${path.module}/kubeconfig.yml") ? 1 : 0
#   name       = "aws-ebs-csi-driver"
#   repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
#   chart      = "aws-ebs-csi-driver"
#   namespace  = "kube-system"
#   version    = "2.23.0"  # Use a specific stable version
#   
#   # Set shorter timeout to avoid long waits
#   timeout    = 300
#   wait       = false  # Don't wait for resources to be ready
#   
#   # Simplified values
#   values = [<<EOF
# controller:
#   serviceAccount:
#     annotations:
#       eks.amazonaws.com/role-arn: ${module.k8s-cluster.control_plane_iam_role_arn}
# storageClasses:
#   - name: ebs-sc
#     annotations:
#       storageclass.kubernetes.io/is-default-class: "true"
#     volumeBindingMode: WaitForFirstConsumer
#     parameters:
#       csi.storage.k8s.io/fstype: ext4
#       type: gp2
#       encrypted: "true"
# EOF
#   ]
# 
#   depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
# }

# ArgoCD deployment - only create after namespaces are ready
module "argocd" {
  count          = local.skip_argocd ? 0 : (fileexists(data.local_file.kubeconfig.filename) ? 1 : 0)
  source         = "./modules/argocd"
  git_repo_url   = var.git_repo_url
  
  providers = {
    kubernetes = kubernetes
    helm       = helm
    kubectl    = kubectl
  }
  
  depends_on     = [
    module.k8s-cluster, 
    null_resource.wait_for_kubernetes, 
    terraform_data.kubectl_provider_config,
    data.local_file.kubeconfig,
    null_resource.create_namespaces,
    null_resource.providers_ready
  ]
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
