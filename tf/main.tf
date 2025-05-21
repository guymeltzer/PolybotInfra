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
    # Use a simple echo command to avoid bash syntax issues
    command = "echo 'Skipping Kubernetes state cleanup to avoid errors'"
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
    command     = <<-EOT
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
    command     = <<-EOT
      #!/bin/bash
      echo "Initializing environment with placeholder kubeconfig..."
      
      # Create a minimal placeholder kubeconfig
      cat > "./kubeconfig.yaml" << EOF
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

      chmod 600 "./kubeconfig.yaml"
      echo "Placeholder kubeconfig created successfully"
    EOT
  }
}

# Wait for Kubernetes API to be fully available
resource "null_resource" "wait_for_kubernetes" {
  depends_on = [module.k8s-cluster]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      echo "Waiting for Kubernetes cluster to be ready..."
      
      # Wait for control plane to be available
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
      if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
        echo "Control plane instance not found yet, waiting..."
        sleep 60
      else
        echo "Control plane instance found: $INSTANCE_ID"
      fi
      
      # Wait for SSM to be available
      MAX_ATTEMPTS=30
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "Checking if control plane is ready (attempt $i/$MAX_ATTEMPTS)..."
        
        # Check if SSM is available
        if aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$INSTANCE_ID" --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
          echo "Control plane SSM is online"
          
          # Check if kubeadm has initialized
          if aws ssm send-command --region ${var.region} --document-name "AWS-RunShellScript" --instance-ids "$INSTANCE_ID" \
              --parameters '{"commands":["test -f /etc/kubernetes/admin.conf && echo \"Found\""], "executionTimeout":["30"]}' \
              --output text --query "Command.CommandId" > /tmp/cmd_id.txt; then
              
            sleep 10
            OUTPUT=$(aws ssm get-command-invocation --region ${var.region} --command-id "$(cat /tmp/cmd_id.txt)" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text)
            if [[ "$OUTPUT" == *"Found"* ]]; then
              echo "Control plane is initialized successfully"
              break
            fi
          fi
        fi
        
        if [ $i -eq $MAX_ATTEMPTS ]; then
          echo "WARNING: Control plane initialization timeout, but continuing..."
        else
          echo "Control plane not ready yet, waiting 30 seconds..."
          sleep 30
        fi
      done
      
      echo "Wait for Kubernetes cluster complete"
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes, module.k8s-cluster]

  triggers_replace = [
    module.k8s-cluster.control_plane_public_ip,
    module.k8s-cluster.control_plane_id,
    # Add a hash of the scripts to ensure we redeploy if scripts change
    module.k8s-cluster.control_plane_script_hash,
    module.k8s-cluster.worker_script_hash
  ]

  provisioner "local-exec" {
    command = "aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=k8s-control-plane Name=instance-state-name,Values=running --query Reservations[0].Instances[0].InstanceId --output text > /tmp/instance_id.txt"
  }

  provisioner "local-exec" {
    command = "aws ec2 describe-instances --region ${var.region} --instance-ids $(cat /tmp/instance_id.txt) --query Reservations[0].Instances[0].PublicIpAddress --output text > /tmp/public_ip.txt"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Waiting for SSM to be ready on the instance..."
      MAX_ATTEMPTS=30
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

  provisioner "local-exec" {
    command = "aws ssm send-command --region ${var.region} --document-name AWS-RunShellScript --instance-ids $(cat /tmp/instance_id.txt) --parameters commands=\"sudo cat /etc/kubernetes/admin.conf\" --output text --query Command.CommandId > /tmp/command_id.txt"
  }

  provisioner "local-exec" {
    command = "sleep 30"
  }

  provisioner "local-exec" {
    command = "aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) --instance-id $(cat /tmp/instance_id.txt) --query StandardOutputContent --output text > /tmp/admin_conf.txt"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      # Check if we got a valid kubeconfig from the server
      if [ ! -s /tmp/admin_conf.txt ] || ! grep -q "apiVersion: v1" /tmp/admin_conf.txt; then
        echo "ERROR: Failed to retrieve a valid kubeconfig from the control plane"
        cat /tmp/admin_conf.txt
        exit 1
      fi
      
      # Update the server endpoint in the kubeconfig
      cat /tmp/admin_conf.txt | sed "s|server:.*|server: https://$(cat /tmp/public_ip.txt):6443|" > /tmp/modified_admin.conf
      
      # Validate the modified kubeconfig
      if [ ! -s /tmp/modified_admin.conf ] || ! grep -q "server: https://.*:6443" /tmp/modified_admin.conf; then
        echo "ERROR: Failed to create a valid modified kubeconfig"
        cat /tmp/modified_admin.conf
        exit 1
      fi
      
      echo "Successfully created modified kubeconfig with correct server endpoint"
    EOT
  }

  # Create kubeconfig.yaml in the current directory for easy access
  provisioner "local-exec" {
    command = "cp /tmp/modified_admin.conf ./kubeconfig.yaml && chmod 600 ./kubeconfig.yaml && echo 'Created usable kubeconfig.yaml file in current directory'"
  }

  # Verify the kubeconfig file works with the actual Kubernetes API
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Validating kubeconfig connects to the Kubernetes API server..."
      export KUBECONFIG="./kubeconfig.yaml"
      
      # Test kubectl without validation (just connectivity)
      kubectl version --client || {
        echo "ERROR: kubectl client not available"
        exit 1
      }
      
      # Test simple connectivity to the cluster
      MAX_ATTEMPTS=5
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "Attempt $i of $MAX_ATTEMPTS: Testing connection to Kubernetes API server..."
        if kubectl version --short 2>/dev/null; then
          echo "SUCCESS: Kubernetes API server is reachable using the kubeconfig!"
          break
        else
          echo "WARNING: Cannot connect to Kubernetes API server yet, waiting 10 seconds..."
          sleep 10
        fi
        
        if [ $i -eq $MAX_ATTEMPTS ]; then
          echo "WARNING: Could not connect to Kubernetes API server. Continuing anyway, but later steps may fail."
        fi
      done
    EOT
  }
}

# Store the control plane IP locally so we can use it in provider configs
locals {
  control_plane_ip = try(
    module.k8s-cluster.control_plane_public_ip,
    "kubernetes.default.svc"
  )
  skip_argocd     = false # Enable ArgoCD deployment
  skip_namespaces = false # Enable namespace creation
}

# Add a data source to ensure kubeconfig is ready
data "local_file" "kubeconfig" {
  depends_on = [terraform_data.kubectl_provider_config]
  filename   = "${path.module}/kubeconfig.yaml"
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
  config_path      = data.local_file.kubeconfig.filename
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
  count = local.skip_namespaces ? 0 : 1

  depends_on = [
    terraform_data.kubectl_provider_config,
    data.local_file.kubeconfig,
    null_resource.providers_ready
  ]

  # Only trigger after the control plane is actually ready
  triggers = {
    kubectl_config_id = terraform_data.kubectl_provider_config.id
    control_plane_ip  = try(module.k8s-cluster.control_plane_public_ip, "none")
  }

  # Use local-exec to create namespaces directly with kubectl
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e
      
      echo "Creating namespaces directly with kubectl..."
      
      # Wait a moment before attempting to create namespaces
      echo "Waiting 10 seconds for Kubernetes API server to stabilize..."
      sleep 10
      
      # Use the kubeconfig generated by terraform_data.kubectl_provider_config
      export KUBECONFIG="${path.module}/kubeconfig.yaml"
      
      # First verify the kubeconfig is valid and pointing to a real server
      echo "Validating kubeconfig before creating namespaces..."
      if grep -q "placeholder" "$KUBECONFIG"; then
        echo "ERROR: Kubeconfig still contains placeholder values. Waiting for real kubeconfig to be created."
        exit 1
      fi
      
      # Verify we can reach the Kubernetes API server
      if ! kubectl version --short 2>/dev/null; then
        echo "ERROR: Cannot connect to Kubernetes API server. Waiting for cluster to be ready."
        exit 1
      fi
      
      echo "Kubeconfig is valid and points to a real cluster. Creating namespaces..."
      
      # Create dev namespace if it doesn't exist
      echo "Creating dev namespace..."
      kubectl create namespace dev --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      # Create prod namespace if it doesn't exist
      echo "Creating prod namespace..."
      kubectl create namespace prod --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      # Create argocd namespace if it doesn't exist
      echo "Creating argocd namespace..."
      kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
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
  depends_on = [terraform_data.init_environment, terraform_data.deployment_information]
}

# Install EBS CSI Driver for persistent storage
resource "helm_release" "aws_ebs_csi_driver" {
  count      = fileexists("${path.module}/kubeconfig.yml") ? 1 : 0
  name       = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  namespace  = "kube-system"
  version    = "2.23.0"  # Use a specific stable version
  
  # Set shorter timeout to avoid long waits
  timeout    = 300
  wait       = false  # Don't wait for resources to be ready
  
  # Simplified values
  values = [<<EOF
controller:
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: ${module.k8s-cluster.control_plane_iam_role_arn}
storageClasses:
  - name: ebs-sc
    annotations:
      storageclass.kubernetes.io/is-default-class: "true"
    volumeBindingMode: WaitForFirstConsumer
    parameters:
      csi.storage.k8s.io/fstype: ext4
      type: gp2
      encrypted: "true"
EOF
  ]

  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
}

# ArgoCD deployment - only create after namespaces are ready
module "argocd" {
  count        = local.skip_argocd ? 0 : (fileexists(data.local_file.kubeconfig.filename) ? 1 : 0)
  source       = "./modules/argocd"
  git_repo_url = var.git_repo_url

  providers = {
    kubernetes = kubernetes
    helm       = helm
    kubectl    = kubectl
  }

  depends_on = [
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
  source                = "./modules/polybot"
  region                = var.region
  route53_zone_id       = var.route53_zone_id
  alb_dns_name          = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id           = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment           = "dev"
  telegram_token        = var.telegram_token_dev
  aws_access_key_id     = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username       = var.docker_username
  docker_password       = var.docker_password
}

# Production environment resources
module "polybot_prod" {
  source                = "./modules/polybot"
  region                = var.region
  route53_zone_id       = var.route53_zone_id
  alb_dns_name          = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id           = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment           = "prod"
  telegram_token        = var.telegram_token_prod
  aws_access_key_id     = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username       = var.docker_username
  docker_password       = var.docker_password
}

# Output commands for manual verification and namespace creation
resource "null_resource" "cluster_readiness_info" {
  depends_on = [
    module.k8s-cluster,
    terraform_data.kubectl_provider_config,
    data.local_file.kubeconfig
  ]

  # Run on each apply
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "---------------------------------------------------------"
      echo "KUBERNETES CLUSTER DEPLOYMENT INFORMATION"
      echo "---------------------------------------------------------"
      echo "Kubernetes control plane IP: ${try(module.k8s-cluster.control_plane_public_ip, "Not available yet")}"
      echo "Kubeconfig file: ${path.module}/kubeconfig.yaml"
      echo ""
      echo "To manually verify the cluster and create namespaces, run:"
      echo "export KUBECONFIG=${path.module}/kubeconfig.yaml"
      echo "kubectl get nodes"
      echo "kubectl create namespace dev --dry-run=client -o yaml | kubectl apply --validate=false -f -"
      echo "kubectl create namespace prod --dry-run=client -o yaml | kubectl apply --validate=false -f -"
      echo "kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply --validate=false -f -"
      echo ""
      echo "When cluster is verified as working, set skip_namespaces = false in locals"
      echo "---------------------------------------------------------"
    EOT
  }
}

terraform {
  # Standard configuration without experimental features
}

# Display important information at the start of deployment
resource "terraform_data" "deployment_information" {
  # Always run at the beginning of every terraform apply
  triggers_replace = {
    timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      # Save the start time for later tracking
      date +%s > /tmp/tf_start_time.txt
      
      echo -e "\033[1;34m========================================================\033[0m"
      echo -e "\033[1;34m     🚀 Polybot Kubernetes Deployment Started 🚀\033[0m"
      echo -e "\033[1;34m========================================================\033[0m"
      echo -e "\033[0;33m⏱️  This deployment takes approximately 10 minutes.\033[0m"
      echo -e "\033[0;33m⏱️  Progress indicators will be displayed throughout.\033[0m"
      echo -e "\033[0;33m⏱️  Colorful status updates will show deployment stages.\033[0m"
      echo -e "\033[0;33m⏱️  The first 5 minutes are AWS resources creation.\033[0m"
      echo -e "\033[0;33m⏱️  The next 5 minutes are Kubernetes initialization.\033[0m"
      echo -e "\033[0;32m➡️  Beginning infrastructure deployment now...\033[0m"
      
      # No background processes to avoid blocking terraform
    EOT
  }
}

# Final progress information and timing resource
resource "terraform_data" "deployment_completion_information" {
  depends_on = [
    module.k8s-cluster,
    module.polybot_dev,
    module.polybot_prod
  ]

  # Always run at the end of every terraform apply
  triggers_replace = {
    timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      # Simple completion message - no time tracking to avoid complexity
      echo -e "\033[1;34m========================================================\033[0m"
      echo -e "\033[1;32m     ✅ Polybot Kubernetes Deployment Complete! ✅\033[0m"
      echo -e "\033[1;34m========================================================\033[0m"
    EOT
  }
}


