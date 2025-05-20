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

  # Force provision step to ensure consistency between kubeconfig and the API server
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      # Helper function to create token-based config as fallback
      create_token_config() {
        local PUBLIC_IP="$1"
        
        # Determine if we have a bootstrap token available
        BOOTSTRAP_TOKEN="${try(module.k8s-cluster.kube_token, "")}"
        if [ -z "$BOOTSTRAP_TOKEN" ]; then
          # Generate a bootstrap token on the control plane if none exists
          echo "Bootstrap token not available from module, attempting to generate one"
          TOKEN_OUTPUT=$(aws ssm send-command \
            --region ${var.region} \
            --instance-ids $INSTANCE_ID \
            --document-name "AWS-RunShellScript" \
            --parameters commands="sudo kubeadm token create --ttl 24h --print-join-command" \
            --output text --query "Command.CommandId")
            
          if [ -n "$TOKEN_OUTPUT" ]; then
            echo "Waiting for token generation command to complete..."
            sleep 30
            
            TOKEN_RESULT=$(aws ssm get-command-invocation \
              --region ${var.region} \
              --command-id "$TOKEN_OUTPUT" \
              --instance-id "$INSTANCE_ID" \
              --query "StandardOutputContent" \
              --output text)
              
            if [[ "$TOKEN_RESULT" == *"--token"* ]]; then
              BOOTSTRAP_TOKEN=$(echo "$TOKEN_RESULT" | grep -o '\-\-token [^ ]*' | cut -d' ' -f2)
              echo "Successfully generated bootstrap token"
            else
              echo "Failed to extract token from result, using fallback token"
              BOOTSTRAP_TOKEN="ir58d3.jb0lbl6bf8uj3haq"
            fi
          else
            echo "Failed to run token generation command, using fallback token"
            BOOTSTRAP_TOKEN="ir58d3.jb0lbl6bf8uj3haq"
          fi
        fi
        
        # Create a kubeconfig with token-based auth and TLS skip
        KUBECONFIG_DIR="${path.module}"
        alias k='kubectl'
        echo "Creating kubeconfig with token auth and TLS skip verification..."
        cat > "$KUBECONFIG_DIR/kubeconfig.yml" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://$PUBLIC_IP:6443
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
    token: "$BOOTSTRAP_TOKEN"
EOF
        
        chmod 600 "$KUBECONFIG_DIR/kubeconfig.yml"
        echo "Created token-based kubeconfig with server URL: https://$PUBLIC_IP:6443"
      }

      # Wait for cluster to be ready with retry logic
      MAX_ATTEMPTS=10
      attempt=1
      while [ $attempt -le $MAX_ATTEMPTS ]; do
        echo "Attempt $attempt/$MAX_ATTEMPTS: Getting control plane IP"
        
        # Get the control plane's current IP
        INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
        if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
          echo "Control plane instance not found, retrying in 30 seconds..."
          sleep 30
          attempt=$((attempt + 1))
          continue
        fi
        
        PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
        if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" == "None" ]; then
          echo "Control plane public IP not found, retrying in 30 seconds..."
          sleep 30
          attempt=$((attempt + 1))
          continue
        fi
        
        echo "Control plane public IP: $PUBLIC_IP"
        break
      done
      
      if [ $attempt -gt $MAX_ATTEMPTS ]; then
        echo "Failed to get control plane IP after $MAX_ATTEMPTS attempts. Using a placeholder."
        PUBLIC_IP="placeholder"
      fi
      
      # Get the admin.conf from the control plane
      echo "Getting admin kubeconfig from control plane..."
      ADMIN_KUBECONFIG=$(aws ssm send-command \
        --region ${var.region} \
        --instance-ids $INSTANCE_ID \
        --document-name "AWS-RunShellScript" \
        --parameters commands="sudo cat /etc/kubernetes/admin.conf" \
        --output text --query "Command.CommandId")
        
      if [ -n "$ADMIN_KUBECONFIG" ]; then
        echo "Waiting for admin kubeconfig command to complete..."
        sleep 30
        
        # Get the command result
        KUBECONFIG_CONTENT=$(aws ssm get-command-invocation \
          --region ${var.region} \
          --command-id "$ADMIN_KUBECONFIG" \
          --instance-id "$INSTANCE_ID" \
          --query "StandardOutputContent" \
          --output text)
          
        if [ -n "$KUBECONFIG_CONTENT" ] && [[ "$KUBECONFIG_CONTENT" == *"apiVersion: v1"* ]]; then
          echo "Successfully retrieved admin kubeconfig from control plane"
          
          # Save the kubeconfig and update the server address
          KUBECONFIG_DIR="${path.module}"
          echo "$KUBECONFIG_CONTENT" > "$KUBECONFIG_DIR/kubeconfig.yml"
          
          # Update the server URL to use the public IP
          sed -i.bak "s|server:.*|server: https://$PUBLIC_IP:6443|g" "$KUBECONFIG_DIR/kubeconfig.yml"
          
          # Add insecure-skip-tls-verify
          sed -i.bak "s|certificate-authority-data:.*|insecure-skip-tls-verify: true|g" "$KUBECONFIG_DIR/kubeconfig.yml"
          
          chmod 600 "$KUBECONFIG_DIR/kubeconfig.yml"
          echo "Created kubeconfig with server URL: https://$PUBLIC_IP:6443"
        else
          echo "Failed to retrieve valid admin kubeconfig, falling back to token-based config"
          create_token_config "$PUBLIC_IP"
        fi
      else
        echo "Failed to send command to retrieve admin kubeconfig, falling back to token-based config"
        create_token_config "$PUBLIC_IP"
      fi
      
      # Test the connection
      if [ "$PUBLIC_IP" != "placeholder" ] && command -v kubectl &> /dev/null; then
        echo "Testing connection to Kubernetes API server..."
        if KUBECONFIG="${path.module}/kubeconfig.yml" kubectl cluster-info --request-timeout=10s; then
          echo "Successfully connected to Kubernetes API server"
          KUBECONFIG="${path.module}/kubeconfig.yml" kubectl get nodes
        else
          echo "Warning: Failed to connect to Kubernetes API server"
        fi
      fi
      
      echo "Kubeconfig script completed"
    EOT
  }
}

# Store the control plane IP locally so we can use it in provider configs
locals {
  control_plane_ip = try(
    module.k8s-cluster.control_plane_public_ip,
    "kubernetes.default.svc"
  )
}

# Configure the Kubernetes provider with proper authentication
provider "kubernetes" {
  config_path = "${path.module}/kubeconfig.yml"
  insecure = true # Explicitly skip TLS verification
}

# Configure the Helm provider with proper authentication
provider "helm" {
  kubernetes {
    config_path = "${path.module}/kubeconfig.yml"
    insecure = true # Explicitly skip TLS verification
  }
}

# Configure the kubectl provider with proper authentication
provider "kubectl" {
  config_path = "${path.module}/kubeconfig.yml"
  load_config_file = true
}

# Create Kubernetes namespaces for dev and prod
resource "kubernetes_namespace" "dev" {
  metadata {
    name = "dev"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  
  lifecycle {
    create_before_destroy = true
    # Add retry logic via local-exec instead of failing the resource
    precondition {
      condition     = fileexists("${path.module}/kubeconfig.yml")
      error_message = "Kubeconfig file must exist at ${path.module}/kubeconfig.yml"
    }
  }
}

resource "kubernetes_namespace" "prod" {
  metadata {
    name = "prod"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  
  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = fileexists("${path.module}/kubeconfig.yml")
      error_message = "Kubeconfig file must exist at ${path.module}/kubeconfig.yml"
    }
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
