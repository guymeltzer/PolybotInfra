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
  # Use a static count value
  count = 1

  # Make sure this only runs after the cluster setup starts
  depends_on = [module.k8s-cluster]

  # Run only when needed by tracking the control plane
  triggers = {
    # This will trigger a recreation if the cluster config changes
    instance_id = module.k8s-cluster.control_plane_id
  }

  # Check if the control plane API is actually accessible
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e
      
      # Get the control plane instance ID
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
        echo "No running control plane instance found"
        exit 0
      fi
      
      # Get the public IP of the control plane
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
      
      if [ "$PUBLIC_IP" == "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo "Control plane instance doesn't have a public IP yet"
        exit 0
      fi
      
      echo "Found control plane public IP: $PUBLIC_IP"
      
      echo "Waiting for Kubernetes API at https://$PUBLIC_IP:6443 to be ready..."
      
      # Function to test if API is reachable
      test_api() {
        curl -k -s --max-time 5 https://$PUBLIC_IP:6443/healthz
      }
      
      # Wait for API to be ready with retries
      MAX_ATTEMPTS=10
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "Attempt $i/$MAX_ATTEMPTS - Testing API connection..."
        if test_api | grep -q "ok"; then
          echo "API server is ready!"
          exit 0
        fi
        
        if [ $i -eq $MAX_ATTEMPTS ]; then
          echo "WARNING: API server not responding after $MAX_ATTEMPTS attempts, but continuing..."
          exit 0
        else
          echo "API not ready yet, waiting 10 seconds..."
          sleep 10
        fi
      done
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  # Use a static count value
  count = 1

  # Ensure this runs after the control plane is available and we've waited for the API
  depends_on = [
    null_resource.wait_for_kubernetes,
    module.k8s-cluster
  ]

  # Trigger updates when control plane details change
  triggers_replace = [
    module.k8s-cluster.control_plane_id
  ]

  # Retrieve and store kubeconfig directly from the control plane
  provisioner "local-exec" {
    command = <<-EOT
      # Wait for instance to appear
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
        echo "No running control plane instance found, exiting early"
        exit 0
      fi
      
      # Get the public IP of the control plane
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
      
      if [ "$PUBLIC_IP" == "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo "Control plane instance doesn't have a public IP yet, exiting early"
        exit 0
      fi
      
      echo "Using control plane with IP: $PUBLIC_IP and instance ID: $INSTANCE_ID"
      
      # Wait for SSM to be ready
      echo "Checking if SSM is available on the control plane..."
      if ! aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
           --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
        echo "SSM not available yet, exiting early"
        exit 0
      fi
      
      # Retrieve the kubeconfig from the control plane
      echo "Getting kubeconfig from control plane..."
      aws ssm send-command --region ${var.region} --document-name "AWS-RunShellScript" \
        --instance-ids "$INSTANCE_ID" --parameters 'commands=["cat /etc/kubernetes/admin.conf"]' \
        --output text --query "Command.CommandId" > /tmp/command_id.txt
      
      sleep 5
      
      # Get the kubeconfig content
      aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) \
        --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text > /tmp/kubeconfig_content.yaml
      
      # Only update kubeconfig if we got valid content
      if grep -q "apiVersion: v1" /tmp/kubeconfig_content.yaml; then
        # Update server endpoint in the kubeconfig
        cat /tmp/kubeconfig_content.yaml | sed "s|server:.*|server: https://$PUBLIC_IP:6443|" > ./kubeconfig.yaml
        chmod 600 ./kubeconfig.yaml
        echo "Created kubeconfig.yaml with server endpoint: https://$PUBLIC_IP:6443"
      else
        echo "Failed to retrieve valid kubeconfig, not updating existing file"
      fi
    EOT
  }
}

# Add a data source to ensure kubeconfig is ready - use a different pattern to avoid errors
# We'll use the file() function directly in a local value instead of a data source
locals {
  control_plane_ip = try(
    module.k8s-cluster.control_plane_public_ip,
    "kubernetes.default.svc"
  )
  skip_argocd     = false # Enable ArgoCD deployment
  skip_namespaces = false # Enable namespace creation
  # Check if kubeconfig exists and doesn't contain placeholder
  kubeconfig_exists = fileexists("${path.module}/kubeconfig.yaml")
  # Only consider Kubernetes ready if we have a real kubeconfig (not the placeholder)
  k8s_ready = local.kubeconfig_exists && (
    !contains(
      try(split("\n", file("${path.module}/kubeconfig.yaml")), []),
      "    server: https://placeholder:6443"
    )
  )
  kubeconfig_path = "${path.module}/kubeconfig.yaml"
}

# This ensures the Kubernetes providers are properly initialized before any resources use them
resource "null_resource" "providers_ready" {
  # Use a static count value
  count = 1
  
  # Depend on both the kubeconfig and the wait for Kubernetes resources
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.wait_for_kubernetes
  ]

  triggers = {
    # Track control plane properties to ensure this runs when they change
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }

  # Verify the kubeconfig is accessible
  provisioner "local-exec" {
    command = <<-EOT
      #!/bin/bash
      set -e
      
      # Check if kubeconfig exists
      if [ ! -f "${local.kubeconfig_path}" ]; then
        echo "Kubeconfig doesn't exist yet, creating placeholder"
        exit 0
      fi
      
      echo "Kubeconfig exists at ${local.kubeconfig_path}"
      
      # Get control plane info if available
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" != "None" ] && [ ! -z "$INSTANCE_ID" ]; then
        PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        
        if [ "$PUBLIC_IP" != "None" ] && [ ! -z "$PUBLIC_IP" ]; then
          echo "Checking if kubeconfig contains the real control plane IP..."
          if grep -q "server: https://$PUBLIC_IP:6443" "${local.kubeconfig_path}"; then
            echo "Kubeconfig contains real control plane IP ($PUBLIC_IP)"
          else
            echo "Updating kubeconfig with current IP"
            sed -i '' "s|server:.*|server: https://$PUBLIC_IP:6443|" "${local.kubeconfig_path}" || true
          fi
        fi
      fi
      
      echo "Providers ready with kubeconfig at ${local.kubeconfig_path}"
    EOT
  }
}

# Create Kubernetes namespaces directly with kubectl to avoid provider auth issues
resource "null_resource" "create_namespaces" {
  # Use a static count value based on the skip_namespaces flag
  count = local.skip_namespaces ? 0 : 1

  # Ensure all prerequisites are met
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready,
    null_resource.wait_for_kubernetes
  ]

  # Only trigger after the control plane is actually ready
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    instance_id = module.k8s-cluster.control_plane_id
  }

  # Use local-exec to create namespaces directly with kubectl
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      
      echo -e "\033[1;34m==== 🔍 Attempting to Create Kubernetes Namespaces ====\033[0m"
      
      export KUBECONFIG="${path.module}/kubeconfig.yaml"
      
      # Function to test API server connection with better error messages
      test_api_server() {
        echo -e "\033[0;33m⏱️  Testing Kubernetes API server connection...\033[0m"
        if kubectl get nodes --request-timeout=5s >/dev/null 2>&1; then
          echo -e "\033[0;32m✅ Connected to Kubernetes API server successfully\033[0m"
          return 0
        else
          echo -e "\033[0;33m⚠️  Cannot connect to Kubernetes API server\033[0m"
          return 1
        fi
      }
      
      # Function to display a spinner during wait periods
      spinner() {
        local pid=$1
        local delay=0.5
        local spinstr='|/-\'
        echo -n "   "
        while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
          local temp=$${spinstr#?}
          printf "\r\033[0;33m⏱️  Waiting for API server... %c\033[0m" "$spinstr"
          local spinstr=$temp$${spinstr%"$temp"}
          sleep $$delay
        done
        printf "\r   \033[0;33m⏱️  Continuing...\033[0m                      \n"
      }
      
      # Verify the kubeconfig is valid
      echo -e "\033[0;33m🔍 Validating kubeconfig at $KUBECONFIG\033[0m"
      if grep -q "placeholder" "$KUBECONFIG"; then
        echo -e "\033[0;31m❌ ERROR: Kubeconfig contains placeholder values\033[0m"
        exit 1
      fi
      
      # Try to connect to the API server with retries
      MAX_RETRIES=30
      RETRY_INTERVAL=20
      
      echo -e "\033[0;33m⏱️  Waiting up to 10 minutes for API server to be ready...\033[0m"
      
      for ((i=1; i<=MAX_RETRIES; i++)); do
        if test_api_server; then
          break
        fi
        
        if [ $i -eq $MAX_RETRIES ]; then
          echo -e "\033[0;31m❌ ERROR: Could not connect to API server after 30 attempts. Manual intervention required.\033[0m"
          echo -e "\033[0;33m📋 Troubleshooting tips:\033[0m"
          echo -e "   1. SSH to control plane: ssh ubuntu@${module.k8s-cluster.control_plane_public_ip}"
          echo -e "   2. Check logs: sudo journalctl -u kubelet"
          echo -e "   3. Check status: sudo systemctl status kubelet"
          echo -e "   4. Check pods: sudo kubectl get pods -A"
          exit 1
        else
          echo -e "\033[0;33m⏱️  Retry $i/$MAX_RETRIES - Waiting $RETRY_INTERVAL seconds before next attempt...\033[0m"
          sleep $RETRY_INTERVAL &
          spinner $!
        fi
      done
      
      echo -e "\033[1;34m==== 🚀 Creating Kubernetes Namespaces ====\033[0m"
      
      # Create dev namespace
      echo -e "\033[0;33m🔨 Creating dev namespace...\033[0m"
      kubectl create namespace dev --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      # Create prod namespace
      echo -e "\033[0;33m🔨 Creating prod namespace...\033[0m"
      kubectl create namespace prod --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      # Create argocd namespace
      echo -e "\033[0;33m🔨 Creating argocd namespace...\033[0m"
      kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      echo -e "\033[0;32m✅ Namespaces created successfully!\033[0m"
      echo -e "\033[1;34m===============================================\033[0m"
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
  rebuild_control_plane       = false # Set to true only when you need to force a rebuild

  addons = [
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/storage-class.yaml",
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/autoscaler.yaml"
  ]

  # Start with the initialization resource that creates a valid kubeconfig
  depends_on = [terraform_data.init_environment, terraform_data.deployment_information]
}

# Install EBS CSI Driver using local-exec only
resource "null_resource" "install_ebs_csi_driver" {
  # Use a static count value
  count = 1
  
  # Only run after we have a valid kubeconfig
  depends_on = [
    module.k8s-cluster, 
    null_resource.wait_for_kubernetes, 
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready
  ]
  
  # Only run when needed, based on resource changes
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    instance_id = module.k8s-cluster.control_plane_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Checking if kubeconfig is valid before installing EBS CSI Driver..."
      KUBECONFIG="${local.kubeconfig_path}"
      
      if [ ! -f "$KUBECONFIG" ]; then
        echo "Kubeconfig file not found, skipping installation"
        exit 0
      fi
      
      # Check if kubeconfig contains placeholder values
      if grep -q "placeholder" "$KUBECONFIG"; then
        echo "Kubeconfig contains placeholder values, skipping installation"
        exit 0
      fi
      
      # Check if we can connect to the Kubernetes API
      if ! kubectl --kubeconfig="$KUBECONFIG" cluster-info >/dev/null 2>&1; then
        echo "Cannot connect to Kubernetes cluster, skipping installation"
        exit 0
      fi
      
      echo "Installing EBS CSI Driver via Helm..."
      helm --kubeconfig="$KUBECONFIG" repo add aws-ebs-csi-driver https://kubernetes-sigs.github.io/aws-ebs-csi-driver
      helm --kubeconfig="$KUBECONFIG" repo update
      
      helm --kubeconfig="$KUBECONFIG" upgrade --install aws-ebs-csi-driver aws-ebs-csi-driver/aws-ebs-csi-driver \
        --namespace kube-system \
        --set controller.serviceAccount.annotations."eks\\.amazonaws\\.com/role-arn"="${module.k8s-cluster.control_plane_iam_role_arn}" \
        --set storageClasses[0].name=ebs-sc \
        --set storageClasses[0].annotations."storageclass\\.kubernetes\\.io/is-default-class"="true" \
        --set storageClasses[0].volumeBindingMode=WaitForFirstConsumer \
        --set storageClasses[0].parameters."csi\\.storage\\.k8s\\.io/fstype"=ext4 \
        --set storageClasses[0].parameters.type=gp2 \
        --set storageClasses[0].parameters.encrypted="true"
    EOT
  }
}

# Install ArgoCD using local-exec only
resource "null_resource" "install_argocd" {
  # Use a static count value based on the skip_argocd flag
  count = local.skip_argocd ? 0 : 1
  
  # Ensure all prerequisites are met
  depends_on = [
    module.k8s-cluster,
    null_resource.wait_for_kubernetes,
    terraform_data.kubectl_provider_config,
    null_resource.create_namespaces,
    null_resource.providers_ready,
    null_resource.install_ebs_csi_driver
  ]
  
  # Only run when needed
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    instance_id = module.k8s-cluster.control_plane_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Checking if kubeconfig is valid before installing ArgoCD..."
      KUBECONFIG="${local.kubeconfig_path}"
      
      if [ ! -f "$KUBECONFIG" ]; then
        echo "Kubeconfig file not found, skipping installation"
        exit 0
      fi
      
      # Check if kubeconfig contains placeholder values
      if grep -q "placeholder" "$KUBECONFIG"; then
        echo "Kubeconfig contains placeholder values, skipping installation"
        exit 0
      fi
      
      # Check if we can connect to the Kubernetes API
      if ! kubectl --kubeconfig="$KUBECONFIG" cluster-info >/dev/null 2>&1; then
        echo "Cannot connect to Kubernetes cluster, skipping installation"
        exit 0
      fi
      
      echo "Ensuring argocd namespace exists..."
      kubectl --kubeconfig="$KUBECONFIG" create namespace argocd --dry-run=client -o yaml | kubectl --kubeconfig="$KUBECONFIG" apply --validate=false -f -
      
      echo "Installing ArgoCD..."
      kubectl --kubeconfig="$KUBECONFIG" apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
      
      # Configure ArgoCD with Git repository (optional)
      # If you need to configure ArgoCD with specific Git repositories, add appropriate kubectl commands here
      
      # Example: Wait for ArgoCD to be ready
      echo "Waiting for ArgoCD to be ready..."
      kubectl --kubeconfig="$KUBECONFIG" -n argocd wait --for=condition=available --timeout=300s deployment/argocd-server || true
      
      echo "ArgoCD installation complete (or timeout reached)"
    EOT
  }
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
  # Use a static count value
  count = 1

  depends_on = [
    module.k8s-cluster,
    terraform_data.kubectl_provider_config
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
      echo "Kubeconfig file: ${local.kubeconfig_path}"
      echo ""
      echo "To manually verify the cluster and create namespaces, run:"
      echo "export KUBECONFIG=${local.kubeconfig_path}"
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

# Configure providers with proper dependency handling
provider "kubernetes" {
  # Use config_path instead of trying to parse the YAML during plan
  config_path    = "${path.module}/kubeconfig.yaml"
  config_context = "kubernetes-admin@kubernetes"
}

provider "helm" {
  kubernetes {
    # Use config_path instead of trying to parse the YAML during plan
    config_path    = "${path.module}/kubeconfig.yaml"
    config_context = "kubernetes-admin@kubernetes"
  }
}

provider "kubectl" {
  # Use config_path instead of trying to parse the YAML during plan
  config_path    = "${path.module}/kubeconfig.yaml"
  config_context = "kubernetes-admin@kubernetes"
  load_config_file = true
}

# Special resource to clean up Kubernetes state
resource "terraform_data" "kubernetes_state_clean" {
  # Only run during destroy operations
  triggers_replace = {
    timestamp = timestamp()
  }

  # This will only be executed during destroy operations
  provisioner "local-exec" {
    when = destroy
    command = <<-EOT
      echo "Removing Kubernetes-dependent resources from state if needed..."
      terraform state rm null_resource.wait_for_kubernetes[0] || true
      terraform state rm null_resource.install_ebs_csi_driver[0] || true
      terraform state rm null_resource.install_argocd[0] || true
      terraform state rm null_resource.create_namespaces[0] || true
      terraform state rm null_resource.providers_ready[0] || true
      terraform state rm terraform_data.kubectl_provider_config[0] || true
      echo "Kubernetes resources cleaned up from state."
    EOT
  }
}


