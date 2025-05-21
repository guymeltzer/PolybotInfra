provider "aws" {
  region = var.region
}

# Variable to indicate destroy mode - set to true when running terraform destroy
variable "destroy_mode" {
  description = "Set to true when destroying infrastructure to skip Kubernetes API connections"
  type        = bool
  default     = false
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
  # Completely disable this resource during destroy
  count = local.destroy_mode ? 0 : 1
  # Make sure this only runs after the cluster setup starts
  depends_on = [module.k8s-cluster]

  # Run only when needed by adding a dynamic trigger
  triggers = {
    # This will ensure it runs only when needed
    cluster_id = try(module.k8s-cluster.control_plane_id, "no-id-yet")
    # Always run if the hash of the scripts changes
    script_hash = join("", [
      try(module.k8s-cluster.control_plane_script_hash, ""),
      try(module.k8s-cluster.worker_script_hash, "")
    ])
  }

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
  count = local.destroy_mode ? 0 : 1
  
  depends_on = [null_resource.wait_for_kubernetes, module.k8s-cluster]

  triggers_replace = [
    try(module.k8s-cluster.control_plane_public_ip, "no-ip-yet"),
    try(module.k8s-cluster.control_plane_id, "no-id-yet"),
    # Add a hash of the scripts to ensure we redeploy if scripts change
    try(module.k8s-cluster.control_plane_script_hash, "no-hash-yet"),
    try(module.k8s-cluster.worker_script_hash, "no-hash-yet")
  ]

  provisioner "local-exec" {
    command = <<-EOT
      # Make sure we have the AWS CLI available
      which aws || { echo "AWS CLI not installed"; exit 1; }
      
      # Get the control plane instance ID
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
        echo "No running control plane instance found, will wait for it to be created"
        sleep 30
        exit 0
      fi
      
      echo "Found control plane instance ID: $INSTANCE_ID"
      echo $INSTANCE_ID > /tmp/instance_id.txt
      
      # Get the public IP of the control plane
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
      
      if [ "$PUBLIC_IP" == "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo "Control plane instance doesn't have a public IP yet, will wait"
        sleep 30
        exit 0
      fi
      
      echo "Found control plane public IP: $PUBLIC_IP"
      echo $PUBLIC_IP > /tmp/public_ip.txt
    EOT
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Waiting for SSM to be ready on the instance..."
      MAX_ATTEMPTS=30
      WAIT_SECONDS=30
      
      PUBLIC_IP=$(cat /tmp/public_ip.txt)
      INSTANCE_ID=$(cat /tmp/instance_id.txt)
      
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "Attempt $i of $MAX_ATTEMPTS - Checking if SSM is ready..."
        
        if aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$INSTANCE_ID" --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
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
      
      # Try to get the kubeconfig from the control plane
      echo "Retrieving kubeconfig from control plane..."
      aws ssm send-command --region ${var.region} --document-name AWS-RunShellScript --instance-ids $INSTANCE_ID \
        --parameters 'commands=["sudo cat /etc/kubernetes/admin.conf"]' \
        --output text --query Command.CommandId > /tmp/command_id.txt
      
      sleep 10
      
      # Get the kubeconfig content
      aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) \
        --instance-id $INSTANCE_ID --query StandardOutputContent --output text > /tmp/admin_conf.txt
      
      # Check if we got a valid kubeconfig from the server
      if [ ! -s /tmp/admin_conf.txt ] || ! grep -q "apiVersion: v1" /tmp/admin_conf.txt; then
        echo "WARNING: Failed to retrieve a valid kubeconfig. Creating placeholder instead."
                 cat > /tmp/admin_conf.txt << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://\$PUBLIC_IP:6443
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
      else
        echo "Successfully retrieved kubeconfig from control plane"
      fi
      
      # Update the server endpoint in the kubeconfig
      cat /tmp/admin_conf.txt | sed "s|server:.*|server: https://$PUBLIC_IP:6443|" > /tmp/modified_admin.conf
      
      # Create kubeconfig.yaml in the current directory
      cp /tmp/modified_admin.conf ./kubeconfig.yaml && chmod 600 ./kubeconfig.yaml
      
      echo "Created usable kubeconfig.yaml file in current directory with server endpoint: https://$PUBLIC_IP:6443"
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
  
  # NEW: Special flag to disable all Kubernetes-dependent resources for destroy operations
  # Set this to true when running terraform destroy
  destroy_mode = tobool(try(var.destroy_mode, false))
}

# This is a workaround to ensure the local-exec commands run in the right order
resource "null_resource" "providers_ready" {
  count = local.destroy_mode ? 0 : 1
  
  depends_on = [
    terraform_data.kubectl_provider_config
  ]

  triggers = {
    # Use the instance_id instead of file hash to avoid inconsistency during apply
    instance_id = try(module.k8s-cluster.control_plane_instance_id, "placeholder-instance-id")
    # Add a timestamp component to ensure this runs when needed
    config_timestamp = local.destroy_mode ? "dummy-id" : try(terraform_data.kubectl_provider_config[0].id, "dummy-id")
  }

  provisioner "local-exec" {
    command = "echo 'Kubeconfig generated at ${local.kubeconfig_path}'"
  }
}

# Create Kubernetes namespaces directly with kubectl to avoid provider auth issues
resource "null_resource" "create_namespaces" {
  count = local.destroy_mode || local.skip_namespaces ? 0 : 1

  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready,
    null_resource.wait_for_kubernetes
  ]

  # Only trigger after the control plane is actually ready
  triggers = {
    kubectl_config_id = local.destroy_mode ? "dummy-id" : try(terraform_data.kubectl_provider_config[0].id, "dummy-id")
    control_plane_ip  = try(module.k8s-cluster.control_plane_public_ip, "none")
    # Add a timestamp to ensure it runs when needed
    timestamp = timestamp()
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
  count = local.destroy_mode ? 0 : 1
  
  # Only run after we have a valid kubeconfig
  depends_on = [
    module.k8s-cluster, 
    null_resource.wait_for_kubernetes, 
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready
  ]
  
  # Only run when needed, based on resource changes
  triggers = {
    k8s_config_timestamp = local.destroy_mode ? "dummy-id" : try(terraform_data.kubectl_provider_config[0].id, "dummy-id")
    control_plane_ip = try(module.k8s-cluster.control_plane_public_ip, "placeholder")
    always_run = timestamp() # Run on every apply
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
  count = local.destroy_mode || local.skip_argocd ? 0 : 1
  
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
    k8s_config_timestamp = local.destroy_mode ? "dummy-id" : try(terraform_data.kubectl_provider_config[0].id, "dummy-id")
    control_plane_ip = try(module.k8s-cluster.control_plane_public_ip, "placeholder")
    always_run = timestamp() # Run on every apply
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
  count = local.destroy_mode ? 0 : 1

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

# Configure Kubernetes providers with intentionally invalid/unusable configurations
# This block only appears in main.tf for reference but isn't actually used during destroy
provider "kubernetes" {
  # Never actually used - just to avoid provider errors without attempting connections
  host = "https://127.0.0.1:1"
  insecure = true
}

provider "helm" {
  # Never actually used - just to avoid provider errors without attempting connections
  kubernetes {
    host = "https://127.0.0.1:1"
    insecure = true
  }
}

provider "kubectl" {
  # Never actually used - just to avoid provider errors without attempting connections
  host = "https://127.0.0.1:1"
  insecure = true
  load_config_file = false
}


