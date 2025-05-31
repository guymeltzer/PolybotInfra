provider "aws" {
  region = var.region
  # Note: If explicit deny issues persist, consider this alternative approach
  # Uncomment and set role_arn to a role with appropriate permissions
  # assume_role {
  #   role_arn = "arn:aws:iam::${var.account_id}:role/terraform-deployer-role"
  # }
}

provider "tls" {}

#DEBUGGABLE: Enhanced Terraform debugging and logging configuration
locals {
  # Debugging configuration for enhanced visibility
  debug_config = {
    log_level = "DEBUG"
    log_path  = "logs/"
    timestamp = timestamp()
  }

  # Structured logging for all components
  debug_environment = {
    TF_LOG                = "DEBUG"
    TF_LOG_CORE          = "DEBUG"
    TF_LOG_PATH          = "${local.debug_config.log_path}terraform-${local.debug_config.timestamp}.log"
    TF_LOG_PROVIDER      = "DEBUG"
    AWS_LOG_LEVEL        = "debug"
  }

  # Debug log file path
  debug_log = "${local.debug_config.log_path}tf_debug.log"

  kubeconfig_path = "${path.module}/kubeconfig.yaml"
  # Enhanced SSH key path resolution with comprehensive fallback logic
  ssh_private_key_path = var.key_name != "" ? (
    # Priority 1: Check if key exists in current module directory
    fileexists("${path.module}/${var.key_name}.pem") ?
    "${path.module}/${var.key_name}.pem" :
    # Priority 2: Check if key exists in user's .ssh directory 
    (fileexists("${pathexpand("~/.ssh/${var.key_name}.pem")}") ?
      "${pathexpand("~/.ssh/${var.key_name}.pem")}" :
      # Priority 3: Check for absolute path if provided
      (fileexists("${var.ssh_private_key_file_path}") && var.ssh_private_key_file_path != "" ?
        var.ssh_private_key_file_path :
        # Priority 4: Use default polybot-key in module directory
        "${path.module}/polybot-key.pem"
      )
    )
  ) : "${path.module}/polybot-key.pem"
  
  # SSH configuration for consistent usage across all provisioners
  ssh_config = {
    key_path = local.ssh_private_key_path
    user = "ubuntu"
    options = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
  }
  
  skip_argocd     = false # Enable ArgoCD deployment
  skip_namespaces = false # Enable namespace creation
  # Check if kubeconfig exists and doesn't contain placeholder
  kubeconfig_exists = fileexists("${path.module}/kubeconfig.yaml")
  # Only consider Kubernetes ready if we have a real kubeconfig (not the placeholder)
  k8s_ready = local.kubeconfig_exists && (
  !strcontains(
    try(file("${path.module}/kubeconfig.yaml"), ""),
    "server: https://placeholder:6443"
  )
  )
  # Add the control_plane_ip from the second locals block
  control_plane_ip = try(
    module.k8s-cluster.control_plane_public_ip,
    "kubernetes.default.svc"
  )
}

# K8S-CLUSTER MODULE - Main Kubernetes cluster infrastructure
module "k8s-cluster" {
  source = "./modules/k8s-cluster"

  # Required parameters
  region                       = var.region
  cluster_name                 = "guy-cluster"  # Fixed cluster name
  vpc_id                       = var.vpc_id
  subnet_ids                   = var.subnet_ids
  route53_zone_id              = var.route53_zone_id
  key_name                     = var.key_name
  control_plane_ami            = var.control_plane_ami
  worker_ami                   = var.worker_ami
  control_plane_instance_type  = var.control_plane_instance_type
  worker_instance_type         = var.worker_instance_type
  worker_count                 = var.desired_worker_nodes
  instance_type                = var.instance_type
  ssh_public_key              = var.ssh_public_key
  skip_api_verification       = var.skip_api_verification
  skip_token_verification     = var.skip_token_verification
  verification_max_attempts   = var.verification_max_attempts
  verification_wait_seconds   = var.verification_wait_seconds
  pod_cidr                    = var.pod_cidr
  
  # ASG Control Variables
  desired_worker_nodes         = var.desired_worker_nodes
  force_cleanup_asg           = var.force_cleanup_asg

  # Optional parameters
  tags = {
    Environment = "production"
    Project     = "polybot"
    ManagedBy   = "terraform"
  }
}

# SIMPLIFIED: Comprehensive debugging and logging
# Replaces: debug_initialization, kubernetes_readiness_debug, debug_bundle_creation, deployment_summary, integrated_debug_analysis
resource "null_resource" "debug_comprehensive" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      # Create debug infrastructure
      mkdir -p logs
      
      # Log deployment start with environment info
      cat > logs/deployment_start.json <<JSON
{
  "stage": "deployment_start",
  "timestamp": "${timestamp()}",
  "terraform_workspace": "${terraform.workspace}",
  "region": "${var.region}",
  "kubeconfig_path": "${local.kubeconfig_path}",
  "debug_environment": ${jsonencode(local.debug_environment)}
}
JSON

      echo "✅ Debug infrastructure initialized"
    EOT
  }
}

# Final deployment status and comprehensive logging
resource "null_resource" "deployment_summary" {
  depends_on = [
    null_resource.cluster_readiness_check,
    null_resource.install_argocd,
    null_resource.configure_argocd_apps,
    null_resource.cleanup_orphaned_nodes
  ]

  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id
    argocd_install_id = try(null_resource.install_argocd[0].id, "skipped")
    cleanup_id = null_resource.cleanup_orphaned_nodes.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "📊 Creating comprehensive deployment summary..."
      
      # Create summary directory
      mkdir -p logs/final_summary
      
      # Capture final cluster state
      if kubectl get nodes >/dev/null 2>&1; then
        kubectl get nodes -o wide > logs/final_summary/nodes.txt 2>&1 || echo "Failed to get nodes" > logs/final_summary/nodes.txt
        kubectl get pods --all-namespaces -o wide > logs/final_summary/all_pods.txt 2>&1 || echo "Failed to get pods" > logs/final_summary/all_pods.txt
        kubectl get deployments --all-namespaces > logs/final_summary/deployments.txt 2>&1 || echo "Failed to get deployments" > logs/final_summary/deployments.txt
        kubectl get services --all-namespaces > logs/final_summary/services.txt 2>&1 || echo "Failed to get services" > logs/final_summary/services.txt
      else
        echo "Kubectl connection failed" > logs/final_summary/connection_failed.txt
      fi
      
      # Capture AWS resources
      aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:aws:autoscaling:groupName,Values=guy-polybot-asg" \
        --output json > logs/final_summary/worker_instances.json 2>&1 || echo "Failed to get worker instances" > logs/final_summary/worker_instances.json
      
      # Create deployment summary JSON
      cat > logs/final_summary/deployment_summary.json <<JSON
{
  "deployment_complete": "${timestamp()}",
  "region": "${var.region}",
  "terraform_workspace": "${terraform.workspace}",
  "control_plane_ip": "${module.k8s-cluster.control_plane_public_ip}",
  "skip_argocd": ${local.skip_argocd},
  "kubeconfig_path": "${local.kubeconfig_path}",
  "status": "deployment_completed"
}
JSON

      echo "📦 Creating debug bundle..."
      cd logs
      tar -czf "debug-bundle-$(date +%Y%m%d-%H%M%S).tgz" . 2>/dev/null || echo "Failed to create debug bundle"
      
      echo "✅ Comprehensive deployment summary complete!"
      echo "📋 Summary files created in logs/final_summary/"
      echo "📦 Debug bundle created in logs/"
    EOT
  }
}

# Resource to clean problematic resources from Terraform state
resource "terraform_data" "clean_kubernetes_state" {
  # Use more deterministic triggers that don't cause unnecessary runs
  triggers_replace = {
    # Only run when the kubeconfig changes or is created/deleted
    kubeconfig_status = fileexists("${path.module}/kubeconfig.yaml") ? filemd5("${path.module}/kubeconfig.yaml") : "not_exists"
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

  # Only run when relevant files change
  triggers_replace = {
    # Run when relevant configuration files change
    tfvars_exists = fileexists("${path.module}/region.${var.region}.tfvars") ? filemd5("${path.module}/region.${var.region}.tfvars") : "not_exists"
    variables_hash = filemd5("${path.module}/variables.tf")
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
# DISABLED: init_environment resource removed to prevent kubeconfig conflicts
# This resource was creating placeholder kubeconfig files that interfered with
# the proper kubeconfig management in terraform_data.kubectl_provider_config
# All kubeconfig creation is now handled by the robust kubectl_provider_config resource

# Resource to wait for Kubernetes API to be fully available - with enhanced validation
resource "null_resource" "wait_for_kubernetes" {
  count = 1
  
  # CRITICAL: Depend on the kubeconfig being properly created
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    cluster_id = module.k8s-cluster.control_plane_instance_id
    # Force re-run if kubeconfig changes
    kubeconfig_hash = fileexists("${local.kubeconfig_path}") ? filemd5("${local.kubeconfig_path}") : "no-file"
    validation_version = "v2-enhanced"
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      echo "🔄 Waiting for Kubernetes API to be ready..."
      echo "📁 Using kubeconfig: ${local.kubeconfig_path}"
      
      # CRITICAL: Comprehensive kubeconfig validation
      validate_kubeconfig() {
        echo "🔍 Validating kubeconfig file..."
        
        # Check if file exists
        if [[ ! -f "${local.kubeconfig_path}" ]]; then
          echo "❌ FATAL: Kubeconfig file not found at ${local.kubeconfig_path}"
          echo "💡 This indicates terraform_data.kubectl_provider_config failed"
          echo "   Check previous logs for kubeconfig generation errors"
          return 1
        fi
        
        # Check file size (should be substantial)
        FILESIZE=$(stat -f%z "${local.kubeconfig_path}" 2>/dev/null || stat -c%s "${local.kubeconfig_path}" 2>/dev/null || echo "0")
        if [[ "$FILESIZE" -lt 100 ]]; then
          echo "❌ FATAL: Kubeconfig file is too small ($FILESIZE bytes)"
          echo "   This suggests the file is empty or contains placeholder content"
          echo "📋 Current content:"
          cat "${local.kubeconfig_path}" || echo "   (file is empty or unreadable)"
          return 1
        fi
        
        echo "✅ Kubeconfig file size: $FILESIZE bytes"
        
        # Check for required kubeconfig structure
        if ! grep -q "apiVersion.*Config" "${local.kubeconfig_path}"; then
          echo "❌ FATAL: Kubeconfig missing apiVersion Config"
          echo "📋 File content preview:"
          head -10 "${local.kubeconfig_path}"
          return 1
        fi
        
        if ! grep -q "clusters:" "${local.kubeconfig_path}"; then
          echo "❌ FATAL: Kubeconfig missing clusters section"
          return 1
        fi
        
        if ! grep -q "users:" "${local.kubeconfig_path}"; then
          echo "❌ FATAL: Kubeconfig missing users section"
          return 1
        fi
        
        # CRITICAL: Check for placeholder endpoints
        SERVER_ENDPOINT=$(grep "server:" "${local.kubeconfig_path}" | head -1 | awk '{print $2}' || echo "")
        echo "🔗 Server endpoint: $SERVER_ENDPOINT"
        
        if [[ -z "$SERVER_ENDPOINT" ]]; then
          echo "❌ FATAL: No server endpoint found in kubeconfig"
          return 1
        fi
        
        # Check for known placeholder patterns
        PLACEHOLDER_PATTERNS=(
          "placeholder"
          "127.0.0.1:9999"
          "localhost:9999"
          "kubernetes.default.svc"
          "example.com"
          "PLACEHOLDER"
        )
        
        for pattern in "$${PLACEHOLDER_PATTERNS[@]}"; do
          if [[ "$SERVER_ENDPOINT" == *"$pattern"* ]]; then
            echo "❌ FATAL: Kubeconfig contains placeholder endpoint: $SERVER_ENDPOINT"
            echo "   Pattern detected: $pattern"
            echo "   This means kubeconfig generation didn't complete properly"
            echo ""
            echo "📋 Full kubeconfig content:"
            cat "${local.kubeconfig_path}"
            echo ""
            echo "💡 To fix this:"
            echo "   1. Check terraform_data.kubectl_provider_config logs"
            echo "   2. Verify control plane is fully initialized"
            echo "   3. Re-run: terraform apply -target=terraform_data.kubectl_provider_config"
            return 1
          fi
        done
        
        # Validate endpoint format (should be https://IP:6443)
        if [[ ! "$SERVER_ENDPOINT" =~ ^https://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:6443$ ]]; then
          echo "⚠️  Server endpoint format unexpected: $SERVER_ENDPOINT"
          echo "   Expected format: https://IP:6443"
          echo "   This might still work, but could indicate an issue"
        fi
        
        # Check for certificates (should be base64 encoded)
        if ! grep -q "certificate-authority-data:" "${local.kubeconfig_path}"; then
          echo "⚠️  No certificate-authority-data found"
          echo "   This might work with insecure-skip-tls-verify"
        fi
        
        if ! grep -q "client-certificate-data:" "${local.kubeconfig_path}"; then
          echo "⚠️  No client-certificate-data found"
          echo "   This might indicate authentication issues"
        fi
        
        echo "✅ Kubeconfig validation passed"
        echo "   Endpoint: $SERVER_ENDPOINT"
        return 0
      }
      
      # Enhanced Kubernetes API connectivity test
      test_kubernetes_api() {
        echo ""
        echo "🌐 Testing Kubernetes API connectivity..."
        
        # Test with timeout and retries
        MAX_ATTEMPTS=30  # 10 minutes total (30 * 20 seconds)
        ATTEMPT=1
        
        while [[ $ATTEMPT -le $MAX_ATTEMPTS ]]; do
          echo "🔄 Attempt $ATTEMPT/$MAX_ATTEMPTS: Testing Kubernetes API connection..."
          
          # Try kubectl with detailed error capture
          if KUBECONFIG="${local.kubeconfig_path}" timeout 15 kubectl get nodes --request-timeout=10s >/dev/null 2>&1; then
            echo "✅ Successfully connected to Kubernetes API!"
            echo ""
            echo "📋 Cluster information:"
            KUBECONFIG="${local.kubeconfig_path}" kubectl get nodes -o wide || echo "Could not get detailed node info"
            echo ""
            KUBECONFIG="${local.kubeconfig_path}" kubectl cluster-info || echo "Could not get cluster info"
            return 0
          else
            echo "⏳ API not ready yet (attempt $ATTEMPT/$MAX_ATTEMPTS)"
            
            # Get detailed error on every 5th attempt
            if [[ $((ATTEMPT % 5)) -eq 0 ]]; then
              echo "🔍 Detailed error information:"
              KUBECONFIG="${local.kubeconfig_path}" kubectl get nodes --request-timeout=10s 2>&1 | head -5 || true
            fi
            
            if [[ $ATTEMPT -eq $MAX_ATTEMPTS ]]; then
              echo ""
              echo "❌ FATAL: Failed to connect to Kubernetes API after $MAX_ATTEMPTS attempts"
              echo ""
              echo "🔍 Final troubleshooting information:"
              echo "   Kubeconfig path: ${local.kubeconfig_path}"
              echo "   Server endpoint: $(grep 'server:' "${local.kubeconfig_path}" | head -1)"
              echo ""
              echo "📋 Last kubectl error:"
              KUBECONFIG="${local.kubeconfig_path}" kubectl get nodes --request-timeout=10s 2>&1 || true
              echo ""
              echo "📋 Kubeconfig content:"
              cat "${local.kubeconfig_path}"
              echo ""
              echo "🛠️  Troubleshooting steps:"
              echo "   1. Verify control plane is running:"
              echo "      aws ec2 describe-instances --region ${var.region} --instance-ids ${module.k8s-cluster.control_plane_instance_id}"
              echo ""
              echo "   2. Check control plane logs:"
        echo "5. 🔧 Generate new SSH key pair:"
        echo "   aws ec2 create-key-pair --key-name new-polybot-key --query 'KeyMaterial' --output text > new-polybot-key.pem"
        echo "   chmod 600 new-polybot-key.pem"
        echo ""
        echo "6. 🔍 Check security group rules:"
        echo "   aws ec2 describe-security-groups --region ${var.region} --group-ids \$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)"
      }
      
      # Main execution
      echo "🚀 Starting SSH diagnostics..."
      
      SUCCESS=true
      
      # Run all validation steps
      if ! validate_ssh_key; then
        SUCCESS=false
      fi
      
      if ! validate_instance_key_pair; then
        SUCCESS=false
      fi
      
      if ! test_ssh_connectivity; then
        SUCCESS=false
      fi
      
      if [[ "$SUCCESS" == "true" ]]; then
        echo ""
        echo "✅ SSH diagnostics completed successfully!"
        echo "🎉 SSH connectivity is working properly"
        echo ""
        echo "📋 Connection details:"
        echo "   Command: ssh $SSH_OPTIONS -i \"$SSH_KEY_PATH\" $SSH_USER@$CONTROL_PLANE_IP"
        echo "   Key: $SSH_KEY_PATH"
        echo "   Target: $SSH_USER@$CONTROL_PLANE_IP"
      else
        echo ""
        echo "❌ SSH diagnostics found issues"
        provide_troubleshooting_steps
        echo ""
        echo "⚠️  Note: This diagnostic failure won't stop Terraform deployment"
        echo "    But subsequent SSH-based provisioners may fail"
        echo "    Consider fixing SSH issues before proceeding"
      fi
      
      # Always exit successfully to not block deployment
      exit 0
    EOT
  }
}
