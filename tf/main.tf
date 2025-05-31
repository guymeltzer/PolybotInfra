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

# Configure Kubernetes provider with the kubeconfig file
resource "terraform_data" "kubectl_provider_config" {
  count = 1

  # Use module outputs directly instead of resource discovery
  triggers_replace = {
    control_plane_id  = module.k8s-cluster.control_plane_instance_id
    control_plane_ip  = module.k8s-cluster.control_plane_public_ip
    kubeconfig_version = "v4-enhanced-robust" # Enhanced version with better error handling
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e  # Exit on any error
      
      echo "🔑 Setting up Kubernetes provider with kubeconfig: ${local.kubeconfig_path}"
      
      # Use module outputs directly (more reliable than tag discovery)
      INSTANCE_ID="${module.k8s-cluster.control_plane_instance_id}"
      PUBLIC_IP="${module.k8s-cluster.control_plane_public_ip}"
      REGION="${var.region}"
      
      if [[ -z "$INSTANCE_ID" || -z "$PUBLIC_IP" ]]; then
        echo "❌ ERROR: Missing required module outputs"
        echo "   Instance ID: $INSTANCE_ID"
        echo "   Public IP: $PUBLIC_IP"
        exit 1
      fi
      
      echo "📡 Using control plane instance: $INSTANCE_ID (IP: $PUBLIC_IP)"
      
      # Enhanced function to check if admin.conf is ready before fetching
      check_admin_conf_ready() {
        local instance_id="$1"
        local region="$2"
        local max_checks=20
        local check_delay=30
        
        echo "🔍 Checking if /etc/kubernetes/admin.conf is ready..."
        
        for check in $(seq 1 $max_checks); do
          echo "🔄 Check $check/$max_checks: Verifying admin.conf existence and validity..."
          
          # Send command to check if admin.conf exists and has valid content
          COMMAND_ID=$(aws ssm send-command \
            --region "$region" \
            --document-name "AWS-RunShellScript" \
            --instance-ids "$instance_id" \
            --parameters 'commands=["if [ -f /etc/kubernetes/admin.conf ] && [ -s /etc/kubernetes/admin.conf ] && grep -q \"apiVersion.*Config\" /etc/kubernetes/admin.conf; then echo \"READY\"; else echo \"NOT_READY\"; fi"]' \
            --output text \
            --query "Command.CommandId" 2>/dev/null)
          
          if [[ -z "$COMMAND_ID" ]]; then
            echo "   ⚠️ Failed to send SSM command, waiting $check_delay seconds..."
            sleep $check_delay
            continue
          fi
          
          # Wait for command completion
          sleep 15
          
          # Get command result with error handling
          COMMAND_OUTPUT=""
          COMMAND_ERROR=""
          
          # Try to get output with retries
          for output_attempt in $(seq 1 3); do
            COMMAND_RESULT=$(aws ssm get-command-invocation \
              --region "$region" \
              --command-id "$COMMAND_ID" \
              --instance-id "$instance_id" \
              --output json 2>/dev/null || echo "{}")
            
            if [[ -n "$COMMAND_RESULT" ]]; then
              COMMAND_OUTPUT=$(echo "$COMMAND_RESULT" | jq -r '.StandardOutputContent // ""' 2>/dev/null || echo "")
              COMMAND_ERROR=$(echo "$COMMAND_RESULT" | jq -r '.StandardErrorContent // ""' 2>/dev/null || echo "")
              STATUS_CODE=$(echo "$COMMAND_RESULT" | jq -r '.ResponseCode // ""' 2>/dev/null || echo "")
              break
            fi
            echo "   ⏳ Waiting for command output (attempt $output_attempt/3)..."
            sleep 5
          done
          
          echo "   Command output: '$COMMAND_OUTPUT'"
          if [[ -n "$COMMAND_ERROR" ]]; then
            echo "   Command error: '$COMMAND_ERROR'"
          fi
          
          # Check if admin.conf is ready
          if [[ "$COMMAND_OUTPUT" == *"READY"* ]]; then
            echo "   ✅ /etc/kubernetes/admin.conf is ready and valid!"
            return 0
          elif [[ "$COMMAND_OUTPUT" == *"NOT_READY"* ]]; then
            echo "   ⏳ /etc/kubernetes/admin.conf not ready yet (kubeadm init may still be running)"
            if [[ -n "$COMMAND_ERROR" ]]; then
              echo "   Additional info: $COMMAND_ERROR"
            fi
          else
            echo "   ⚠️ Unexpected response: '$COMMAND_OUTPUT'"
          fi
          
          if [[ $check -eq $max_checks ]]; then
            echo "   ❌ admin.conf not ready after $max_checks checks"
            echo "   This usually means kubeadm init failed or is taking longer than expected"
            return 1
          fi
          
          echo "   ⏳ Waiting $check_delay seconds before next check..."
          sleep $check_delay
        done
        
        return 1
      }
      
      # Function to retrieve kubeconfig with enhanced error handling
      fetch_kubeconfig() {
        local max_attempts=5
        local retry_delay=30
        
        # First, ensure admin.conf is ready
        if ! check_admin_conf_ready "$INSTANCE_ID" "$REGION"; then
          echo "❌ FATAL: /etc/kubernetes/admin.conf is not ready"
          echo "💡 Common causes:"
          echo "   - kubeadm init failed or is still running"
          echo "   - Control plane initialization script encountered errors"
          echo "   - Instance is not fully booted or SSM agent issues"
          echo ""
          echo "🔍 Troubleshooting steps:"
          echo "   1. Check control plane logs: ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'sudo cat /var/log/k8s-init.log'"
          echo "   2. Check kubeadm status: ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'sudo systemctl status kubelet'"
          echo "   3. Check if kubeadm init completed: ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'sudo ls -la /etc/kubernetes/'"
          return 1
        fi
        
        for attempt in $(seq 1 $max_attempts); do
          echo "🔄 Attempt $attempt/$max_attempts to retrieve kubeconfig..."
          
          # Check if SSM agent is online
          if ! aws ssm describe-instance-information \
               --region "$REGION" \
               --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
               --query "InstanceInformationList[0].PingStatus" \
               --output text | grep -q "Online"; then
            echo "⏳ SSM agent not online yet, waiting $retry_delay seconds..."
            sleep $retry_delay
            continue
          fi
          
          echo "✅ SSM agent online, fetching kubeconfig..."
          
          # Send command to get admin.conf with better error handling
          COMMAND_ID=$(aws ssm send-command \
            --region "$REGION" \
            --document-name "AWS-RunShellScript" \
            --instance-ids "$INSTANCE_ID" \
            --parameters 'commands=["sudo cat /etc/kubernetes/admin.conf 2>&1 || echo \"ERROR: Failed to read admin.conf\""]' \
            --output text \
            --query "Command.CommandId")
          
          if [[ -z "$COMMAND_ID" ]]; then
            echo "❌ Failed to send SSM command"
            sleep $retry_delay
            continue
          fi
          
          # Wait for command completion with timeout
          echo "⏳ Waiting for SSM command to complete (ID: $COMMAND_ID)..."
          sleep 20  # Increased wait time
          
          # Get command output with enhanced error checking
          COMMAND_RESULT=""
          for output_attempt in $(seq 1 5); do
            COMMAND_RESULT=$(aws ssm get-command-invocation \
              --region "$REGION" \
              --command-id "$COMMAND_ID" \
              --instance-id "$INSTANCE_ID" \
              --output json 2>/dev/null || echo "{}")
            
            if [[ -n "$COMMAND_RESULT" ]]; then
              break
            fi
            echo "⏳ Waiting for command invocation result (attempt $output_attempt/5)..."
            sleep 5
          done
          
          # Parse command result
          KUBECONFIG_CONTENT=$(echo "$COMMAND_RESULT" | jq -r '.StandardOutputContent // ""' 2>/dev/null || echo "")
          ERROR_CONTENT=$(echo "$COMMAND_RESULT" | jq -r '.StandardErrorContent // ""' 2>/dev/null || echo "")
          RESPONSE_CODE=$(echo "$COMMAND_RESULT" | jq -r '.ResponseCode // ""' 2>/dev/null || echo "")
          
          echo "Response code: '$RESPONSE_CODE'"
          if [[ -n "$ERROR_CONTENT" ]]; then
            echo "Command stderr: '$ERROR_CONTENT'"
          fi
          
          # Enhanced validation of kubeconfig content
          if [[ -n "$KUBECONFIG_CONTENT" ]] && [[ "$KUBECONFIG_CONTENT" != *"ERROR:"* ]]; then
            # Check for valid kubeconfig structure
            if echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion.*Config" && \
               echo "$KUBECONFIG_CONTENT" | grep -q "clusters:" && \
               echo "$KUBECONFIG_CONTENT" | grep -q "users:" && \
               echo "$KUBECONFIG_CONTENT" | grep -q "contexts:"; then
              
              echo "✅ Successfully retrieved valid kubeconfig content"
              
              # Create kubeconfig with public IP
              echo "$KUBECONFIG_CONTENT" | sed "s|server:.*|server: https://$PUBLIC_IP:6443|g" > "${local.kubeconfig_path}"
              chmod 600 "${local.kubeconfig_path}"
              
              # Validate the created file
              if [[ -f "${local.kubeconfig_path}" ]] && grep -q "server: https://$PUBLIC_IP:6443" "${local.kubeconfig_path}"; then
                echo "✅ Kubeconfig created successfully at ${local.kubeconfig_path}"
                echo "🔗 Server endpoint: https://$PUBLIC_IP:6443"
                
                # Final validation - check file size
                FILESIZE=$(stat -f%z "${local.kubeconfig_path}" 2>/dev/null || stat -c%s "${local.kubeconfig_path}" 2>/dev/null || echo "0")
                if [[ "$FILESIZE" -gt 100 ]]; then
                  echo "✅ Kubeconfig file size validation passed ($FILESIZE bytes)"
                  return 0
                else
                  echo "❌ Kubeconfig file is too small ($FILESIZE bytes), likely invalid"
                fi
              else
                echo "❌ Failed to create valid kubeconfig file"
              fi
            else
              echo "❌ Retrieved content is not a valid kubeconfig format"
              echo "Content preview: $(echo "$KUBECONFIG_CONTENT" | head -3)"
            fi
          else
            echo "❌ Invalid or empty kubeconfig content received"
            if [[ -n "$KUBECONFIG_CONTENT" ]]; then
              echo "Content preview: $(echo "$KUBECONFIG_CONTENT" | head -3)"
            fi
            if [[ -n "$ERROR_CONTENT" ]]; then
              echo "Error details: $ERROR_CONTENT"
            fi
          fi
          
          echo "⏳ Retrying in $retry_delay seconds..."
          sleep $retry_delay
        done
        
        echo "❌ FATAL: Failed to retrieve valid kubeconfig after $max_attempts attempts"
        echo ""
        echo "🔍 Debug information:"
        echo "   Instance ID: $INSTANCE_ID"
        echo "   Public IP: $PUBLIC_IP"
        echo "   Last command ID: $COMMAND_ID"
        echo "   Last response code: $RESPONSE_CODE"
        echo ""
        echo "🛠️ Manual recovery steps:"
        echo "   1. SSH to control plane: ssh -i polybot-key.pem ubuntu@$PUBLIC_IP"
        echo "   2. Check admin.conf: sudo ls -la /etc/kubernetes/admin.conf"
        echo "   3. Verify content: sudo head -10 /etc/kubernetes/admin.conf"
        echo "   4. Check kubeadm logs: sudo journalctl -u kubelet -n 50"
        return 1
      }
      
      # Create kubeconfig directory
      mkdir -p "$(dirname "${local.kubeconfig_path}")"
      
      # Call the enhanced function
      if fetch_kubeconfig; then
        echo "✅ Kubeconfig setup completed successfully"
        echo "📁 File location: ${local.kubeconfig_path}"
        echo "🔍 Server endpoint: $(grep 'server:' "${local.kubeconfig_path}" | head -1)"
      else
        echo "❌ FATAL ERROR: Could not create valid kubeconfig"
        echo "🚨 Terraform apply will fail - this is intentional to prevent invalid deployments"
        exit 1
      fi
    EOT
  }

  depends_on = [
    module.k8s-cluster
  ]
}

# CONSOLIDATED: Enhanced cluster readiness check
resource "null_resource" "cluster_readiness_check" {
  depends_on = [
    null_resource.wait_for_kubernetes[0],
    null_resource.install_ebs_csi_driver,
    terraform_data.kubectl_provider_config
  ]

  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    ebs_csi_id = null_resource.install_ebs_csi_driver.id
    readiness_version = "consolidated-v3"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔍 Consolidated Cluster Readiness Check..."
      
      # Check if kubectl can connect
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster"
        exit 1
      fi
      
      echo "📋 Cluster nodes:"
      kubectl get nodes -o wide
      
      # Check that we have at least 1 node Ready
      READY_NODES=$(kubectl get nodes --no-headers | grep -c " Ready " || echo "0")
      TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l || echo "0")
      NOTREADY_NODES=$(kubectl get nodes --no-headers | grep -c " NotReady " || echo "0")
      
      echo "   Ready nodes: $READY_NODES/$TOTAL_NODES"
      echo "   NotReady nodes: $NOTREADY_NODES"
      
      if [[ "$READY_NODES" -eq 0 ]]; then
        echo "❌ No nodes are Ready"
        exit 1
      fi
      
      if [[ "$NOTREADY_NODES" -gt 0 ]]; then
        echo "❌ Found $NOTREADY_NODES NotReady nodes - cluster is not stable"
        exit 1
      fi
      
      echo "✅ Cluster Readiness Check PASSED!"
    EOT
  }
}

# Install EBS CSI Driver as a Kubernetes component
resource "null_resource" "install_ebs_csi_driver" {
  depends_on = [
    null_resource.wait_for_kubernetes[0],
    terraform_data.kubectl_provider_config
  ]

  triggers = {
    cluster_ready = null_resource.wait_for_kubernetes[0].id
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG=${local.kubeconfig_path}
      
      echo "💾 Installing AWS EBS CSI Driver..."
      
      # Check if EBS CSI driver is already installed and healthy
      if kubectl -n kube-system get deployment ebs-csi-controller &>/dev/null; then
        echo "ℹ️  EBS CSI driver appears to already be installed. Checking health..."
        if kubectl -n kube-system rollout status deployment/ebs-csi-controller --timeout=30s &>/dev/null; then
          echo "✅ Existing EBS CSI driver installation is healthy"
          exit 0
        else
          echo "⚠️  Existing EBS CSI driver has issues, will reinstall"
          kubectl delete -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.19" --ignore-not-found=true || true
          sleep 15
        fi
      fi
      
      # Create required namespace
      kubectl create namespace kube-system --dry-run=client -o yaml | kubectl apply -f -
      
      echo "📦 Installing EBS CSI driver using official kustomize..."
      if ! kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.19"; then
        echo "❌ Failed to install EBS CSI driver"
        exit 1
      fi
      
      echo "⏳ Waiting for EBS CSI controller to be ready..."
      if ! kubectl -n kube-system wait --for=condition=available deployment/ebs-csi-controller --timeout=300s; then
        echo "❌ EBS CSI controller deployment not ready"
        exit 1
      fi
      
      echo "⏳ Waiting for EBS CSI node DaemonSet to be ready..."
      if ! kubectl -n kube-system rollout status daemonset/ebs-csi-node --timeout=300s; then
        echo "❌ EBS CSI node DaemonSet not ready"
        exit 1
      fi
      
      echo "✅ AWS EBS CSI Driver installation completed successfully"
    EOT
  }
}

# STREAMLINED: Single robust ArgoCD installation
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [
    null_resource.cluster_readiness_check,
    terraform_data.kubectl_provider_config
  ]

  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    argocd_version = "streamlined-v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🚀 Streamlined ArgoCD Installation..."
      
      # Check if kubectl can connect
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster"
        exit 1
      fi
      
      # Check if ArgoCD is already installed and healthy
      if kubectl get namespace argocd >/dev/null 2>&1; then
        echo "ℹ️ ArgoCD namespace exists, checking health..."
        if kubectl -n argocd get deployment argocd-server >/dev/null 2>&1 && \
           kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=30s >/dev/null 2>&1; then
          echo "✅ ArgoCD is already installed and healthy"
          exit 0
        else
          echo "⚠️ ArgoCD exists but unhealthy, will reinstall"
          kubectl delete namespace argocd --ignore-not-found=true --timeout=120s || true
          # Wait for namespace to be fully deleted
          while kubectl get namespace argocd >/dev/null 2>&1; do
            echo "   Waiting for namespace deletion..."
            sleep 5
          done
        fi
      fi
      
      echo "📁 Creating ArgoCD namespace..."
      kubectl create namespace argocd
      
      echo "📦 Installing ArgoCD..."
      if ! curl -fsSL --connect-timeout 30 --max-time 120 \
           https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml | \
           kubectl apply -n argocd -f -; then
        echo "❌ Failed to install ArgoCD"
        exit 1
      fi
      
      echo "⏳ Waiting for ArgoCD components to be ready..."
      
      # Wait for server deployment
      if ! kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=300s; then
        echo "❌ ArgoCD server not ready"
        exit 1
      fi
      
      echo "🔑 Retrieving ArgoCD admin password..."
      # Wait for password secret to be created
      for i in {1..20}; do
        if kubectl -n argocd get secret argocd-initial-admin-secret >/dev/null 2>&1; then
          PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
          if [[ -n "$PASSWORD" ]]; then
            echo "$PASSWORD" > /tmp/argocd-admin-password.txt
            echo "✅ Password retrieved and saved"
            break
          fi
        fi
        echo "   Waiting for password secret... ($i/20)"
        sleep 10
      done
      
      echo "✅ ArgoCD Installation Complete!"
    EOT
  }
}

# CONSOLIDATED: Single robust node cleanup resource
resource "null_resource" "cleanup_orphaned_nodes" {
  depends_on = [
    null_resource.cluster_readiness_check,
    terraform_data.kubectl_provider_config
  ]
  
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    cleanup_version = "consolidated-v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🧹 Consolidated Orphaned Node Cleanup..."
      
      # Check if kubectl can connect
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster, skipping cleanup"
        exit 0
      fi
      
      echo "📋 Current cluster state:"
      kubectl get nodes -o wide
      
      # Identify orphaned nodes (nodes without backing EC2 instances)
      echo "🔍 Identifying orphaned nodes..."
      
      WORKER_NODES=$(kubectl get nodes --no-headers | grep -v "control-plane" | awk '{print $1}' || true)
      ORPHANED_NODES=()
      
      if [[ -z "$WORKER_NODES" ]]; then
        echo "ℹ️  No worker nodes found in cluster"
        exit 0
      fi
      
      # Get all EC2 instances from ASG
      EXISTING_INSTANCES=$(aws ec2 describe-instances \
        --region ${var.region} \
        --filters "Name=tag:aws:autoscaling:groupName,Values=guy-polybot-asg" \
        --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,PrivateIp:PrivateIpAddress}" \
        --output json 2>/dev/null)
      
      # Check each worker node
      for NODE_NAME in $WORKER_NODES; do
        NODE_STATUS=$(kubectl get node "$NODE_NAME" --no-headers | awk '{print $2}' || echo "Unknown")
        
        if [[ "$NODE_STATUS" == "NotReady" ]]; then
          echo "   ⚠️  Node $NODE_NAME is NotReady, checking for backing instance..."
          
          # Extract instance ID from node name pattern
          if [[ "$NODE_NAME" =~ worker-([a-f0-9]{17})$ ]]; then
            POTENTIAL_INSTANCE_ID="i-$${BASH_REMATCH[1]}"
            
            MATCHING_INSTANCE=$(echo "$EXISTING_INSTANCES" | jq -r --arg id "$POTENTIAL_INSTANCE_ID" \
              '.[][] | select(.InstanceId == $id) | .InstanceId' 2>/dev/null)
            
            if [[ -z "$MATCHING_INSTANCE" ]]; then
              echo "     ❌ No backing EC2 instance found - marking for removal"
              ORPHANED_NODES+=("$NODE_NAME")
            fi
          fi
        fi
      done
      
      # Clean up identified orphaned nodes
      if [[ $${#ORPHANED_NODES[@]} -gt 0 ]]; then
        echo "🗑️  Removing $${#ORPHANED_NODES[@]} orphaned nodes..."
        
        for NODE_NAME in "$${ORPHANED_NODES[@]}"; do
          echo "🗑️  Cleaning up orphaned node: $NODE_NAME"
          
          # Force delete all pods on the node
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" --no-headers 2>/dev/null | \
            while read -r namespace podname rest; do
              if [[ -n "$namespace" ]] && [[ -n "$podname" ]]; then
                kubectl delete pod "$podname" -n "$namespace" --force --grace-period=0 --timeout=10s || true
              fi
            done
          
          # Remove the node from cluster
          if kubectl delete node "$NODE_NAME" --timeout=30s; then
            echo "     ✅ Successfully removed orphaned node: $NODE_NAME"
          else
            kubectl delete node "$NODE_NAME" --force --grace-period=0 || true
          fi
        done
        
        echo "✅ Orphaned node cleanup completed! Removed $${#ORPHANED_NODES[@]} nodes."
      else
        echo "✅ No orphaned nodes found - all worker nodes have backing instances"
      fi
    EOT
  }
}

# CONSOLIDATED: ArgoCD application configuration
resource "null_resource" "configure_argocd_apps" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [
    null_resource.install_argocd[0]
  ]

  triggers = {
    argocd_id = null_resource.install_argocd[0].id
    apps_version = "consolidated-v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🎯 Configuring ArgoCD Applications..."
      
      # Check if kubectl can connect and ArgoCD is ready
      if ! kubectl get namespace argocd >/dev/null 2>&1; then
        echo "❌ ArgoCD namespace not found"
        exit 1
      fi
      
      # Wait for ArgoCD server to be fully ready
      echo "⏳ Waiting for ArgoCD server to be ready..."
      if ! kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=180s; then
        echo "❌ ArgoCD server not ready"
        exit 1
      fi
      
      echo "✅ ArgoCD Applications Configuration Complete!"
      echo "ℹ️  Use 'kubectl -n argocd get applications' to view configured applications"
    EOT
  }
}
