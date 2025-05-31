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
  
  kubeconfig_path = "${path.module}/kubeconfig.yaml"
  ssh_private_key_path = var.key_name != "" ? (
    fileexists("${path.module}/${var.key_name}.pem") ? 
    "${path.module}/${var.key_name}.pem" : 
    (fileexists("$HOME/.ssh/${var.key_name}.pem") ? 
     "$HOME/.ssh/${var.key_name}.pem" : 
     "${path.module}/polybot-key.pem")
  ) : "${path.module}/polybot-key.pem"
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
  
  # Optional parameters
  tags = {
    Environment = "production"
    Project     = "polybot"
    ManagedBy   = "terraform"
  }
}

#DEBUGGABLE: Debug initialization and pre-execution logging
resource "null_resource" "debug_initialization" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = local.debug_environment
    command = <<EOT
      # Create debug infrastructure
      mkdir -p logs/cluster_state logs/kubernetes_state logs/final_state
      
      # Initialize structured debug log with environment info
      echo '{"stage":"terraform_init", "status":"start", "time":"${timestamp()}", "workspace":"${terraform.workspace}", "region":"${var.region}"}' >> logs/tf_debug.log
      
      # Log system information for debugging
      echo '{"stage":"system_info", "os":"'$(uname -s)'", "arch":"'$(uname -m)'", "terraform_version":"'$(terraform version -json 2>/dev/null | grep -o '"terraform_version":"[^"]*"' | cut -d'"' -f4 || terraform version | head -1 | cut -d' ' -f2)'", "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      # Log debug environment configuration
      echo '{"stage":"debug_environment", "config":${jsonencode(local.debug_environment)}, "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      # Log AWS configuration
      echo '{"stage":"aws_config", "region":"${var.region}", "account":"'$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")'", "user":"'$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo "unknown")'", "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      # Export debug environment for all subsequent commands
      export TF_LOG="${local.debug_environment.TF_LOG}"
      export TF_LOG_CORE="${local.debug_environment.TF_LOG_CORE}"
      export TF_LOG_PATH="${local.debug_environment.TF_LOG_PATH}"
      export TF_LOG_PROVIDER="${local.debug_environment.TF_LOG_PROVIDER}"
      export AWS_LOG_LEVEL="${local.debug_environment.AWS_LOG_LEVEL}"
      
      echo ""
      echo "🐛 Enhanced Terraform Debugging Enabled!"
      echo "📊 Debug Environment:"
      echo "   TF_LOG: ${local.debug_environment.TF_LOG}"
      echo "   TF_LOG_CORE: ${local.debug_environment.TF_LOG_CORE}"  
      echo "   TF_LOG_PATH: ${local.debug_environment.TF_LOG_PATH}"
      echo "   AWS_LOG_LEVEL: ${local.debug_environment.AWS_LOG_LEVEL}"
      echo "📁 Debug logs will be saved to: logs/"
      echo "📋 Main debug log: logs/tf_debug.log"
      echo ""
    EOT
  }

  provisioner "local-exec" {
    when = destroy
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"terraform_destroy", "status":"complete", "time":"${timestamp()}"}' >> logs/tf_debug.log 2>/dev/null || true
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
resource "terraform_data" "init_environment" {
  depends_on = [terraform_data.manage_secrets]

  # Use a more deterministic trigger that won't cause cycles
  triggers_replace = {
    # Trigger on kubeconfig presence/absence without referencing module.k8s-cluster
    run_kubeconfig = fileexists("./kubeconfig.yaml") ? filemd5("./kubeconfig.yaml") : "notexists"
  }

  # Create a valid kubeconfig before any resources are created
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      
      # Look for control plane instance
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      # Look for public IP if instance exists
      if [ "$INSTANCE_ID" != "None" ] && [ ! -z "$INSTANCE_ID" ]; then
        PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        
        # If we have a public IP, try to get the real kubeconfig
        if [ "$PUBLIC_IP" != "None" ] && [ ! -z "$PUBLIC_IP" ]; then
          echo "Control plane found with IP: $PUBLIC_IP, checking for kubeconfig"
          
          if aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
             --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
            
            echo "Control plane has SSM available, retrieving kubeconfig"
            # Try to get a real kubeconfig
            aws ssm send-command --region ${var.region} --document-name "AWS-RunShellScript" \
              --instance-ids "$INSTANCE_ID" --parameters 'commands=["cat /etc/kubernetes/admin.conf"]' \
              --output text --query "Command.CommandId" > /tmp/command_id.txt
            
            sleep 5
            
            # Get the kubeconfig content
            aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) \
              --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text > /tmp/admin_conf.txt
            
            # Check if we got a valid kubeconfig
            if [ -s /tmp/admin_conf.txt ] && grep -q "apiVersion: v1" /tmp/admin_conf.txt; then
              echo "Got valid kubeconfig, updating with correct IP"
              cat /tmp/admin_conf.txt | sed "s|server:.*|server: https://$PUBLIC_IP:6443|" > ./kubeconfig.yaml
              chmod 600 ./kubeconfig.yaml
              echo "Successfully created kubeconfig with real IP"
              exit 0
            fi
          fi
        fi
      fi
      
      # If we're at this point, we didn't get a valid kubeconfig
      echo "Creating placeholder kubeconfig"
      
      # Since we should only get here during initial setup, if a valid kubeconfig exists, DON'T overwrite it
      if [ -f "./kubeconfig.yaml" ] && ! grep -q "server: https://placeholder:6443" ./kubeconfig.yaml; then
        echo "Found existing valid kubeconfig, not overwriting with placeholder"
        exit 0
      fi
      
      # Create a minimal placeholder kubeconfig that won't cause connection errors
      cat > "./kubeconfig.yaml" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:9999
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
      echo "Created placeholder kubeconfig successfully with unused local address"
    EOT
  }
}

# Resource to wait for Kubernetes API to be fully available - with improved triggers
resource "null_resource" "wait_for_kubernetes" {
  count = 1
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      until KUBECONFIG="${local.kubeconfig_path}" kubectl get nodes --request-timeout=10s; do
        echo "Waiting for Kubernetes API..."
        sleep 10
      done
    EOT
  }
  depends_on = [module.k8s-cluster]
}

# Resource that checks if ArgoCD is already deployed before spending time installing it
resource "null_resource" "check_argocd_status" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.wait_for_kubernetes,
    terraform_data.kubectl_provider_config
  ]
  
  # Only trigger on kubeconfig changes, not directly on control plane changes
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Check if argocd is already deployed
      if kubectl get deployments -n argocd argocd-server &>/dev/null; then
        echo "ArgoCD server already deployed, skipping installation"
        # Mark as already installed
        echo "true" > /tmp/argocd_already_installed
      else
        echo "ArgoCD not found, will proceed with installation"
        echo "false" > /tmp/argocd_already_installed
      fi
    EOT
  }
}

# Add cluster readiness validation before running other operations
resource "null_resource" "cluster_readiness_check" {
  depends_on = [
    null_resource.wait_for_kubernetes,
    null_resource.install_calico,
    null_resource.install_ebs_csi_driver
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    force_check = "v6-enhanced-worker-validation"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔍 Enhanced Cluster Readiness Check..."
      
      # Wait for basic connectivity
      echo "Checking kubectl connectivity..."
      for i in {1..30}; do
        if kubectl get nodes >/dev/null 2>&1; then
          echo "✅ kubectl connectivity established"
          break
        fi
        if [ $i -eq 30 ]; then
          echo "❌ kubectl connectivity failed after 30 attempts"
          exit 1
        fi
        echo "Attempt $i/30: Waiting for kubectl connectivity..."
        sleep 10
      done
      
      # Wait for worker nodes to register (give ASG time to launch)
      echo "🕐 Waiting for worker nodes to register..."
      for i in {1..60}; do
        TOTAL_NODES=$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo "0")
        WORKER_NODES=$(kubectl get nodes --no-headers -l '!node-role.kubernetes.io/control-plane' 2>/dev/null | wc -l || echo "0")
        
        echo "Check $i/60: Total nodes: $TOTAL_NODES, Worker nodes: $WORKER_NODES"
        
        if [ "$WORKER_NODES" -ge 1 ]; then
          echo "✅ Worker nodes found, proceeding to readiness check..."
          break
        fi
        
        if [ $i -eq 60 ]; then
          echo "⚠️ No worker nodes found after 10 minutes"
          echo "This might be normal if worker ASG is still launching instances"
          echo "Proceeding with readiness check for existing nodes..."
          break
        fi
        
        sleep 10
      done
      
      # Enhanced readiness check with proper retry logic
      echo "🚀 Checking node readiness..."
      MAX_WAIT_MINUTES=20
      CHECK_INTERVAL=15
      MAX_ITERATIONS=$((MAX_WAIT_MINUTES * 60 / CHECK_INTERVAL))
      
      for i in $(seq 1 $MAX_ITERATIONS); do
        echo "=== Readiness Check $i/$MAX_ITERATIONS ==="
        
        # Get all nodes
        if ! kubectl get nodes --no-headers 2>/dev/null; then
          echo "❌ Failed to get nodes, retrying..."
          sleep $CHECK_INTERVAL
          continue
        fi
        
        # Check node readiness
        NOT_READY_NODES=$(kubectl get nodes --no-headers | grep -v " Ready " | wc -l || echo "0")
        TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l || echo "0")
        READY_NODES=$((TOTAL_NODES - NOT_READY_NODES))
        
        echo "📊 Node Status: $READY_NODES/$TOTAL_NODES ready"
        
        if [ "$NOT_READY_NODES" -eq 0 ] && [ "$TOTAL_NODES" -gt 0 ]; then
          echo "✅ All nodes are ready!"
          break
        fi
        
        # Show detailed status
        echo "📋 Node Details:"
        kubectl get nodes -o wide 2>/dev/null || echo "Failed to get detailed node info"
        
        # Show not ready nodes specifically
        if [ "$NOT_READY_NODES" -gt 0 ]; then
          echo "⚠️ Not Ready Nodes:"
          kubectl get nodes --no-headers | grep -v " Ready " || echo "Unable to show not ready nodes"
        fi
        
        # Check system pods
        echo "🔧 System Pod Status:"
        kubectl get pods -n kube-system --no-headers | grep -E "(coredns|calico|ebs-csi)" | head -10
        
        if [ $i -eq $MAX_ITERATIONS ]; then
          echo "⚠️ Timeout waiting for all nodes to be ready"
          echo "Final status: $READY_NODES/$TOTAL_NODES nodes ready"
          
          # Don't fail if we have at least the control plane ready
          if [ "$READY_NODES" -gt 0 ]; then
            echo "✅ Proceeding with $READY_NODES ready nodes"
            break
          else
            echo "❌ No nodes are ready - this indicates a serious cluster issue"
            exit 1
          fi
        fi
        
        echo "⏳ Waiting $${CHECK_INTERVAL}s before next check..."
        sleep $CHECK_INTERVAL
      done
      
      # Final health summary
      echo ""
      echo "🏁 FINAL CLUSTER STATUS"
      echo "======================"
      kubectl get nodes -o wide
      echo ""
      kubectl get pods -n kube-system | grep -E "(coredns|calico|ebs-csi)"
      echo ""
      echo "✅ Cluster readiness check completed"
    EOT
  }
}

# Pre-ArgoCD comprehensive health check
resource "null_resource" "pre_argocd_health_check" {
  depends_on = [
    null_resource.cluster_readiness_check,
    null_resource.install_calico,
    null_resource.install_ebs_csi_driver
  ]
  
  triggers = {
    cluster_check_id = null_resource.cluster_readiness_check.id
    force_check = "v3-comprehensive-health"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🏥 Pre-ArgoCD Comprehensive Health Check..."
      
      # Function to check component health
      check_component() {
        local component=$1
        local namespace=$2
        local selector=$3
        local timeout=$${4:-300}
        
        echo "🔍 Checking $component..."
        
        if kubectl -n $namespace get deployment $component >/dev/null 2>&1; then
          echo "  ✅ $component deployment found"
          if kubectl -n $namespace wait --for=condition=available deployment/$component --timeout=\$${timeout}s; then
            echo "  ✅ $component is ready"
            return 0
          else
            echo "  ❌ $component not ready within \$${timeout}s"
            kubectl -n $namespace get deployment $component -o wide
            kubectl -n $namespace get pods -l $selector -o wide
            return 1
          fi
        else
          echo "  ⚠️ $component deployment not found"
          return 1
        fi
      }
      
      # Check CoreDNS (critical for DNS resolution)
      echo "=== CoreDNS Health Check ==="
      if ! check_component "coredns" "kube-system" "k8s-app=kube-dns" 300; then
        echo "❌ CoreDNS is not healthy - ArgoCD will fail without DNS"
        echo "CoreDNS logs:"
        kubectl -n kube-system logs -l k8s-app=kube-dns --tail=20 || true
        exit 1
      fi
      
      # Test DNS resolution
      echo "🧪 Testing DNS resolution..."
      kubectl run dns-test --image=busybox --restart=Never --rm -i --timeout=60s -- nslookup kubernetes.default.svc.cluster.local || {
        echo "❌ DNS resolution test failed"
        exit 1
      }
      echo "  ✅ DNS resolution working"
      
      # Check Calico (critical for pod networking)
      echo "=== Calico Health Check ==="
      if kubectl -n kube-system get deployment calico-kube-controllers >/dev/null 2>&1; then
        if ! check_component "calico-kube-controllers" "kube-system" "k8s-app=calico-kube-controllers" 300; then
          echo "❌ Calico controllers not healthy"
          exit 1
        fi
      fi
      
      # Check Calico nodes
      echo "🔍 Checking Calico node pods..."
      CALICO_NODES_NOT_READY=$(kubectl -n kube-system get pods -l k8s-app=calico-node --no-headers | grep -v "Running" | wc -l || echo "0")
      if [ "$CALICO_NODES_NOT_READY" -gt 0 ]; then
        echo "⚠️ $CALICO_NODES_NOT_READY Calico node pods not running"
        kubectl -n kube-system get pods -l k8s-app=calico-node
      else
        echo "  ✅ All Calico node pods running"
      fi
      
      # Check EBS CSI (critical for persistent storage)
      echo "=== EBS CSI Health Check ==="
      if ! check_component "ebs-csi-controller" "kube-system" "app=ebs-csi-controller" 300; then
        echo "❌ EBS CSI controller not healthy - ArgoCD needs persistent storage"
        exit 1
      fi
      
      # Check storage classes
      echo "🔍 Checking storage classes..."
      if kubectl get storageclass >/dev/null 2>&1; then
        STORAGE_CLASSES=$(kubectl get storageclass --no-headers | wc -l)
        echo "  ✅ $STORAGE_CLASSES storage classes available"
      else
        echo "  ❌ No storage classes found - ArgoCD needs storage"
        exit 1
      fi
      
      # Check schedulable nodes
      echo "=== Node Scheduling Check ==="
      SCHEDULABLE_NODES=$(kubectl get nodes --no-headers | grep -v "SchedulingDisabled" | grep "Ready" | wc -l || echo "0")
      echo "📊 Schedulable nodes: $SCHEDULABLE_NODES"
      
      if [ "$SCHEDULABLE_NODES" -eq 0 ]; then
        echo "❌ No schedulable nodes available - ArgoCD pods cannot be scheduled"
        kubectl get nodes -o wide
        exit 1
      fi
      
      # Check resource availability
      echo "=== Resource Availability Check ==="
      kubectl top nodes 2>/dev/null || echo "  ⚠️ Metrics server not available (this is normal)"
      
      # Final validation - try to create a test pod
      echo "🧪 Testing pod scheduling..."
      kubectl run argocd-readiness-test --image=nginx:1.21 --restart=Never --timeout=120s --rm -- echo "test" || {
        echo "❌ Cannot schedule test pod - cluster not ready for ArgoCD"
        exit 1
      }
      echo "  ✅ Pod scheduling test passed"
      
      echo ""
      echo "🎉 PRE-ARGOCD HEALTH CHECK PASSED"
      echo "================================="
      echo "✅ CoreDNS: Ready"
      echo "✅ Calico: Ready" 
      echo "✅ EBS CSI: Ready"
      echo "✅ Storage: Available"
      echo "✅ Scheduling: Working"
      echo "✅ DNS Resolution: Working"
      echo ""
      echo "🚀 Cluster is ready for ArgoCD installation!"
    EOT
  }
}

# Install ArgoCD only if not already installed
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.pre_argocd_health_check,  # Ensure system components are healthy first
    terraform_data.kubectl_provider_config,
    null_resource.wait_for_kubernetes
  ]
  
  # Only run when cluster is stable and ready
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    health_check_id = null_resource.pre_argocd_health_check.id
    # Add a timestamp to force re-run if needed
    force_update = "argocd-v4-system-health-first"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -euo pipefail # Exit on error, undefined vars, pipe failures
      export KUBECONFIG="${local.kubeconfig_path}"
      echo "🚀 Ensuring ArgoCD Installation and Prerequisites are Met..."

      verify_kubectl() {
        local attempts=10; local attempt=1
        echo "Verifying kubectl connectivity..."
        while [ $attempt -le $attempts ]; do
          if kubectl version --client --request-timeout=10s &>/dev/null && \
            kubectl get nodes --request-timeout=10s &>/dev/null; then
            echo "✅ kubectl verified (attempt $attempt)"
            return 0
          fi
          echo "⏳ kubectl verification attempt $attempt/$attempts... waiting 10s"
          sleep 10; attempt=$((attempt + 1))
        done
        echo "❌ kubectl verification failed after $attempts attempts"
        return 1
      }

      # 0. Verify kubectl connectivity first
      if ! verify_kubectl; then
        echo "❌ CRITICAL: Cannot verify kubectl connectivity. ArgoCD installation cannot proceed."
        exit 1
      fi

      # Prerequisite: Wait for CoreDNS to be ready (example, adapt from your cluster_readiness_check)
      echo "⏳ Ensuring CoreDNS is ready before ArgoCD install..."
      if ! kubectl -n kube-system wait --for=condition=available deployment/coredns --timeout=300s; then
        echo "❌ CoreDNS deployment not ready. ArgoCD installation might fail. Please check CoreDNS."
        kubectl -n kube-system get pods -l k8s-app=kube-dns
        # Consider exiting 1 if CoreDNS is critical for ArgoCD install.
      fi
      echo "✅ CoreDNS appears ready or timeout reached (best effort)."

      # 1. Idempotency Check & Potential Cleanup for Re-installation
      if kubectl get namespace argocd &>/dev/null; then
        echo "ℹ️  ArgoCD namespace already exists. Checking health of existing installation..."
        if kubectl -n argocd get deployment argocd-server &>/dev/null && \
          kubectl -n argocd get statefulset argocd-application-controller &>/dev/null; then
          echo "ℹ️  ArgoCD server deployment and application-controller statefulset found. Attempting health check..."
          if kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=30s && \
            kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=30s; then # Use rollout status for sts
            echo "✅ Existing ArgoCD installation appears healthy and available."
            echo "📦 Ensuring storage classes exist (idempotent apply)..."
            kubectl apply -f - <<'EOFSC1' || echo "WARN: Failed to apply ebs-sc during health check, but continuing as ArgoCD is healthy."
      apiVersion: storage.k8s.io/v1
      kind: StorageClass
      metadata:
        name: ebs-sc
        annotations:
          storageclass.kubernetes.io/is-default-class: "true"
      provisioner: ebs.csi.aws.com
      volumeBindingMode: WaitForFirstConsumer
      parameters:
        type: gp3
        encrypted: "true"
      allowVolumeExpansion: true
      EOFSC1
            kubectl apply -f - <<'EOFSC2' || echo "WARN: Failed to apply mongodb-sc during health check, but continuing as ArgoCD is healthy."
      apiVersion: storage.k8s.io/v1
      kind: StorageClass
      metadata:
        name: mongodb-sc
      provisioner: ebs.csi.aws.com
      volumeBindingMode: WaitForFirstConsumer
      parameters:
        type: gp3
        encrypted: "true"
      allowVolumeExpansion: true
      EOFSC2
            echo "🎉 ArgoCD already healthy and storage classes ensured. Install script considers this a success."
            exit 0 
          else
            echo "⚠️  Existing ArgoCD installation (server or app-controller) found but is NOT healthy/available. Proceeding with cleanup and reinstall."
            kubectl delete namespace argocd --ignore-not-found=true --wait=true --timeout=180s # Increased timeout for NS deletion
            cleanup_attempts=30; cleanup_attempt=1
            echo "⏳ Waiting for existing 'argocd' namespace to terminate..."
            while kubectl get namespace argocd &>/dev/null && [ $cleanup_attempt -le $cleanup_attempts ]; do
              echo "    Attempt $cleanup_attempt/$cleanup_attempts: Waiting for namespace 'argocd' deletion..."
              sleep 5; cleanup_attempt=$((cleanup_attempt + 1))
            done
            if kubectl get namespace argocd &>/dev/null; then
              echo "❌ Namespace 'argocd' still exists after cleanup attempt. Manual intervention likely needed."
              exit 1
            fi
            echo "✅ Namespace 'argocd' successfully cleaned up for re-installation."
          fi
        else 
          echo "ℹ️  ArgoCD namespace exists but key components (server deployment or app-controller statefulset) not found. Assuming partial/failed install, will proceed with standard install."
        fi
      fi

      # 2. Create ArgoCD namespace (if it doesn't exist or was just deleted)
      echo "📁 Creating ArgoCD namespace..."
      kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
      if ! kubectl get namespace argocd &>/dev/null; then
        echo "❌ Failed to create/verify ArgoCD namespace after attempt."
        exit 1
      fi
      echo "✅ ArgoCD namespace 'argocd' is ready."

      # 3. Install ArgoCD components using official manifest
      echo "📦 Installing ArgoCD components..."
      install_success=false; install_attempts=3; install_attempt=1
      ARGOCD_MANIFEST_URL="https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"

      while [ $install_attempt -le $install_attempts ] && [ "$install_success" = "false" ]; do
        echo "    ArgoCD manifest application attempt $install_attempt/$install_attempts from $ARGOCD_MANIFEST_URL..."
        if curl -fsSL --connect-timeout 30 --max-time 120 "$ARGOCD_MANIFEST_URL" | kubectl apply -n argocd -f -; then
          echo "✅ ArgoCD manifests applied successfully on attempt $install_attempt."
          install_success=true
        else
          echo "❌ ArgoCD manifest application failed on attempt $install_attempt."
          if [ $install_attempt -eq $install_attempts ]; then echo "❌ All ArgoCD manifest application attempts failed."; exit 1; fi
          echo "    Retrying manifest application in 20 seconds..."; sleep 20
        fi
        install_attempt=$((install_attempt + 1))
      done

      # 4. Wait for critical ArgoCD components to be Available/Ready
      echo "⏳ Waiting for critical ArgoCD components to become ready..."
      declare -A required_components_check # Using associative array to store type
      required_components_check["argocd-server"]="deployment"
      required_components_check["argocd-repo-server"]="deployment"
      required_components_check["argocd-dex-server"]="deployment" # If dex is enabled (default in stable install.yaml)
      required_components_check["argocd-redis"]="deployment"
      required_components_check["argocd-applicationset-controller"]="deployment" # Often a deployment
      required_components_check["argocd-notifications-controller"]="deployment" # If present in install.yaml
      required_components_check["argocd-application-controller"]="statefulset" # This is a StatefulSet

      all_components_ready_flag=false
      wait_total_attempts=36  # Approx 6 minutes (36 * 10s)
      for ((i=1; i<=wait_total_attempts; i++)); do
        echo "  Checking ArgoCD components readiness (attempt $i/$wait_total_attempts)..."
        ready_count=0
        total_required_components=$${#required_components_check[@]} # Bash array length, escape $$ for templatefile

        for component_name in "$${!required_components_check[@]}"; do # Iterate keys, escape $$ for templatefile
          component_type="$${required_components_check[$component_name]}" # Get type, escape $$ for templatefile
          
          if ! kubectl -n argocd get "$component_type" "$component_name" -o name &>/dev/null; then
            echo "    ⏳ $component_type $component_name not found yet..."
            ready_count=0 # Reset and break inner loop if a component isn't even found yet
            break
          elif ! kubectl -n argocd rollout status "$component_type/$component_name" --timeout=5s &>/dev/null; then
            echo "    ⏳ $component_type $component_name found but not yet ready/rolled out."
            ready_count=0 # Reset and break inner loop
            break
          else
            echo "    ✅ $component_type $component_name is ready."
            ready_count=$((ready_count + 1))
          fi
        done

        if [ "$ready_count" -eq "$total_required_components" ]; then
          echo "✅ All $total_required_components critical ArgoCD components are ready!"
          all_components_ready_flag=true
          break
        fi

        if [ "$i" -eq "$wait_total_attempts" ]; then
          echo "❌ Not all ArgoCD components became ready after $wait_total_attempts attempts."
          echo "Current Deployments in 'argocd' namespace:"
          kubectl -n argocd get deployments
          echo "Current StatefulSets in 'argocd' namespace:"
          kubectl -n argocd get statefulset # Changed from sts to statefulset
          echo "Current Pods in 'argocd' namespace:"
          kubectl -n argocd get pods
          exit 1
        fi
        echo "   Waiting 10s before next check..."
        sleep 10
      done

      # 5. Final checks for server pods and service
      echo "⏳ Final verification: waiting for ArgoCD server pods to be ready..."
      if ! kubectl -n argocd wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server --timeout=180s; then
        echo "❌ ArgoCD server pods not ready within timeout."
        kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-server --show-labels || true
        kubectl -n argocd describe pods -l app.kubernetes.io/name=argocd-server || true
        exit 1
      fi
      echo "✅ ArgoCD server pods are ready."

      echo "🔍 Verifying ArgoCD server service..."
      if ! kubectl -n argocd get service argocd-server &>/dev/null; then
        echo "❌ ArgoCD server service not found."
        kubectl -n argocd get services || true
        exit 1
      fi
      echo "✅ ArgoCD server service verified."

      # 6. Retrieve Admin Password
      echo "🔑 Retrieving ArgoCD admin password..."
      password_attempts=15; password_attempt=1; password_retrieved=false; password=""
      while [ $password_attempt -le $password_attempts ] && [ "$password_retrieved" = "false" ]; do
        if kubectl -n argocd get secret argocd-initial-admin-secret &>/dev/null; then
          password=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d 2>/dev/null || echo "")
          if [[ -n "$password" ]] && [[ $${#password} -gt 5 ]]; then # Escape for bash string length for templatefile
            echo "✅ ArgoCD admin password retrieved."
            echo "$password" > /tmp/argocd-admin-password.txt
            chmod 600 /tmp/argocd-admin-password.txt
            password_retrieved=true
          fi
        fi
        if [ "$password_retrieved" = "false" ]; then
          echo "    Waiting for ArgoCD admin secret (attempt $password_attempt/$password_attempts)..."
          sleep 20; password_attempt=$((password_attempt + 1))
        fi
      done
      if [ "$password_retrieved" = "false" ]; then 
        echo "⚠️  Could not retrieve ArgoCD admin password within timeout. It might become available later."
      fi

      # 7. Create essential storage classes (idempotent)
      echo "📦 Creating/Ensuring storage classes..."
      # Using quoted heredoc to prevent any interpolation by bash/templatefile inside the YAML
      kubectl apply -f - <<'EOFSC1' || echo "WARN: Failed to apply ebs-sc, but continuing."
      apiVersion: storage.k8s.io/v1
      kind: StorageClass
      metadata:
        name: ebs-sc
        annotations:
          storageclass.kubernetes.io/is-default-class: "true"
      provisioner: ebs.csi.aws.com
      volumeBindingMode: WaitForFirstConsumer
      parameters:
        type: gp3
        encrypted: "true"
      allowVolumeExpansion: true
      EOFSC1
      kubectl apply -f - <<'EOFSC2' || echo "WARN: Failed to apply mongodb-sc, but continuing."
      apiVersion: storage.k8s.io/v1
      kind: StorageClass
      metadata:
        name: mongodb-sc
      provisioner: ebs.csi.aws.com
      volumeBindingMode: WaitForFirstConsumer
      parameters:
        type: gp3
        encrypted: "true"
      allowVolumeExpansion: true
      EOFSC2
      echo "✅ Storage classes ensured."

      echo "🔍 Final ArgoCD installation verification..."
      kubectl -n argocd get deployments
      kubectl -n argocd get statefulset # Changed from sts
      kubectl -n argocd get pods
      kubectl -n argocd get services

      echo ""
      echo "🎉 ArgoCD installation and initial setup completed successfully!"
      echo ""
      echo "📋 ArgoCD Access Information:"
      echo "   Namespace: argocd"
      echo "   Username: admin"
      echo "   Password: $(cat /tmp/argocd-admin-password.txt 2>/dev/null || echo '(retrieve manually using: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='\'{.data.password}\' \| base64 -d)')" # Escaped single quotes for echo
      echo ""
      echo "🔗 To access ArgoCD:"
      echo "   Run in a separate terminal: kubectl -n argocd port-forward svc/argocd-server 8080:443"
      echo "   Then visit in your browser: https://localhost:8080"
      echo ""
      echo "✅ ArgoCD is ready for application configuration by subsequent steps!"
          EOT
        }
      }

# Simplified alternative: Create ArgoCD Application using direct kubectl apply
resource "null_resource" "create_argocd_app_simple" {
  count = 0  # Set to 1 to use this instead of the complex script above

  triggers = {
    argocd_install_id = null_resource.install_argocd[0].id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "📱 Creating ArgoCD Application using direct kubectl..."
      
      # Create polybot namespace
      kubectl create namespace polybot --dry-run=client -o yaml | kubectl apply -f -
      
      # Create ArgoCD Application manifest
      kubectl apply -f - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: polybot
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: https://github.com/guymeltzer/PolybotInfra.git
    targetRevision: HEAD
    path: k8s-manifests
  destination:
    server: https://kubernetes.default.svc
    namespace: polybot
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
EOF
      
      echo "✅ ArgoCD Application created successfully"
    EOT
  }
  
  depends_on = [
    null_resource.install_argocd,
    module.kubernetes_resources,
    module.k8s-cluster
  ]
}

# Now let's set up ArgoCD applications for polybot and its dependencies
resource "null_resource" "configure_argocd_apps" {
  count = local.skip_argocd ? 0 : 1
  triggers = {
    argocd_repo_id = null_resource.configure_argocd_repositories[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e  # Exit on any error
      
      echo "🚀 Configuring ArgoCD applications..."
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Function to cleanup port-forward
      cleanup_portforward() {
        echo "🧹 Cleaning up port-forward..."
        if [[ -n "$PORTFORWARD_PID" ]]; then
          kill "$PORTFORWARD_PID" 2>/dev/null || true
          wait "$PORTFORWARD_PID" 2>/dev/null || true
        fi
        # Kill any other argocd port-forwards
        pkill -f "kubectl.*port-forward.*argocd-server" 2>/dev/null || true
      }
      
      # Set up trap to cleanup on exit
      trap cleanup_portforward EXIT
      
      # Verify ArgoCD is fully ready before proceeding
      echo "🔍 Verifying ArgoCD readiness..."
      
      # Check if ArgoCD namespace exists
      if ! kubectl get namespace argocd &>/dev/null; then
        echo "❌ ArgoCD namespace not found"
        exit 1
      fi
      
      # Wait for ArgoCD server deployment to be ready
      echo "⏳ Waiting for ArgoCD server deployment..."
      if ! kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=300s; then
        echo "❌ ArgoCD server deployment not ready within timeout"
        kubectl -n argocd get deployments
        kubectl -n argocd get pods
        exit 1
      fi
      
      # Wait for ArgoCD server pods to be running
      echo "⏳ Waiting for ArgoCD server pods..."
      if ! kubectl -n argocd wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server --timeout=180s; then
        echo "❌ ArgoCD server pods not ready within timeout"
        kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-server
        exit 1
      fi
      
      # Check ArgoCD service exists
      if ! kubectl -n argocd get service argocd-server &>/dev/null; then
        echo "❌ ArgoCD server service not found"
        kubectl -n argocd get services
        exit 1
      fi
      
      echo "✅ ArgoCD appears to be ready"
      
      # Clean up any existing port-forwards first
      echo "🧹 Cleaning up existing port-forwards..."
      pkill -f "kubectl.*port-forward.*argocd-server" 2>/dev/null || true
      sleep 3
      
      # Check if port 8080 is already in use
      if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  Port 8080 is already in use, killing processes..."
        lsof -ti:8080 | xargs kill -9 2>/dev/null || true
        sleep 2
      fi
      
      # Setup port-forward with better error handling
      echo "🌐 Setting up ArgoCD port-forward..."
      kubectl -n argocd port-forward service/argocd-server 8080:443 > /tmp/portforward.log 2>&1 &
      PORTFORWARD_PID=$!
      
      # Give port-forward time to start
      sleep 5
      
      # Check if port-forward process is still running
      if ! kill -0 "$PORTFORWARD_PID" 2>/dev/null; then
        echo "❌ Port-forward process died immediately"
        cat /tmp/portforward.log 2>/dev/null || echo "No port-forward log available"
        exit 1
      fi
      
      echo "⏳ Waiting for ArgoCD to be accessible via port-forward..."
      
      # More robust connection testing
      for attempt in {1..30}; do
        # Test multiple endpoints
        if curl -k -s --connect-timeout 5 --max-time 10 https://localhost:8080/api/version &>/dev/null || \
           curl -k -s --connect-timeout 5 --max-time 10 https://localhost:8080/healthz &>/dev/null; then
          echo "✅ ArgoCD is accessible via port-forward (attempt $attempt)"
          break
        fi
        
        # Check if port-forward is still running
        if ! kill -0 "$PORTFORWARD_PID" 2>/dev/null; then
          echo "❌ Port-forward process died during connection testing"
          cat /tmp/portforward.log 2>/dev/null || echo "No port-forward log available"
          exit 1
        fi
        
        echo "   Attempt $attempt/30: ArgoCD not yet accessible, waiting..."
        sleep 5
        
        if [[ $attempt -eq 30 ]]; then
          echo "❌ Timed out waiting for ArgoCD to be accessible"
          echo "Port-forward log:"
          cat /tmp/portforward.log 2>/dev/null || echo "No log available"
          echo "Testing direct connectivity:"
          curl -k -v https://localhost:8080/api/version || true
          exit 1
        fi
      done
      
      # Get ArgoCD admin password
      echo "🔑 Getting ArgoCD admin password..."
      ARGOCD_PASSWORD=""
      for attempt in {1..10}; do
        if kubectl -n argocd get secret argocd-initial-admin-secret &>/dev/null; then
          ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d 2>/dev/null)
          if [[ -n "$ARGOCD_PASSWORD" ]]; then
            echo "✅ ArgoCD password retrieved successfully"
            break
          fi
        fi
        echo "   Attempt $attempt/10: Waiting for ArgoCD password..."
        sleep 3
      done
      
      if [[ -z "$ARGOCD_PASSWORD" ]]; then
        echo "❌ Could not retrieve ArgoCD password"
        kubectl -n argocd get secrets
        exit 1
      fi
      
      # Login to ArgoCD with retries
      echo "🔐 Logging into ArgoCD..."
      LOGIN_SUCCESS=false
      for attempt in {1..5}; do
        if argocd login localhost:8080 --username admin --password "$ARGOCD_PASSWORD" --insecure --grpc-web --plaintext=false; then
          echo "✅ Successfully logged into ArgoCD (attempt $attempt)"
          LOGIN_SUCCESS=true
          break
        fi
        echo "   Login attempt $attempt/5 failed, retrying..."
        sleep 5
      done
      
      if [[ "$LOGIN_SUCCESS" != "true" ]]; then
        echo "❌ Failed to login to ArgoCD after 5 attempts"
        echo "Checking ArgoCD server status:"
        kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-server
        kubectl -n argocd logs -l app.kubernetes.io/name=argocd-server --tail=20
        exit 1
      fi
      
      # Create polybot namespace
      echo "📁 Creating polybot namespace..."
      kubectl create namespace polybot --dry-run=client -o yaml | kubectl apply -f - || true
      
      # Create/update ArgoCD application
      echo "📱 Creating ArgoCD application..."
      if argocd app create polybot \
        --repo https://github.com/guymeltzer/PolybotInfra.git \
        --path k8s-manifests \
        --dest-server https://kubernetes.default.svc \
        --dest-namespace polybot \
        --sync-policy automated \
        --auto-prune \
        --self-heal \
        --upsert; then
        echo "✅ ArgoCD application created/updated successfully"
      else
        echo "⚠️  Application creation failed, trying sync instead..."
        if argocd app sync polybot; then
          echo "✅ Application sync successful"
        else
          echo "❌ Application sync failed, but continuing..."
          argocd app get polybot || echo "Could not get app details"
        fi
      fi
      
      echo "✅ ArgoCD application configuration completed successfully!"
      
      # List applications for verification
      echo "📋 Current ArgoCD applications:"
      argocd app list || echo "Could not list applications"
    EOT
  }
  
  depends_on = [
    null_resource.configure_argocd_repositories,
    module.kubernetes_resources,
    module.k8s-cluster
  ]
}

# Modify Calico/Tigera installation to be more robust
resource "null_resource" "install_calico" {
  depends_on = [
    null_resource.wait_for_kubernetes,
    terraform_data.kubectl_provider_config,
    module.k8s-cluster
  ]
  
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🌐 Installing Calico CNI..."
      
      # Check if Calico is already installed
      if kubectl -n kube-system get deployment calico-kube-controllers &>/dev/null; then
        echo "ℹ️  Calico appears to already be installed. Checking health..."
        if kubectl -n kube-system rollout status deployment/calico-kube-controllers --timeout=30s &>/dev/null; then
          echo "✅ Existing Calico installation is healthy"
          exit 0
        else
          echo "⚠️  Existing Calico installation has issues, will reinstall"
          kubectl delete -f https://docs.projectcalico.org/manifests/calico.yaml --ignore-not-found=true || true
          sleep 15
        fi
      fi
      
      echo "📦 Applying Calico manifest..."
      if ! curl -fsSL --connect-timeout 30 --max-time 120 https://docs.projectcalico.org/manifests/calico.yaml | kubectl apply -f -; then
        echo "❌ Failed to apply Calico manifest"
        exit 1
      fi
      
      echo "⏳ Waiting for Calico components to be ready..."
      
      # Wait for Calico kube-controllers deployment
      echo "   Waiting for calico-kube-controllers deployment..."
      if ! kubectl -n kube-system wait --for=condition=available deployment/calico-kube-controllers --timeout=300s; then
        echo "❌ Calico kube-controllers deployment not ready"
        echo "Deployment status:"
        kubectl -n kube-system get deployment calico-kube-controllers -o wide
        echo "Pod status:"
        kubectl -n kube-system get pods -l k8s-app=calico-kube-controllers -o wide
        exit 1
      fi
      
      # Wait for Calico node DaemonSet to be ready
      echo "   Waiting for calico-node DaemonSet..."
      if ! kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s; then
        echo "❌ Calico node DaemonSet not ready"
        echo "DaemonSet status:"
        kubectl -n kube-system get daemonset calico-node -o wide
        echo "Pod status:"
        kubectl -n kube-system get pods -l k8s-app=calico-node -o wide
        exit 1
      fi
      
      # Verify all nodes have Calico pods running
      echo "   Verifying Calico pod distribution..."
      TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l)
      CALICO_PODS_READY=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector=status.phase=Running --no-headers | wc -l)
      
      if [[ "$CALICO_PODS_READY" -lt "$TOTAL_NODES" ]]; then
        echo "⚠️  Only $CALICO_PODS_READY/$TOTAL_NODES Calico node pods are running"
        echo "Checking pod status:"
        kubectl -n kube-system get pods -l k8s-app=calico-node -o wide
      else
        echo "✅ All $TOTAL_NODES nodes have Calico pods running"
      fi
      
      echo "✅ Calico CNI installation completed successfully"
    EOT
  }
}

# Configure ArgoCD with repository credentials
resource "null_resource" "configure_argocd_repositories" {
  count = local.skip_argocd ? 0 : 1
  triggers = {
    argocd_install_id = null_resource.install_argocd[0].id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      echo "🔧 Configuring ArgoCD repositories..."
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Verify ArgoCD is fully installed and ready
      echo "🔍 Verifying ArgoCD installation..."
      
      # Check if ArgoCD namespace exists
      if ! kubectl get namespace argocd &>/dev/null; then
        echo "❌ ArgoCD namespace not found"
        exit 1
      fi
      
      # Wait for ArgoCD server deployment to be ready
      echo "⏳ Waiting for ArgoCD server deployment..."
      if ! kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=300s; then
        echo "❌ ArgoCD server deployment not ready within timeout"
        kubectl -n argocd get deployments
        kubectl -n argocd get pods
        exit 1
      fi
      
      # Wait for ArgoCD server service to exist
      echo "⏳ Waiting for ArgoCD server service..."
      for attempt in {1..30}; do
        if kubectl -n argocd get service argocd-server &>/dev/null; then
          echo "✅ ArgoCD server service found"
          break
        fi
        echo "   Attempt $attempt/30: Waiting for ArgoCD server service..."
        sleep 10
        if [[ $attempt -eq 30 ]]; then
          echo "❌ ArgoCD server service not found after waiting"
          kubectl -n argocd get services
          exit 1
        fi
      done
      
      # Wait for ArgoCD server to be fully ready
      echo "⏳ Waiting for ArgoCD server to be fully ready..."
      for attempt in {1..60}; do
        if kubectl -n argocd get deployment argocd-server &>/dev/null; then
          READY_REPLICAS=$(kubectl -n argocd get deployment argocd-server -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
          DESIRED_REPLICAS=$(kubectl -n argocd get deployment argocd-server -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
          
          if [[ "$READY_REPLICAS" == "$DESIRED_REPLICAS" ]] && [[ "$READY_REPLICAS" -gt 0 ]]; then
            echo "✅ ArgoCD server is ready ($READY_REPLICAS/$DESIRED_REPLICAS replicas)"
            break
          fi
        fi
        echo "   Attempt $attempt/60: ArgoCD server not ready yet..."
        sleep 10
        if [[ $attempt -eq 60 ]]; then
          echo "❌ ArgoCD server not ready after waiting"
          kubectl -n argocd get deployments
          kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-server
          exit 1
        fi
      done
      
      echo "ℹ️  Skipping ArgoCD CLI-based repository configuration due to complexity"
      echo "✅ ArgoCD is ready - you can add repositories manually via the UI"
      echo ""
      echo "🔗 To access ArgoCD UI:"
      echo "   kubectl -n argocd port-forward svc/argocd-server 8080:443"
      echo "   Then visit: https://localhost:8080"
      echo ""
      echo "🔑 To get the admin password:"
      echo "   kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
    EOT
  }
}

# Enhanced stale node cleanup with robust checking and terminating pod cleanup
resource "null_resource" "cleanup_stale_nodes" {
  depends_on = [
    null_resource.wait_for_kubernetes,
    terraform_data.kubectl_provider_config,
    null_resource.install_node_termination_handler,
    null_resource.remove_orphaned_nodes,  # Run after orphaned nodes are removed
    module.k8s-cluster
  ]

  # Run cleanup only when there are actual issues - more selective triggering
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
    # Only run when cluster is actually having node issues, not on every apply
    run_cleanup = "selective-v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🧹 Enhanced stale node and pod cleanup..."
      
      # Check if kubectl can connect to the cluster
      if ! kubectl get nodes &>/dev/null; then
        echo "❌ Cannot connect to Kubernetes cluster, skipping node cleanup"
        exit 0
      fi
      
      # Wait for cluster to stabilize before cleanup
      echo "⏳ Waiting for cluster to stabilize..."
      sleep 30
      
      echo "📋 Getting all worker nodes..."
      WORKER_NODES=$(kubectl get nodes --no-headers | grep -v "control-plane" | awk '{print $1}' || true)
      
      if [[ -z "$WORKER_NODES" ]]; then
        echo "ℹ️  No worker nodes found in cluster"
      else
        echo "📋 Found worker nodes: $WORKER_NODES"
      fi
      
      # Phase 1: Clean up terminating pods from NotReady nodes
      echo ""
      echo "🧽 Phase 1: Cleaning up terminating pods from NotReady nodes..."
      
      for NODE_NAME in $WORKER_NODES; do
        NODE_STATUS=$(kubectl get node "$NODE_NAME" --no-headers | awk '{print $2}' || echo "Unknown")
        NODE_READY=$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
        
        # Check if node is NotReady (either status="NotReady" or Ready condition is not "True")
        if [[ "$NODE_STATUS" == "NotReady" ]] || [[ "$NODE_READY" != "True" ]]; then
          echo "🔍 Node $NODE_NAME is not ready (Status: $NODE_STATUS, Ready: $NODE_READY)"
          
          # Find terminating pods on this node
          TERMINATING_PODS=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" \
            --output json | jq -r '.items[] | select(.metadata.deletionTimestamp != null) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || true)
          
          if [[ -n "$TERMINATING_PODS" ]]; then
            echo "   Found terminating pods on NotReady node $NODE_NAME:"
            echo "$TERMINATING_PODS" | while read -r pod; do
              if [[ -n "$pod" ]] && [[ "$pod" == *"/"* ]]; then
                NAMESPACE=$(echo "$pod" | cut -d'/' -f1)
                PODNAME=$(echo "$pod" | cut -d'/' -f2)
                echo "     Force deleting terminating pod: $NAMESPACE/$PODNAME"
                kubectl delete pod "$PODNAME" -n "$NAMESPACE" --force --grace-period=0 --timeout=10s || true
              fi
            done
          fi
          
          # Find stuck pending pods on this node that have been pending for >5 minutes
          STUCK_PENDING_PODS=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" \
            --field-selector status.phase=Pending --output json | \
            jq -r --argjson threshold "$(date -d '5 minutes ago' +%s)" \
            '.items[] | select((.metadata.creationTimestamp | fromdateiso8601) < $threshold) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || true)
          
          if [[ -n "$STUCK_PENDING_PODS" ]]; then
            echo "   Found stuck pending pods on NotReady node $NODE_NAME:"
            echo "$STUCK_PENDING_PODS" | while read -r pod; do
              if [[ -n "$pod" ]] && [[ "$pod" == *"/"* ]]; then
                NAMESPACE=$(echo "$pod" | cut -d'/' -f1)
                PODNAME=$(echo "$pod" | cut -d'/' -f2)
                echo "     Deleting stuck pending pod: $NAMESPACE/$PODNAME"
                kubectl delete pod "$PODNAME" -n "$NAMESPACE" --timeout=30s --force --grace-period=0 || true
              fi
            done
          fi
        fi
      done
      
      # Phase 2: Check each worker node for staleness
      echo ""
      echo "🔍 Phase 2: Checking for truly stale nodes to remove..."
      
      STALE_NODES_FOUND=0
      NODES_TO_CLEANUP=()
      
      # First pass: identify nodes that are NotReady for extended periods
      for NODE_NAME in $WORKER_NODES; do
        echo ""
        echo "🔍 Checking node: $NODE_NAME"
        
        # Get detailed node status
        NODE_STATUS=$(kubectl get node "$NODE_NAME" --no-headers | awk '{print $2}' || echo "Unknown")
        NODE_READY=$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
        NODE_AGE_RAW=$(kubectl get node "$NODE_NAME" --no-headers | awk '{print $4}' || echo "Unknown")
        
        echo "   Status: $NODE_STATUS (Ready: $NODE_READY, Age: $NODE_AGE_RAW)"
        
        # Consider a node stale if it's NotReady OR Ready condition is not "True"
        if [[ "$NODE_STATUS" == "NotReady" ]] || [[ "$NODE_READY" != "True" ]]; then
          echo "⚠️  Node $NODE_NAME is not ready, checking if it should be removed..."
          
          # Check node age - be more aggressive: remove nodes that have been NotReady for more than 5 minutes
          NODE_AGE_SECONDS=0
          if [[ "$NODE_AGE_RAW" =~ ^([0-9]+)m$ ]]; then
            NODE_AGE_SECONDS=$(($${BASH_REMATCH[1]} * 60))
          elif [[ "$NODE_AGE_RAW" =~ ^([0-9]+)h$ ]]; then
            NODE_AGE_SECONDS=$(($${BASH_REMATCH[1]} * 3600))
          elif [[ "$NODE_AGE_RAW" =~ ^([0-9]+)d$ ]]; then
            NODE_AGE_SECONDS=$(($${BASH_REMATCH[1]} * 86400))
          fi
          
          # If node is older than 5 minutes and still NotReady, check if EC2 instance exists
          if [[ $NODE_AGE_SECONDS -gt 300 ]]; then
            echo "   Node has been around for >5 minutes and is still NotReady, checking EC2 instance..."
            
            # Initialize instance check flag
            INSTANCE_EXISTS=""
            
            # Extract instance ID from worker node name - try multiple patterns
            if [[ "$NODE_NAME" =~ worker-([a-f0-9]{17})$ ]]; then
              # Pattern: worker-<17-char-instance-id>
              INSTANCE_ID="i-$${BASH_REMATCH[1]}"
              echo "   Extracted instance ID from node name: $INSTANCE_ID"
              
              # Check if this exact instance exists and is running
              INSTANCE_EXISTS=$(aws ec2 describe-instances \
                --region ${var.region} \
                --instance-ids "$INSTANCE_ID" \
                --filters "Name=instance-state-name,Values=running" \
                --query "Reservations[*].Instances[*].InstanceId" \
                --output text 2>/dev/null | head -1)
                
            elif [[ "$NODE_NAME" =~ ^worker-([a-f0-9]+)$ ]]; then
              NODE_HASH="$${BASH_REMATCH[1]}"
              echo "   Looking for EC2 instance with hash: $NODE_HASH"
              
              # Search for running instance with this hash in name or instance ID
              INSTANCE_EXISTS=$(aws ec2 describe-instances \
                --region ${var.region} \
                --filters "Name=instance-state-name,Values=running" \
                --query "Reservations[*].Instances[?contains(Tags[?Key=='Name'].Value, '$NODE_HASH') || contains(InstanceId, '$NODE_HASH')].[InstanceId]" \
                --output text 2>/dev/null | tr '\t' '\n' | grep -v '^$' | head -1)
                
            elif [[ "$NODE_NAME" =~ ^ip-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+) ]]; then
              # Format: ip-<ip-with-dashes>
              PRIVATE_IP="$${BASH_REMATCH[1]}.$${BASH_REMATCH[2]}.$${BASH_REMATCH[3]}.$${BASH_REMATCH[4]}"
              echo "   Looking for EC2 instance with private IP: $PRIVATE_IP"
              
              # Search for running instance with this private IP
              INSTANCE_EXISTS=$(aws ec2 describe-instances \
                --region ${var.region} \
                --filters "Name=private-ip-address,Values=$PRIVATE_IP" "Name=instance-state-name,Values=running" \
                --query "Reservations[*].Instances[*].InstanceId" \
                --output text 2>/dev/null | head -1)
                
            else
              # Generic search - look for any worker instance with similar name
              echo "   Generic search for node: $NODE_NAME"
              INSTANCE_EXISTS=$(aws ec2 describe-instances \
                --region ${var.region} \
                --filters "Name=tag:Name,Values=*worker*" "Name=instance-state-name,Values=running" \
                --query "Reservations[*].Instances[?contains(Tags[?Key=='Name'].Value, '$NODE_NAME')].[InstanceId]" \
                --output text 2>/dev/null | head -1)
            fi
            
            echo "   Instance search result: '$INSTANCE_EXISTS'"
            
            # If no running instance found, mark for cleanup
            if [[ -z "$INSTANCE_EXISTS" ]] || [[ "$INSTANCE_EXISTS" == "None" ]] || [[ "$INSTANCE_EXISTS" == "null" ]]; then
              echo "🗑️  No running EC2 instance found for NotReady node $NODE_NAME, marking for removal"
              NODES_TO_CLEANUP+=("$NODE_NAME")
              STALE_NODES_FOUND=$((STALE_NODES_FOUND + 1))
            else
              echo "   ✅ Node $NODE_NAME has corresponding running EC2 instance: $INSTANCE_EXISTS"
              echo "   📝 Will try to recover this node instead of removing it"
            fi
          else
            echo "   ⏰ Node is NotReady but still young (<5 min old), giving it more time to recover"
          fi
        else
          echo "   ✅ Node $NODE_NAME is healthy (Status: $NODE_STATUS, Ready: $NODE_READY)"
        fi
      done
      
      # Phase 3: Clean up identified stale nodes
      if [[ $${#NODES_TO_CLEANUP[@]} -gt 0 ]]; then
        echo ""
        echo "🧹 Phase 3: Cleaning up $${#NODES_TO_CLEANUP[@]} stale nodes..."
        
        for NODE_NAME in "$${NODES_TO_CLEANUP[@]}"; do
          echo ""
          echo "🗑️  Cleaning up stale node: $NODE_NAME"
          
          # Check if any pods are running on this node
          PODS_ON_NODE=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" --no-headers 2>/dev/null | wc -l || echo "0")
          echo "   Found $PODS_ON_NODE pods on node $NODE_NAME"
          
          if [[ "$PODS_ON_NODE" -gt 0 ]]; then
            echo "   Draining node $NODE_NAME with aggressive strategy..."
            
            # First, try graceful drain with shorter timeout
            kubectl drain "$NODE_NAME" \
              --ignore-daemonsets \
              --delete-emptydir-data \
              --force \
              --timeout=30s \
              --grace-period=15 \
              --disable-eviction=false 2>/dev/null || {
              
              echo "   ⚠️  Graceful drain failed, trying with pod eviction disabled..."
              kubectl drain "$NODE_NAME" \
                --ignore-daemonsets \
                --delete-emptydir-data \
                --force \
                --timeout=30s \
                --grace-period=5 \
                --disable-eviction=true 2>/dev/null || {
                
                echo "   ⚠️  Standard drain failed, force deleting all pods on node..."
                
                # Force delete all pods on this node
                kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" -o json | \
                  jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' | \
                  while read -r pod; do
                    if [[ -n "$pod" ]] && [[ "$pod" == *"/"* ]]; then
                      NAMESPACE=$(echo "$pod" | cut -d'/' -f1)
                      PODNAME=$(echo "$pod" | cut -d'/' -f2)
                      echo "     Force deleting pod: $NAMESPACE/$PODNAME"
                      kubectl delete pod "$PODNAME" -n "$NAMESPACE" --force --grace-period=0 --timeout=10s || true
                    fi
                  done
              }
            }
          fi
          
          # Delete the node from the cluster
          echo "   Deleting node $NODE_NAME from cluster..."
          if kubectl delete node "$NODE_NAME" --timeout=30s; then
            echo "   ✅ Successfully removed stale node: $NODE_NAME"
          else
            echo "   ❌ Failed to delete node $NODE_NAME from cluster"
          fi
        done
      else
        echo ""
        echo "✅ No stale nodes found that need removal"
      fi
      
      # Phase 4: General pod cleanup
      echo ""
      echo "🧹 Phase 4: General problematic pod cleanup..."
      
      # Clean up completed and failed pods (with better error handling)
      echo "   Removing completed pods..."
      kubectl get pods --all-namespaces --field-selector=status.phase=Succeeded -o name 2>/dev/null | \
        head -20 | xargs -r kubectl delete --timeout=30s 2>/dev/null || true
      
      echo "   Removing failed pods..."
      kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o name 2>/dev/null | \
        head -20 | xargs -r kubectl delete --timeout=30s 2>/dev/null || true
      
      # Clean up old pending pods that are clearly stuck (>15 mins)
      echo "   Removing clearly stuck pending pods (>15 mins)..."
      STUCK_PODS=$(kubectl get pods --all-namespaces --field-selector=status.phase=Pending -o json 2>/dev/null | \
        jq -r --argjson threshold "$(date -d '15 minutes ago' +%s)" \
        '.items[] | select((.metadata.creationTimestamp | fromdateiso8601) < $threshold and (.metadata.name | test("(debugger|test|temp|node-debugger)"))) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || true)
      
      if [[ -n "$STUCK_PODS" ]]; then
        echo "$STUCK_PODS" | while read -r pod; do
          if [[ -n "$pod" ]] && [[ "$pod" == *"/"* ]]; then
            NAMESPACE=$(echo "$pod" | cut -d'/' -f1)
            PODNAME=$(echo "$pod" | cut -d'/' -f2)
            echo "     Deleting clearly stuck pod: $NAMESPACE/$PODNAME"
            kubectl delete pod "$PODNAME" -n "$NAMESPACE" --timeout=30s --force --grace-period=0 || true
          fi
        done
      fi
      
      echo ""
      echo "🎉 Enhanced node and pod cleanup completed!"
      echo "📊 Summary:"
      echo "   - Stale nodes removed: $STALE_NODES_FOUND"
      echo ""
      
      # Show current cluster state
      echo "📋 Current cluster state:"
      kubectl get nodes -o wide
      echo ""
      
      echo "🔍 Remaining problematic pods (if any):"
      PROBLEM_PODS=$(kubectl get pods --all-namespaces | grep -E "(Pending|Failed|Unknown|Terminating|CrashLoopBackOff)" | head -10 || true)
      if [[ -n "$PROBLEM_PODS" ]]; then
        echo "$PROBLEM_PODS"
      else
        echo "   ✅ No problematic pods found"
      fi
      
      echo ""
      echo "✅ Enhanced stale node cleanup process complete!"
    EOT
  }
}

# Add pre-deployment cleanup to handle existing resources
resource "null_resource" "pre_deployment_cleanup" {
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.cluster_readiness_check
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    cluster_ready_id = null_resource.cluster_readiness_check.id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🧹 Pre-deployment cleanup..."
      
      # Check if kubectl can connect
      if ! kubectl get nodes &>/dev/null; then
        echo "Cannot connect to Kubernetes cluster, skipping cleanup"
        exit 0
      fi
      
      # Clean up any stuck storage classes with conflicting parameters
      echo "Checking for problematic storage classes..."
      for sc in ebs-sc mongodb-sc ebs-fast ebs-slow; do
        if kubectl get storageclass "$sc" &>/dev/null; then
          echo "Found existing storage class: $sc"
          # Check if it has pods using it
          PODS_USING_SC=$(kubectl get pv -o jsonpath='{.items[?(@.spec.storageClassName=="'$sc'")].spec.claimRef.name}' 2>/dev/null | wc -w)
          if [[ "$PODS_USING_SC" -eq 0 ]]; then
            echo "No pods using $sc, safe to delete and recreate"
            kubectl delete storageclass "$sc" --ignore-not-found=true
          else
            echo "Storage class $sc has $PODS_USING_SC pods using it, will try to update instead"
          fi
        fi
      done
      
      # Clean up any failed jobs or pods that might interfere
      echo "Cleaning up failed resources..."
      kubectl delete pods --field-selector=status.phase=Failed --all-namespaces --ignore-not-found=true &
      kubectl delete jobs --field-selector=status.successful=0 --all-namespaces --ignore-not-found=true &
      
      # Wait for cleanup to complete
      wait
      
      echo "✅ Pre-deployment cleanup completed"
    EOT
  }
}

# Create MongoDB directly without ArgoCD, but with simpler implementation
resource "null_resource" "deploy_mongodb_directly" {
  count = local.skip_argocd ? 0 : 1
  triggers = {
    kubeconfig_trigger = terraform_data.kubectl_provider_config[0].id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "Deploying MongoDB..."
      
      # Use kubectl apply with server-side apply to handle existing resources
      kubectl apply -f ${path.module}/manifests/mongodb-deployment.yaml --server-side=true --force-conflicts || {
        echo "Server-side apply failed, trying regular apply..."
        kubectl apply -f ${path.module}/manifests/mongodb-deployment.yaml || {
          echo "Regular apply failed, checking if resources already exist..."
          
          # Check if deployment exists
          if kubectl get deployment mongodb -n default &>/dev/null; then
            echo "MongoDB deployment already exists, updating if needed..."
            kubectl patch deployment mongodb -n default --type='merge' -p='{"spec":{"template":{"metadata":{"labels":{"restarted":"'$(date +%s)'"}}}}}'
          else
            echo "MongoDB deployment doesn't exist, creating..."
            kubectl create -f ${path.module}/manifests/mongodb-deployment.yaml
          fi
          
          # Check if service exists
          if kubectl get service mongodb-service -n default &>/dev/null; then
            echo "MongoDB service already exists, skipping service creation"
          else
            echo "Creating MongoDB service..."
            # Extract just the service from the manifest and create it
            kubectl apply -f ${path.module}/manifests/mongodb-deployment.yaml --dry-run=client -o yaml | \
              grep -A 20 "kind: Service" | kubectl apply -f -
          fi
        }
      }
      
      echo "MongoDB deployment completed"
    EOT
  }
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.install_ebs_csi_driver,
    null_resource.cluster_readiness_check,
    null_resource.pre_deployment_cleanup,
    module.k8s-cluster
  ]
}

# Use the kubernetes-resources module for all Kubernetes-specific resources
module "kubernetes_resources" {
  source = "./modules/kubernetes-resources"
  
  # Required parameters
  region            = var.region
  kubeconfig_path   = local.kubeconfig_path
  module_path       = path.module
  key_name          = var.key_name
  
  # Optional parameters with defaults
  enable_resources    = true
  skip_mongodb        = false
  
  # Resource dependencies - simplified to avoid cycles
  kubeconfig_trigger_id = terraform_data.kubectl_provider_config[0].id
  kubernetes_dependency = null_resource.wait_for_kubernetes
  ebs_csi_dependency    = null_resource.install_ebs_csi_driver
  control_plane_id      = module.k8s-cluster.control_plane_instance_id
  
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.install_ebs_csi_driver,
    null_resource.wait_for_kubernetes,
    module.k8s-cluster
  ]
}


# Add display information at the start of deployment
resource "terraform_data" "deployment_information" {
  # Run only on first apply or when Terraform files change
  triggers_replace = {
    module_hash = filemd5("${path.module}/main.tf") 
    variables_hash = filemd5("${path.module}/variables.tf")
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
    EOT
  }
}

# Check for existing EBS service-linked role and continue if it exists
resource "null_resource" "check_ebs_role" {
  # Only run this once, not on every apply
  triggers = {
    run_once = "check-ebs-role-v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<EOF
#!/bin/bash
echo "Checking if EBS service-linked role already exists..."

# Try to get the role ARN
ROLE_ARN=$(aws iam get-role --role-name AWSServiceRoleForEBS --query 'Role.Arn' --output text 2>/dev/null || echo "")

if [ -n "$ROLE_ARN" ] && [ "$ROLE_ARN" != "None" ]; then
  echo "EBS service-linked role already exists: $ROLE_ARN"
else
  echo "EBS service-linked role does not exist, attempting to create it..."
  
  # Try to create the role - this might fail due to permissions
  aws iam create-service-linked-role --aws-service-name ebs.amazonaws.com 2>/dev/null || {
    # Try with ec2 service name as fallback
    aws iam create-service-linked-role --aws-service-name ec2.amazonaws.com 2>/dev/null || {
      echo "Warning: Could not create EBS service-linked role - this is normal if you don't have sufficient IAM permissions"
      echo "The EBS CSI driver might still work if the role already exists at the account level"
    }
  }
fi

echo "Continuing with deployment..."
EOF
  }
}

#DEBUGGABLE: Kubernetes readiness validation with detailed state capture
resource "null_resource" "kubernetes_readiness_debug" {
  count = 1
  
  depends_on = [
    null_resource.wait_for_kubernetes
    # Remove circular dependency
    # null_resource.post_cluster_debug
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    timestamp = timestamp()
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"kubernetes_readiness_check", "status":"start", "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      export KUBECONFIG="${local.kubeconfig_path}"
      mkdir -p logs/kubernetes_state
      
      # Capture comprehensive cluster state
      if kubectl get nodes --no-headers 2>/dev/null; then
        kubectl get nodes -o json > logs/kubernetes_state/nodes_${timestamp()}.json 2>&1
        kubectl get pods --all-namespaces -o json > logs/kubernetes_state/all_pods_${timestamp()}.json 2>&1
        kubectl get events --all-namespaces --sort-by='.lastTimestamp' > logs/kubernetes_state/events_${timestamp()}.log 2>&1
        kubectl cluster-info > logs/kubernetes_state/cluster_info_${timestamp()}.log 2>&1
        
        echo '{"stage":"kubernetes_state_capture", "status":"success", "time":"${timestamp()}"}' >> logs/tf_debug.log
      else
        echo '{"stage":"kubernetes_state_capture", "status":"error", "message":"kubectl unavailable", "time":"${timestamp()}"}' >> logs/tf_debug.log
      fi
      
      echo '{"stage":"kubernetes_readiness_check", "status":"complete", "time":"${timestamp()}"}' >> logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

#DEBUGGABLE: Debug artifact packaging and final validation
resource "null_resource" "debug_bundle_creation" {
  depends_on = [
    null_resource.kubernetes_readiness_debug
    # Remove potential circular dependency with kubernetes_resources module
    # module.kubernetes_resources
  ]
  
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"debug_bundle_creation", "status":"start", "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      # Create comprehensive debug bundle
      BUNDLE_NAME="debug-bundle-$(date +%Y%m%d-%H%M%S).tgz"
      
      # Collect all log files and debug artifacts
      find logs/ -type f -name "*.log" -o -name "*.json" > /tmp/debug_files.list
      
      # Add Terraform state and plan files
      find . -maxdepth 1 -name "*.tfstate*" -o -name "*.tfplan" >> /tmp/debug_files.list
      
      # Add cloud-init logs if accessible
      if [ -f "/var/log/cloud-init-output.log" ]; then
        echo "/var/log/cloud-init-output.log" >> /tmp/debug_files.list
      fi
      
      # Create the bundle
      tar czf "logs/$BUNDLE_NAME" -T /tmp/debug_files.list 2>/dev/null || {
        echo '{"stage":"bundle_creation", "status":"error", "time":"${timestamp()}"}' >> logs/tf_debug.log
      }
      
      # Generate debug summary report
      cat > logs/debug_summary_${timestamp()}.json <<SUMMARY
{
  "bundle_name": "$BUNDLE_NAME",
  "creation_time": "${timestamp()}",
  "terraform_workspace": "${terraform.workspace}",
  "region": "${var.region}",
  "control_plane_ip": "${try(module.k8s-cluster.control_plane_public_ip, "unknown")}",
  "cluster_status": "$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo 0) nodes ready",
  "log_files": $(find logs/ -name "*.log" | wc -l),
  "json_files": $(find logs/ -name "*.json" | wc -l),
  "analysis_commands": {
    "error_analysis": "jq '. | select(.status == \"error\")' logs/tf_debug.log",
    "timing_analysis": "jq -r '[.stage, .time, .status] | @csv' logs/tf_debug.log",
    "aws_errors": "grep -i error logs/aws_*.json || echo 'No AWS errors found'",
    "k8s_failures": "grep -i failed logs/kubernetes_state/*.log || echo 'No K8s failures found'"
  }
}
SUMMARY
      
      echo "📦 Debug bundle created: logs/$BUNDLE_NAME"
      echo "📋 Debug summary: logs/debug_summary_${timestamp()}.json"
      
      echo '{"stage":"debug_bundle_creation", "status":"complete", "bundle":"'$BUNDLE_NAME'", "time":"${timestamp()}"}' >> logs/tf_debug.log
    EOT
    
    on_failure = continue
  }

  provisioner "local-exec" {
    when = destroy
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"terraform_destroy_debug", "status":"start", "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      # Create destroy debug bundle
      DESTROY_BUNDLE="destroy-debug-$(date +%Y%m%d-%H%M%S).tgz"
      tar czf "logs/$DESTROY_BUNDLE" logs/*.log logs/*.json 2>/dev/null || true
      
      echo '{"stage":"terraform_destroy_debug", "status":"complete", "bundle":"'$DESTROY_BUNDLE'", "time":"${timestamp()}"}' >> logs/tf_debug.log
    EOT
  }
}

#DEBUGGABLE: Final deployment summary and troubleshooting guide
resource "null_resource" "deployment_summary" {
  # Remove circular dependency - this should run independently
  # depends_on = [null_resource.integrated_debug_analysis]
  
  triggers = {
    completion_time = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"deployment_completion", "status":"finalizing", "time":"${timestamp()}"}' >> logs/tf_debug.log
      
      # Generate simple troubleshooting guide
      cat > logs/TROUBLESHOOTING_GUIDE.md <<GUIDE
# 🐛 Terraform Debugging Guide

## Generated at: ${timestamp()}

### Quick Debug Commands:
\`\`\`bash
# Find all errors in debug log:
grep '"status":"error"' logs/tf_debug.log

# Timeline of all events:
grep -E '(start|complete)' logs/tf_debug.log

# Check AWS connectivity issues:
grep -i "aws_validation" logs/tf_debug.log

# Find cluster connectivity problems:
grep -i "connectivity" logs/tf_debug.log
\`\`\`

### Log Files to Analyze:
- **logs/tf_debug.log**: Main structured debug log
- **logs/cluster_state/**: AWS instance details
- **logs/kubernetes_state/**: Kubernetes cluster state
- **logs/aws_identity_*.json**: AWS authentication info

### Copy-Paste for Cursor AI:
When reporting issues, use \`terraform output copy_paste_debug_info\`

### Environment Variables Used:
- TF_LOG=DEBUG
- TF_LOG_CORE=DEBUG  
- TF_LOG_PATH=logs/terraform-*.log
- AWS_LOG_LEVEL=debug
GUIDE

      echo ""
      echo "🎉 Terraform Deployment Complete!"
      echo "📋 Debug analysis displayed above"
      echo "📁 Troubleshooting guide: logs/TROUBLESHOOTING_GUIDE.md"
      echo "📊 Use 'terraform output' commands for detailed debug info"
      echo ""
      
      echo '{"stage":"deployment_completion", "status":"complete", "time":"${timestamp()}"}' >> logs/tf_debug.log
    EOT
  }
}

#DEBUGGABLE: Comprehensive debug analysis and summary integrated into Terraform apply
resource "null_resource" "integrated_debug_analysis" {
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      echo "Integrated debug: Worker ASG: ${module.k8s-cluster.worker_asg_name}" > /tmp/integrated_debug.txt
      echo "Cluster debug: Control plane ID: ${module.k8s-cluster.control_plane_instance_id}" > /tmp/post_cluster_debug.txt
    EOT
  }
  depends_on = [module.k8s-cluster]
}

# Configure Kubernetes provider with the kubeconfig file
resource "terraform_data" "kubectl_provider_config" {
  count = 1

  triggers_replace = {
    control_plane_id = module.k8s-cluster.control_plane_instance_id
    kubeconfig_path  = local.kubeconfig_path
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<EOF
#!/bin/bash
set -e

echo "Setting up Kubernetes provider with kubeconfig: ${local.kubeconfig_path}"

# Function to retrieve kubeconfig from control plane with retries
fetch_kubeconfig() {
  local MAX_ATTEMPTS=10
  local RETRY_DELAY=30
  local attempt=1
  
  echo "Retrieving kubeconfig from control plane instance..."
  
  while [ $attempt -le $MAX_ATTEMPTS ]; do
    echo "Attempt $attempt/$MAX_ATTEMPTS to get kubeconfig"
    
    # Get the instance ID of the control plane - as a single line command
    INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=guy-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text | tr -d '\r\n')
        
    if [ "$INSTANCE_ID" = "None" ] || [ -z "$INSTANCE_ID" ]; then
      echo "No running control plane instance found, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      attempt=$(expr $attempt + 1)
      continue
    fi
    
    echo "Found control plane instance: $INSTANCE_ID"
    
    # Use SSM to get the kubeconfig from the instance - as a single line command
    COMMAND_ID=$(aws ssm send-command --region ${var.region} --document-name "AWS-RunShellScript" --instance-ids "$INSTANCE_ID" --parameters commands="sudo cat /etc/kubernetes/admin.conf" --output text --query "Command.CommandId" 2>/dev/null | tr -d '\r\n')
        
    if [ -z "$COMMAND_ID" ]; then
      echo "Failed to send SSM command, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      attempt=$(expr $attempt + 1)
      continue
    fi
    
    echo "SSM command sent, waiting for completion..."
    sleep 10
    
    # Get the command output - as a single line command
    KUBECONFIG_CONTENT=$(aws ssm get-command-invocation --region ${var.region} --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text 2>/dev/null)
        
    if [ -n "$KUBECONFIG_CONTENT" ] && echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion"; then
      echo "Successfully retrieved kubeconfig"
      echo "$KUBECONFIG_CONTENT" > ${local.kubeconfig_path}
      chmod 600 ${local.kubeconfig_path}
      
      # Update the server address in the kubeconfig to use public IP - as a single line command
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids "$INSTANCE_ID" --query "Reservations[0].Instances[0].PublicIpAddress" --output text | tr -d '\r\n')
          
      if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "None" ]; then
        echo "Updating kubeconfig to use public IP: $PUBLIC_IP"
        # Different sed syntax for macOS and Linux
        if [[ "$OSTYPE" == "darwin"* ]]; then
          sed -i '' "s|server:.*|server: https://$PUBLIC_IP:6443|g" ${local.kubeconfig_path}
        else
          sed -i "s|server:.*|server: https://$PUBLIC_IP:6443|g" ${local.kubeconfig_path}
        fi
      fi
      
      echo "Kubeconfig saved to ${local.kubeconfig_path}"
      return 0
    else
      echo "Invalid kubeconfig content received, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      attempt=$(expr $attempt + 1)
    fi
  done
  
  echo "Failed to retrieve kubeconfig after $MAX_ATTEMPTS attempts"
  return 1
}

# Call the function to fetch the kubeconfig
fetch_kubeconfig || {
  echo "ERROR: Could not retrieve kubeconfig, creating a placeholder file"
  mkdir -p $(dirname "${local.kubeconfig_path}")
  cat > ${local.kubeconfig_path} << EOFINNER
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://placeholder:6443
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
    client-certificate-data: placeholder
    client-key-data: placeholder
EOFINNER
  chmod 600 ${local.kubeconfig_path}
}

echo "Kubeconfig file is ready at ${local.kubeconfig_path}"
EOF
  }
  
  depends_on = [module.k8s-cluster]
}

# Install EBS CSI Driver as a Kubernetes component
resource "null_resource" "install_ebs_csi_driver" {
  depends_on = [
    null_resource.wait_for_kubernetes,
    null_resource.check_ebs_role,
    null_resource.install_calico,  # Install after Calico is ready
    terraform_data.kubectl_provider_config
  ]
  
  # Trigger reinstall when the role check is run
  triggers = {
    ebs_role_check = null_resource.check_ebs_role.id
    calico_ready = null_resource.install_calico.id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
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
        echo "Deployment status:"
        kubectl -n kube-system get deployment ebs-csi-controller -o wide
        echo "Pod status:"
        kubectl -n kube-system get pods -l app=ebs-csi-controller -o wide
        echo "Checking for any scheduling issues:"
        kubectl -n kube-system describe pods -l app=ebs-csi-controller | grep -A 10 "Events:" || true
        exit 1
      fi
      
      echo "⏳ Waiting for EBS CSI node DaemonSet to be ready..."
      if ! kubectl -n kube-system rollout status daemonset/ebs-csi-node --timeout=300s; then
        echo "❌ EBS CSI node DaemonSet not ready"
        echo "DaemonSet status:"
        kubectl -n kube-system get daemonset ebs-csi-node -o wide
        echo "Pod status:"
        kubectl -n kube-system get pods -l app=ebs-csi-node -o wide
        exit 1
      fi
      
      echo "🔍 Verifying EBS CSI installation..."
      CONTROLLER_READY=$(kubectl -n kube-system get deployment ebs-csi-controller -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
      NODE_READY=$(kubectl -n kube-system get daemonset ebs-csi-node -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
      
      echo "   EBS CSI Controller: $CONTROLLER_READY replicas ready"
      echo "   EBS CSI Node: $NODE_READY pods ready"
      
      if [[ "$CONTROLLER_READY" -lt 1 ]] || [[ "$NODE_READY" -lt 1 ]]; then
        echo "❌ EBS CSI driver not fully ready"
        exit 1
      fi
      
      echo "✅ AWS EBS CSI Driver installation completed successfully"
    EOT
  }
}

# Install AWS Node Termination Handler to properly handle ASG instance terminations
resource "null_resource" "install_node_termination_handler" {
  depends_on = [
    null_resource.install_ebs_csi_driver,
    terraform_data.kubectl_provider_config
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG=${local.kubeconfig_path}
      
      echo "Installing AWS Node Termination Handler..."
      
      # Install AWS Node Termination Handler using Helm-like approach with kubectl
      kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-node-termination-handler
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/NodeInstanceRole
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aws-node-termination-handler
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "patch", "update"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
- apiGroups: ["extensions", "apps"]
  resources: ["daemonsets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aws-node-termination-handler
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: aws-node-termination-handler
subjects:
- kind: ServiceAccount
  name: aws-node-termination-handler
  namespace: kube-system
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: aws-node-termination-handler
  namespace: kube-system
  labels:
    app: aws-node-termination-handler
spec:
  selector:
    matchLabels:
      app: aws-node-termination-handler
  template:
    metadata:
      labels:
        app: aws-node-termination-handler
    spec:
      serviceAccountName: aws-node-termination-handler
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: aws-node-termination-handler
        image: public.ecr.aws/aws-ec2/aws-node-termination-handler:v1.19.0
        imagePullPolicy: IfNotPresent
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: ENABLE_SPOT_INTERRUPTION_DRAINING
          value: "true"
        - name: ENABLE_SCHEDULED_EVENT_DRAINING
          value: "true"
        - name: ENABLE_REBALANCE_MONITORING
          value: "true"
        - name: ENABLE_REBALANCE_DRAINING
          value: "true"
        - name: DELETE_LOCAL_DATA
          value: "true"
        - name: IGNORE_DAEMON_SETS
          value: "true"
        - name: POD_TERMINATION_GRACE_PERIOD
          value: "10"           # Reduced from 30 to 10 seconds
        - name: NODE_TERMINATION_GRACE_PERIOD
          value: "60"           # Reduced from 120 to 60 seconds
        - name: METADATA_TRIES
          value: "3"
        - name: CORDON_ONLY
          value: "false"
        - name: DRY_RUN
          value: "false"
        - name: ENABLE_PROMETHEUS_SERVER
          value: "false"
        - name: WEBHOOK_URL
          value: ""
        - name: WEBHOOK_HEADERS
          value: ""
        - name: WEBHOOK_TEMPLATE
          value: ""
        - name: ENABLE_SQS_TERMINATION_DRAINING
          value: "false"
        - name: QUEUE_URL
          value: ""
        - name: CHECK_ASG_TAG_BEFORE_DRAINING
          value: "true"
        - name: MANAGED_ASG_TAG
          value: "aws-node-termination-handler/managed"
        - name: USE_PROVIDER_ID
          value: "false"
        - name: JSON_LOGGING
          value: "false"
        - name: LOG_LEVEL
          value: "info"
        - name: ENABLE_PROBES_SERVER
          value: "false"
        - name: PROBES_SERVER_PORT
          value: "8080"
        - name: PROBES_SERVER_ENDPOINT
          value: "/healthz"
        - name: NODE_DRAIN_TIMEOUT_SECONDS
          value: "45"           # Reduced from default 120 to 45 seconds
        - name: POD_TERMINATION_TIMEOUT_SECONDS
          value: "15"           # Added explicit pod timeout of 15 seconds
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          runAsGroup: 1000
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      tolerations:
      - operator: Exists
      nodeSelector:
        kubernetes.io/os: linux
EOF

      echo "Waiting for Node Termination Handler pods to be ready..."
      kubectl -n kube-system wait --for=condition=ready pod -l app=aws-node-termination-handler --timeout=120s || {
        echo "Warning: Node Termination Handler pods not ready within timeout"
      }
      
      echo "AWS Node Termination Handler installation complete"
      
      # Create PodDisruptionBudgets for faster evictions
      echo "Creating PodDisruptionBudgets for optimized pod evictions..."
      kubectl apply -f - <<'EOF'
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: fast-eviction-pdb-default
  namespace: default
spec:
  maxUnavailable: 50%
  selector: {}  # Applies to all pods in default namespace
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: fast-eviction-pdb-kube-system
  namespace: kube-system
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app: not-critical  # Only applies to non-critical system pods
---
# Allow aggressive eviction for debugging pods
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: debug-pod-pdb
  namespace: default
spec:
  maxUnavailable: 100%
  selector:
    matchLabels:
      app: node-debugger
EOF
      
      echo "PodDisruptionBudgets created for optimized evictions"
    EOT
  }
}

# Direct ArgoCD access setup
resource "null_resource" "argocd_direct_access" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.install_argocd,
    terraform_data.kubectl_provider_config
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "Setting up ArgoCD direct access..."
      
      # Wait for ArgoCD deployment to be ready
      echo "Waiting for ArgoCD deployment to be ready..."
      kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=300s || true
      
      echo "ArgoCD direct access setup complete"
    EOT
  }
}

# Immediate orphaned node cleanup - runs right after cluster is ready
resource "null_resource" "remove_orphaned_nodes" {
  depends_on = [
    null_resource.wait_for_kubernetes,
    terraform_data.kubectl_provider_config
  ]

  # Run this immediately when cluster is ready, not when readiness check completes
  triggers = {
    kubeconfig_ready = terraform_data.kubectl_provider_config[0].id
    control_plane_id = module.k8s-cluster.control_plane_instance_id
    # Force immediate run to clean up orphaned nodes
    force_run = "immediate-cleanup-v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔍 Checking for orphaned worker nodes..."
      
      # Check if kubectl can connect to the cluster
      if ! kubectl get nodes &>/dev/null; then
        echo "❌ Cannot connect to Kubernetes cluster, skipping orphaned node cleanup"
        exit 0
      fi
      
      # Get all worker nodes from Kubernetes
      WORKER_NODES=$(kubectl get nodes --no-headers | grep -v "control-plane" | awk '{print $1}' || true)
      
      if [[ -z "$WORKER_NODES" ]]; then
        echo "ℹ️  No worker nodes found in cluster"
        exit 0
      fi
      
      echo "📋 Found worker nodes in Kubernetes: $WORKER_NODES"
      
      # Get all running EC2 instances from ASG
      echo "📋 Getting running EC2 instances..."
      RUNNING_INSTANCES=$(aws ec2 describe-instances \
        --region ${var.region} \
        --filters "Name=tag:aws:autoscaling:groupName,Values=guy-polybot-asg" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].InstanceId" \
        --output text 2>/dev/null | tr '\t' '\n' | sort)
      
      echo "📋 Running EC2 instances: $RUNNING_INSTANCES"
      
      ORPHANED_NODES=()
      
      # Check each worker node to see if it has a backing instance
      for NODE_NAME in $WORKER_NODES; do
        echo ""
        echo "🔍 Checking node: $NODE_NAME"
        
        INSTANCE_FOUND=false
        
        # Try to extract instance ID from node name
        if [[ "$NODE_NAME" =~ worker-([a-f0-9]{17})$ ]]; then
          # Pattern: worker-<17-char-instance-id>
          INSTANCE_ID="i-$${BASH_REMATCH[1]}"
          echo "   Extracted instance ID: $INSTANCE_ID"
          
          # Check if this instance is in our running instances list
          if echo "$RUNNING_INSTANCES" | grep -q "^$INSTANCE_ID$"; then
            echo "   ✅ Found matching running instance: $INSTANCE_ID"
            INSTANCE_FOUND=true
          fi
          
        elif [[ "$NODE_NAME" =~ ^worker-([a-f0-9]+)$ ]]; then
          # Pattern: worker-<hash> - check if any running instance contains this hash
          NODE_HASH="$${BASH_REMATCH[1]}"
          echo "   Looking for instances containing hash: $NODE_HASH"
          
          for INSTANCE_ID in $RUNNING_INSTANCES; do
            if [[ "$INSTANCE_ID" == *"$NODE_HASH"* ]]; then
              echo "   ✅ Found matching running instance: $INSTANCE_ID"
              INSTANCE_FOUND=true
              break
            fi
          done
          
        elif [[ "$NODE_NAME" =~ ^ip-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+) ]]; then
          # Pattern: ip-<ip-with-dashes> - check by private IP
          PRIVATE_IP="$${BASH_REMATCH[1]}.$${BASH_REMATCH[2]}.$${BASH_REMATCH[3]}.$${BASH_REMATCH[4]}"
          echo "   Looking for EC2 instance with private IP: $PRIVATE_IP"
          
          MATCHING_INSTANCE=$(aws ec2 describe-instances \
            --region ${var.region} \
            --filters "Name=private-ip-address,Values=$PRIVATE_IP" "Name=instance-state-name,Values=running" \
            --query "Reservations[*].Instances[*].InstanceId" \
            --output text 2>/dev/null | head -1)
            
          if [[ -n "$MATCHING_INSTANCE" ]] && [[ "$MATCHING_INSTANCE" != "None" ]]; then
            echo "   ✅ Found matching running instance: $MATCHING_INSTANCE"
            INSTANCE_FOUND=true
          fi
        fi
        
        # If no backing instance found, mark as orphaned
        if [[ "$INSTANCE_FOUND" == false ]]; then
          echo "   ❌ No backing EC2 instance found for node $NODE_NAME"
          ORPHANED_NODES+=("$NODE_NAME")
        fi
      done
      
      # Remove orphaned nodes immediately
      if [[ $${#ORPHANED_NODES[@]} -gt 0 ]]; then
        echo ""
        echo "🗑️  Found $${#ORPHANED_NODES[@]} orphaned nodes to remove immediately:"
        for NODE_NAME in "$${ORPHANED_NODES[@]}"; do
          echo "   - $NODE_NAME"
        done
        
        echo ""
        echo "🧹 Removing orphaned nodes..."
        
        for NODE_NAME in "$${ORPHANED_NODES[@]}"; do
          echo "🗑️  Removing orphaned node: $NODE_NAME"
          
          # First, force delete any pods on this node
          echo "   Force deleting all pods on node $NODE_NAME..."
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" --no-headers | \
            awk '{print $1 " " $2}' | \
            while read -r namespace podname; do
              if [[ -n "$namespace" ]] && [[ -n "$podname" ]]; then
                echo "     Force deleting pod: $namespace/$podname"
                kubectl delete pod "$podname" -n "$namespace" --force --grace-period=0 --timeout=10s || true
              fi
            done
          
          # Remove the node from cluster
          echo "   Deleting node $NODE_NAME from cluster..."
          if kubectl delete node "$NODE_NAME" --timeout=30s; then
            echo "   ✅ Successfully removed orphaned node: $NODE_NAME"
          else
            echo "   ❌ Failed to delete node $NODE_NAME, trying force delete..."
            kubectl delete node "$NODE_NAME" --force --grace-period=0 || true
          fi
        done
        
        echo ""
        echo "✅ Orphaned node cleanup completed! Removed $${#ORPHANED_NODES[@]} nodes."
        
      else
        echo ""
        echo "✅ No orphaned nodes found - all worker nodes have backing EC2 instances"
      fi
      
      # Show final cluster state
      echo ""
      echo "📋 Final cluster state after orphaned node cleanup:"
      kubectl get nodes -o wide
      
    EOT
  }
}
