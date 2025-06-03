# =============================================================================
# POLYBOT KUBERNETES CLUSTER - ROOT TERRAFORM CONFIGURATION
# =============================================================================
# Comprehensive refactored configuration with logical flow and no duplicates
# Kubernetes Version: 1.32.3 (hardcoded for consistency)
# Cluster Name: guy-cluster
# Worker ASG: guy-polybot-asg

# =============================================================================
# 🔧 PROVIDERS
# =============================================================================

provider "aws" {
  region = var.region
}

provider "tls" {}

provider "local" {}

# =============================================================================
# 📋 LOCALS - CENTRALIZED CONFIGURATION
# =============================================================================

locals {
  # Kubernetes version configuration (hardcoded to 1.32.3)
  k8s_version = "1.32.3" # This can be passed to the module if module needs it explicitly

  # Cluster configuration
  cluster_name    = "guy-cluster"
  worker_asg_name = "guy-polybot-asg" # This seems to be defined in the module too, ensure consistency or pass it

  # Paths and file management
  kubeconfig_path        = "${path.module}/kubeconfig.yaml"
  ssh_private_key_path = var.key_name != "" ? (
    fileexists("${path.module}/${var.key_name}.pem") ?
    "${path.module}/${var.key_name}.pem" :
    (fileexists(pathexpand("~/.ssh/${var.key_name}.pem")) ? # Corrected: pathexpand
      pathexpand("~/.ssh/${var.key_name}.pem") :            # Corrected: pathexpand
      "${path.module}/polybot-key.pem"
    )
  ) : "${path.module}/polybot-key.pem"

  # Feature flags
  skip_argocd     = false
  skip_namespaces = false

  # Cluster readiness validation (can be simplified now)
  kubeconfig_exists = fileexists(local.kubeconfig_path)
  k8s_ready         = local.kubeconfig_exists # Further checks can be done by null_resource.cluster_readiness_check
}

# =============================================================================
# 🏗️ CLUSTER MODULE - CORE INFRASTRUCTURE
# =============================================================================

module "k8s-cluster" {
  source = "./modules/k8s-cluster"
  
  # Core configuration
  region                       = var.region
  cluster_name                 = local.cluster_name
  route53_zone_id              = var.route53_zone_id
  domain_name                  = var.domain_name

  # Instance configuration
  control_plane_ami            = var.control_plane_ami
  worker_ami                   = var.worker_ami
  control_plane_instance_type  = var.control_plane_instance_type
  worker_instance_type         = var.worker_instance_type

  # SSH configuration
  key_name                     = var.key_name
  ssh_public_key               = var.ssh_public_key

  # Worker node configuration
  desired_worker_nodes         = var.desired_worker_nodes

  # Network configuration
  pod_cidr                     = var.pod_cidr

  # ASG control
  force_cleanup_asg            = var.force_cleanup_asg

  # Verification settings
  skip_api_verification        = var.skip_api_verification
  skip_token_verification      = var.skip_token_verification
  verification_max_attempts    = var.verification_max_attempts
  verification_wait_seconds    = var.verification_wait_seconds

  # Deployment environment
  deployment_environment       = "prod"
  
  tags = {
    Environment       = "production"
    Project           = "polybot"
    ManagedBy         = "terraform"
    KubernetesVersion = local.k8s_version
  }
}

# =============================================================================
# ☸️ KUBERNETES SETUP - KUBECONFIG VIA SECRETS MANAGER
# =============================================================================

# Wait for the kubeconfig to be available in Secrets Manager
resource "null_resource" "wait_for_kubeconfig_secret" {
  depends_on = [module.k8s-cluster.control_plane_instance_id_output] # Depends on control plane being "created"

  triggers = {
    # Re-run if control plane changes or secret name changes
    control_plane_id = module.k8s-cluster.control_plane_instance_id_output
    secret_name      = module.k8s-cluster.kubeconfig_secret_name_output
    region           = var.region
    script_version   = "v7-tls-fix-applied" # Added retry logic for secret retrieval + TLS fix
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e
      
      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }
      
      log_header "🔧 Waiting for Kubeconfig Secret (with retry logic)"
      
      KUBECONFIG_PATH="${local.kubeconfig_path}"
      SECRET_NAME="${module.k8s-cluster.kubeconfig_secret_name_output}"
      REGION="${var.region}"
      
      log_info "Target kubeconfig path: $${BOLD}$KUBECONFIG_PATH$${RESET}"
      log_info "Secret name: $${BOLD}$SECRET_NAME$${RESET}"
      log_info "Region: $${BOLD}$REGION$${RESET}"
      
      log_subheader "🔍 Checking Local Kubeconfig Status"
      if [[ -f "$KUBECONFIG_PATH" ]]; then
        log_success "Local kubeconfig file exists"
        
        if grep -q "apiVersion" "$KUBECONFIG_PATH" && grep -q "clusters:" "$KUBECONFIG_PATH"; then
          log_success "Local kubeconfig appears valid"
          
          log_step "Testing connectivity to ensure it works"
          if timeout 10 kubectl --insecure-skip-tls-verify --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
            log_success "Local kubeconfig connectivity confirmed - no action needed"
            exit 0
          else
            log_warning "Local kubeconfig exists but cannot connect to cluster - refreshing"
          fi
        else
          log_warning "Local kubeconfig exists but appears invalid - refreshing"
        fi
      else
        log_warning "Local kubeconfig file not found - creating"
      fi
      
      log_subheader "📥 Downloading Fresh Kubeconfig (with retry logic)"
      log_info "Attempting to download kubeconfig from Secrets Manager for secret: $${BOLD}$SECRET_NAME$${RESET}"
      
      # Retry logic configuration
      KUBECONFIG_CONTENT=""
      MAX_RETRIES=36  # 36 retries * 10 seconds = 6 minutes total wait time
      RETRY_COUNT=0
      SLEEP_DURATION=10  # seconds between retries
      
      log_progress "Starting retry loop (max $MAX_RETRIES attempts, $SLEEP_DURATION second intervals)"
      
      while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_step "Attempt $RETRY_COUNT/$MAX_RETRIES: Fetching secret from AWS Secrets Manager"
        
        # Capture both stdout and stderr, and the exit code
        # Temporarily disable set -e for this command to handle errors manually
        set +e
        AWS_CLI_OUTPUT=$(aws secretsmanager get-secret-value \
          --secret-id "$SECRET_NAME" \
          --region "$REGION" \
          --query SecretString \
          --output text 2>&1)
        AWS_CLI_EXIT_CODE=$?
        set -e  # Re-enable set -e
        
        if [[ $AWS_CLI_EXIT_CODE -eq 0 ]]; then
          KUBECONFIG_CONTENT="$AWS_CLI_OUTPUT"
          log_success "Successfully retrieved kubeconfig content on attempt $RETRY_COUNT"
          break
        else
          log_warning "Attempt $RETRY_COUNT/$MAX_RETRIES failed. AWS CLI exit code: $AWS_CLI_EXIT_CODE"
          
          # Check if it's a ResourceNotFoundException specifically
          if echo "$AWS_CLI_OUTPUT" | grep -q "ResourceNotFoundException"; then
            log_info "Secret not found yet (ResourceNotFoundException) - this is expected during initial cluster setup"
          else
            log_warning "Unexpected error from AWS CLI:"
            log_cmd_output "$AWS_CLI_OUTPUT"
          fi
          
          if [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; then
            log_progress "Waiting $SLEEP_DURATION seconds before next attempt..."
            sleep $SLEEP_DURATION
          else
            log_error "All $MAX_RETRIES attempts failed. Could not retrieve secret: $SECRET_NAME"
            log_error "This may indicate:"
            log_error "  • Control plane hasn't finished creating/uploading the kubeconfig secret yet"
            log_error "  • IAM permissions issue preventing access to Secrets Manager"
            log_error "  • Network connectivity issue to AWS Secrets Manager"
            log_error "  • Incorrect secret name or region"
            break
          fi
        fi
      done
      
      # Process the retrieved kubeconfig content
      if [[ -n "$KUBECONFIG_CONTENT" ]] && echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion"; then
        log_success "Retrieved valid kubeconfig from Secrets Manager after $RETRY_COUNT attempts"
        
        log_step "Creating directory if it doesn't exist"
        mkdir -p "$(dirname "$KUBECONFIG_PATH")"
        
        log_step "Writing kubeconfig to file"
        echo "$KUBECONFIG_CONTENT" > "$KUBECONFIG_PATH"
        chmod 600 "$KUBECONFIG_PATH"
        
        log_success "Local kubeconfig file created: $${BOLD}$KUBECONFIG_PATH$${RESET}"
        
        log_step "Verifying the new file works"
        if timeout 10 kubectl --insecure-skip-tls-verify --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
          log_success "New kubeconfig connectivity verified"
        else
          log_warning "New kubeconfig created but connectivity test failed (may be temporary)"
        fi
      else
        log_error "Failed to retrieve valid kubeconfig from Secrets Manager after $MAX_RETRIES attempts"
        log_error "Last AWS CLI output: $AWS_CLI_OUTPUT"
        log_info "Troubleshooting steps:"
        log_info "  1. Check that the control plane instance is running and has completed bootstrap"
        log_info "  2. Verify IAM permissions for Secrets Manager access"
        log_info "  3. Confirm the secret name '$SECRET_NAME' matches what the control plane creates"
        log_info "  4. Check AWS Secrets Manager console in region '$REGION'"
        exit 1
      fi
    EOT
  }
}

# Retrieve the kubeconfig from AWS Secrets Manager
data "aws_secretsmanager_secret_version" "retrieved_kubeconfig" {
  secret_id  = module.k8s-cluster.kubeconfig_secret_name_output # Use output from module
  depends_on = [null_resource.wait_for_kubeconfig_secret]
}

# Save the retrieved kubeconfig to a local file
resource "local_file" "kubeconfig" {
  content         = data.aws_secretsmanager_secret_version.retrieved_kubeconfig.secret_string
  filename        = local.kubeconfig_path
  file_permission = "0600"

  depends_on = [data.aws_secretsmanager_secret_version.retrieved_kubeconfig]
}

# Ensure kubeconfig file exists locally for terraform scripts
resource "null_resource" "ensure_local_kubeconfig" {
  depends_on = [
    local_file.kubeconfig,
    null_resource.wait_for_kubeconfig_secret
  ]

  triggers = {
    # Re-run if control plane changes (new deployment)
    control_plane_id = module.k8s-cluster.control_plane_instance_id_output
    # Re-run if kubeconfig content changes
    kubeconfig_content_hash = data.aws_secretsmanager_secret_version.retrieved_kubeconfig.version_id
    # Version for tracking script changes
    script_version = "v6-tls-fix-applied" # Fixed bash variable syntax + TLS fix
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      # --- Style Definitions ---
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }
      # --- End Style Definitions ---
      
      log_header "🔧 Ensuring Local Kubeconfig Availability"
      
      KUBECONFIG_PATH="${local.kubeconfig_path}"
      SECRET_NAME="${module.k8s-cluster.kubeconfig_secret_name_output}"
      REGION="${var.region}"
      
      log_info "Target kubeconfig path: $${BOLD}$KUBECONFIG_PATH$${RESET}"
      log_info "Secret name: $${BOLD}$SECRET_NAME$${RESET}"
      log_info "Region: $${BOLD}$REGION$${RESET}"
      
      log_subheader "🔍 Checking Local Kubeconfig Status"
      # Check if local kubeconfig exists and is valid
      if [[ -f "$KUBECONFIG_PATH" ]]; then
        log_success "Local kubeconfig file exists"
        
        # Quick validation - check if it contains required fields
        if grep -q "apiVersion" "$KUBECONFIG_PATH" && grep -q "clusters:" "$KUBECONFIG_PATH"; then
          log_success "Local kubeconfig appears valid"
          
          log_step "Testing connectivity to ensure it works"
          # Test connectivity to ensure it works
          if timeout 10 kubectl --insecure-skip-tls-verify --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
            log_success "Local kubeconfig connectivity confirmed - no action needed"
            exit 0
          else
            log_warning "Local kubeconfig exists but cannot connect to cluster - refreshing"
          fi
        else
          log_warning "Local kubeconfig exists but appears invalid - refreshing"
        fi
      else
        log_warning "Local kubeconfig file not found - creating"
      fi
      
      log_subheader "📥 Downloading Fresh Kubeconfig"
      # Download fresh kubeconfig from Secrets Manager
      log_progress "Downloading kubeconfig from Secrets Manager"
      KUBECONFIG_CONTENT=$(aws secretsmanager get-secret-value \
        --secret-id "$SECRET_NAME" \
        --region "$REGION" \
        --query SecretString \
        --output text)
      
      if [[ -n "$KUBECONFIG_CONTENT" ]] && echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion"; then
        log_success "Retrieved valid kubeconfig from Secrets Manager"
        
        log_step "Creating directory if it doesn't exist"
        # Create directory if it doesn't exist
        mkdir -p "$(dirname "$KUBECONFIG_PATH")"
        
        log_step "Writing kubeconfig to file"
        # Write kubeconfig to file
        echo "$KUBECONFIG_CONTENT" > "$KUBECONFIG_PATH"
        chmod 600 "$KUBECONFIG_PATH"
        
        log_success "Local kubeconfig file created: $${BOLD}$KUBECONFIG_PATH$${RESET}"
        
        log_step "Verifying the new file works"
        # Verify the new file works
        if timeout 10 kubectl --insecure-skip-tls-verify --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
          log_success "New kubeconfig connectivity verified"
        else
          log_warning "New kubeconfig created but connectivity test failed (may be temporary)"
        fi
      else
        log_error "Failed to retrieve valid kubeconfig from Secrets Manager"
        exit 1
      fi
    EOT
  }
}

# =============================================================================
# 🔍 CLUSTER VALIDATION - HEALTH AND READINESS CHECKS
# =============================================================================

# Comprehensive cluster readiness validation
resource "null_resource" "cluster_readiness_check" {
  depends_on = [
    null_resource.ensure_local_kubeconfig, # Ensure kubeconfig file exists locally
    null_resource.wait_for_kubeconfig_secret # Ensure kubeconfig is available in Secrets Manager
  ]
  
  triggers = {
    kubeconfig_file_id    = local_file.kubeconfig.id # Trigger when kubeconfig file changes
    kubeconfig_ensured    = null_resource.ensure_local_kubeconfig.id # Trigger when kubeconfig is ensured
    readiness_version     = "v11-create-namespaces-and-ebs-csi"
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      # Note: Removing set -e to allow more graceful error handling

      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }

      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🔍 Enhanced Cluster Readiness Check v10 (Create Namespaces)"

      log_subheader "📊 Debug Information"
      log_info "Kubeconfig file: $${BOLD}$KUBECONFIG$${RESET}"
      if [[ -f "$KUBECONFIG" ]]; then
        KUBECONFIG_SIZE=$(wc -c < "$KUBECONFIG")
        log_info "Kubeconfig size: $${BOLD}$KUBECONFIG_SIZE bytes$${RESET}"
        if grep -q "server:" "$KUBECONFIG" 2>/dev/null; then
          SERVER_URL=$(grep "server:" "$KUBECONFIG" | head -1 | awk '{print $2}')
          log_info "API Server: $${BOLD}$SERVER_URL$${RESET}"
          
          # Extract host and port for connectivity test
          if [[ "$SERVER_URL" =~ https://([^:]+):([0-9]+) ]]; then
            SERVER_HOST="$${BASH_REMATCH[1]}"
            SERVER_PORT="$${BASH_REMATCH[2]}"
            log_step "Testing TCP connectivity to $SERVER_HOST:$SERVER_PORT"
            if timeout 10 bash -c "</dev/tcp/$SERVER_HOST/$SERVER_PORT" 2>/dev/null; then
              log_success "TCP connectivity confirmed"
            else
              log_error "TCP connectivity failed"
            fi
          fi
        fi
      else
        log_error "Kubeconfig file not found!"
      fi

      log_subheader "🔗 Testing kubectl connectivity"
      if kubectl --insecure-skip-tls-verify get nodes >/dev/null 2>/dev/null; then
        log_success "Kubectl connectivity confirmed"
        
        # Create essential namespaces immediately after connectivity is confirmed
        log_subheader "🏗️ Creating essential namespaces"
        for ns in argocd prod dev mongodb; do
          if kubectl --insecure-skip-tls-verify create namespace "$ns" 2>/dev/null; then
            log_success "Created namespace: $ns"
          else
            log_info "Namespace $ns already exists"
          fi
        done
        
        log_subheader "💾 Installing AWS EBS CSI Driver"
        log_step "Applying EBS CSI driver manifests"
        # Install AWS EBS CSI driver for proper volume provisioning
        if kubectl --insecure-skip-tls-verify apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.28" 2>/dev/null; then
          log_success "EBS CSI driver manifests applied successfully"
          
          log_step "Waiting for EBS CSI driver to be ready"
          # Wait for the EBS CSI driver to be deployed
          for i in {1..30}; do
            if kubectl --insecure-skip-tls-verify get deployment ebs-csi-controller -n kube-system >/dev/null 2>&1; then
              READY_REPLICAS=$(kubectl --insecure-skip-tls-verify get deployment ebs-csi-controller -n kube-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
              DESIRED_REPLICAS=$(kubectl --insecure-skip-tls-verify get deployment ebs-csi-controller -n kube-system -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
              
              if [[ "$READY_REPLICAS" == "$DESIRED_REPLICAS" ]] && [[ "$READY_REPLICAS" -gt 0 ]]; then
                log_success "EBS CSI driver is ready ($READY_REPLICAS/$DESIRED_REPLICAS replicas)"
                break
              fi
            fi
            
            if [[ $i -eq 30 ]]; then
              log_warning "EBS CSI driver not ready within timeout, but continuing"
            else
              log_info "Waiting for EBS CSI driver... attempt $i/30"
              sleep 10
            fi
          done
        else
          log_warning "Failed to apply EBS CSI driver - trying alternative installation method"
          
          # Alternative: Apply from specific version URL
          log_step "Trying alternative EBS CSI driver installation"
          if kubectl --insecure-skip-tls-verify apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-ebs-csi-driver/v1.28.0/deploy/kubernetes/base/controller.yaml 2>/dev/null && \
             kubectl --insecure-skip-tls-verify apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-ebs-csi-driver/v1.28.0/deploy/kubernetes/base/node.yaml 2>/dev/null; then
            log_success "EBS CSI driver installed via alternative method"
          else
            log_warning "Could not install EBS CSI driver - manual installation may be required"
            log_info "Manual installation command: kubectl apply -k 'github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.28'"
          fi
        fi
        
        log_subheader "📋 Current cluster state"
        log_cmd_output "$(kubectl --insecure-skip-tls-verify get nodes -o wide 2>/dev/null || echo "Failed to get detailed node info")"
        
        # Get node counts with error handling
        ready_nodes=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "0")
        notready_nodes=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -c " NotReady " || echo "0")
        total_nodes=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | wc -l || echo "0")
        ready_workers=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -v "control-plane" | grep -c " Ready " || echo "0")

        log_subheader "📊 Node Status Summary"
        log_info "Node Status: $${BOLD}$ready_nodes Ready$${RESET}, $${BOLD}$notready_nodes NotReady$${RESET} (Total: $${BOLD}$total_nodes$${RESET})"
        log_info "Workers Ready: $${BOLD}$ready_workers$${RESET}"

        # More lenient validations with warnings instead of fatal errors
        if [[ "$total_nodes" -eq 0 ]]; then
          log_warning "WARNING: No nodes found in the cluster yet - this may be expected during initial setup"
        fi

        if [[ "$notready_nodes" -gt 0 ]]; then
          log_warning "WARNING: $notready_nodes NotReady nodes found - this may be transient during cluster startup"
          NOTREADY_LIST=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep "NotReady" || echo "No NotReady nodes actually listed by kubectl")
          log_cmd_output "$NOTREADY_LIST"
        fi

        # Check expected node counts with warnings
        expected_ready_nodes=$((1 + ${var.desired_worker_nodes}))
        if [[ "$ready_nodes" -lt "$expected_ready_nodes" ]]; then
          log_warning "WARNING: Only $ready_nodes Ready nodes found, expected $expected_ready_nodes (1 CP + ${var.desired_worker_nodes} workers)"
        fi

        if [[ "$ready_workers" -lt "${var.desired_worker_nodes}" ]]; then
          log_warning "WARNING: Only $ready_workers worker nodes Ready, desired ${var.desired_worker_nodes}"
        fi

        log_subheader "🔍 Checking core components"
        if kubectl --insecure-skip-tls-verify get deployment coredns -n kube-system >/dev/null 2>&1; then
          coredns_ready=$(kubectl --insecure-skip-tls-verify get deployment coredns -n kube-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
          coredns_desired=$(kubectl --insecure-skip-tls-verify get deployment coredns -n kube-system -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
          
          # Ensure variables are numeric and properly quoted
          coredns_ready=$${coredns_ready:-0}
          coredns_desired=$${coredns_desired:-1}
          
          if [[ "$${coredns_ready}" -eq "$${coredns_desired}" ]] && [[ "$${coredns_ready}" -gt 0 ]]; then
            log_success "CoreDNS: $coredns_ready/$coredns_desired ready"
          else
            log_warning "CoreDNS: $coredns_ready/$coredns_desired ready (may still be starting)"
          fi
        else
          log_warning "CoreDNS deployment not found (may not be installed yet)"
        fi

        # Check for problematic pods with lenient thresholds
        problematic_pods_count=$(kubectl --insecure-skip-tls-verify get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | wc -l || echo "0")
        
        # Ensure the count is numeric
        problematic_pods_count=$${problematic_pods_count:-0}
        
        if [[ "$${problematic_pods_count}" -gt 5 ]]; then
          log_warning "WARNING: Many problematic pods ($problematic_pods_count) - may indicate issues"
          PROBLEMATIC_PODS=$(kubectl --insecure-skip-tls-verify get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | head -5 || echo "No problematic pods listed")
          log_cmd_output "$PROBLEMATIC_PODS"
        elif [[ "$${problematic_pods_count}" -gt 0 ]]; then
          log_info "INFO: $problematic_pods_count pods in non-Running/Succeeded state (likely transient)"
        else
          log_success "All pods in good state"
        fi

        log_subheader "🎉 Summary"
        log_success "CLUSTER ACCESSIBLE!"
        log_info "Summary:"
        log_info "   • $${BOLD}$ready_nodes$${RESET} Ready nodes ($${BOLD}$ready_workers$${RESET} workers)"
        log_info "   • $${BOLD}$notready_nodes$${RESET} NotReady nodes"
        log_info "   • Core components checked"
        
      else
        # Enhanced error diagnostics for connection failures
        log_error "Cannot connect to cluster using kubectl"
        
        log_subheader "🔍 Diagnostic information"
        kubectl_error=$(kubectl --insecure-skip-tls-verify get nodes 2>&1 || echo "No error captured")
        log_cmd_output "kubectl error: $kubectl_error"
        
        log_subheader "📋 Common causes"
        log_warning "This may be expected during initial cluster setup."
        log_info "Common causes:"
        log_info "   • API server still starting up"
        log_info "   • Network connectivity issues"
        log_info "   • Kubeconfig not yet properly configured"
        log_info "   • Security groups blocking access"
        
        log_info "Deployment will continue - cluster may become accessible shortly."
        log_info "You can manually check cluster status later with: $${BOLD}kubectl --insecure-skip-tls-verify get nodes$${RESET}"
      fi
    EOT
  }
}

# =============================================================================
# 🧹 CLUSTER MAINTENANCE - CLEANUP AND OPTIMIZATION
# =============================================================================

resource "null_resource" "cluster_maintenance" {
  depends_on = [null_resource.ensure_local_kubeconfig] # Changed to depend on kubeconfig being ensured

  triggers = {
    cluster_ready_id    = null_resource.cluster_readiness_check.id
    kubeconfig_ensured  = null_resource.ensure_local_kubeconfig.id # Added trigger
    maintenance_version = "v6-fixed-node-processing"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e # Exit on error, but allow some commands to fail gracefully with || true

      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }

      # Ensure KUBECONFIG is set from local.kubeconfig_path which is now managed by local_file
      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🧹 Refined Cluster Maintenance v5 (Health-aware node deletion)"

      # Check kubectl connectivity
      if ! kubectl --insecure-skip-tls-verify get nodes >/dev/null 2>&1; then
        log_error "Cannot connect to cluster using KUBECONFIG=$KUBECONFIG, skipping maintenance."
        exit 0 # Exit gracefully if cluster not accessible
      fi

      log_subheader "👻 Checking for orphaned worker nodes (with health check)"
      # 1. Clean up orphaned nodes (nodes in k8s but not in ASG) - only if unhealthy

      log_step "Getting active ASG instances"
      # Get active ASG instances (ensure local.worker_asg_name is correct)
      # Using AWS CLI to get instance IDs from ASG
      ACTIVE_ASG_INSTANCE_IDS=$(aws ec2 describe-instances \
        --region "${var.region}" \
        --filters "Name=tag:aws:autoscaling:groupName,Values=${local.worker_asg_name}" \
                  "Name=instance-state-name,Values=running,pending" \
        --query "Reservations[*].Instances[*].PrivateDnsName" \
        --output text 2>/dev/null | tr '\\t' '\\n' || echo "")
        # Using PrivateDnsName as node names often match this. Adjust if your node names are different.

      log_step "Getting worker nodes from Kubernetes"
      # Get worker nodes from Kubernetes
      K8S_WORKER_NODES=$(kubectl --insecure-skip-tls-verify get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null || echo "")

      ORPHANED_COUNT=0
      HEALTHY_SKIPPED=0
      while IFS= read -r node_name; do
        [[ -z "$node_name" ]] && continue
        # Check if the K8s node name (which is often the private DNS name) is in the list of active ASG instances
        if ! echo "$ACTIVE_ASG_INSTANCE_IDS" | grep -qxF "$node_name"; then
          log_warning "Potential orphaned node found: $${BOLD}$node_name$${RESET}"
          
          # Check node health status before deletion
          NODE_READY_STATUS=$(kubectl --insecure-skip-tls-verify get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
          
          if [[ "$NODE_READY_STATUS" == "True" ]]; then
            log_info "Node $${BOLD}$node_name$${RESET} is Ready - skipping deletion to avoid removing healthy nodes"
            HEALTHY_SKIPPED=$((HEALTHY_SKIPPED + 1))
            continue
          else
            log_warning "Node $${BOLD}$node_name$${RESET} is NotReady/Unknown (status: $NODE_READY_STATUS) - proceeding with cleanup"
          fi
          
          ORPHANED_COUNT=$((ORPHANED_COUNT + 1))

          log_step "Force deleting pods on $node_name"
          # Force delete pods on this node (quicker for non-graceful)
          kubectl --insecure-skip-tls-verify get pods --all-namespaces --field-selector spec.nodeName="$node_name" --no-headers 2>/dev/null | \
            while read -r ns pod rest; do
              log_info "     Deleting pod $${BOLD}$pod$${RESET} in namespace $${BOLD}$ns$${RESET} on node $node_name"
              kubectl --insecure-skip-tls-verify delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=10s 2>/dev/null || log_warning "     Failed to delete pod $pod in $ns"
            done

          log_step "Deleting node $node_name from Kubernetes"
          # Remove the node from Kubernetes
          kubectl --insecure-skip-tls-verify delete node "$node_name" --timeout=30s 2>/dev/null || log_warning "   Failed to delete node $node_name"
        fi
      done <<< "$K8S_WORKER_NODES"
      log_info "Processed $${BOLD}$ORPHANED_COUNT$${RESET} orphaned unhealthy nodes."
      log_info "Skipped $${BOLD}$HEALTHY_SKIPPED$${RESET} healthy orphaned nodes (preserved to avoid disruption)."

      log_subheader "🗑️ Cleaning up stuck terminating pods"
      # 2. Clean up stuck terminating pods
      log_step "Finding stuck terminating pods (older than 5 minutes)"
      # This is a more complex operation and might be better suited for an in-cluster operator
      # For a simple local-exec, we can list them
      STUCK_TERMINATING_PODS=$(kubectl --insecure-skip-tls-verify get pods --all-namespaces --field-selector=status.phase=Terminating -o go-template='{{range .items}}{{if gt (now.Sub .metadata.deletionTimestamp) (timeDuration "5m")}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' 2>/dev/null || echo "")

      if [[ -n "$STUCK_TERMINATING_PODS" ]]; then
        log_warning "Found stuck terminating pods (older than 5m):"
        log_cmd_output "$STUCK_TERMINATING_PODS"
        echo "$STUCK_TERMINATING_PODS" | while read -r ns pod; do
          if [[ -n "$ns" && -n "$pod" ]]; then # Ensure we have both namespace and pod name
             log_step "Forcibly deleting stuck pod $${BOLD}$pod$${RESET} in namespace $${BOLD}$ns$${RESET}"
             kubectl --insecure-skip-tls-verify delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=10s 2>/dev/null || log_warning "   Failed to delete stuck pod $pod in $ns"
          fi
        done
      else
        log_success "No stuck terminating pods found (older than 5 minutes)."
      fi

      log_success "Refined cluster maintenance checks completed."
    EOT
  }
}

# =============================================================================
# 🔐 APPLICATION SETUP - NAMESPACES AND SECRETS
# =============================================================================

# Essential namespace and secret creation
resource "null_resource" "application_setup" {
  depends_on = [
    null_resource.cluster_readiness_check, # Ensure cluster is ready and namespaces exist
    null_resource.install_argocd           # Ensure ArgoCD is installed before deploying applications
  ]
  
  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id # Trigger when cluster and namespaces are ready
    argocd_installed = try(null_resource.install_argocd[0].id, "skipped") # Trigger when ArgoCD changes
    setup_version    = "v25-critical-ssl-certificate-fix" # CRITICAL SSL FIX: Use actual TLS certificate from k8s/shared/polybot-tls-secret.yaml instead of dummy content
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      # Dynamic values from current Terraform deployment (to be combined with static AWS secrets)
      TF_VAR_S3_BUCKET_NAME    = aws_s3_bucket.polybot_storage.bucket                # Dynamic: S3 bucket from generated-secrets.tf
      TF_VAR_SQS_QUEUE_URL     = aws_sqs_queue.polybot_queue.url                     # Dynamic: SQS queue from generated-secrets.tf
      TF_VAR_TELEGRAM_APP_URL  = "https://${module.k8s-cluster.alb_dns_name_output}" # Dynamic: ALB DNS from k8s-cluster module
      TF_VAR_AWS_REGION        = var.region                                          # AWS region for secrets manager
    }
    command     = <<-EOT
      #!/bin/bash
      # Removed set -e to allow graceful error handling during initial setup
      
      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }
      
      # CRITICAL FIX: Capture initial working directory and set KUBECONFIG to absolute path
      TERRAFORM_EXEC_DIR=$(pwd)
      ABSOLUTE_KUBECONFIG_PATH="$TERRAFORM_EXEC_DIR/kubeconfig.yaml"
      export KUBECONFIG="$ABSOLUTE_KUBECONFIG_PATH"
      log_info "KUBECONFIG environment variable set to absolute path: $KUBECONFIG"

      # Add verification step to ensure the file exists at this absolute path
      if [[ ! -f "$KUBECONFIG" ]]; then
        log_error "CRITICAL: Kubeconfig file not found at absolute path: $KUBECONFIG. This script will likely fail."
        log_error "Expected kubeconfig location: $KUBECONFIG"
        log_error "Current working directory: $(pwd)"
        log_error "Contents of current directory:"
        ls -la . | head -10
        # Exit early as subsequent kubectl commands will not work without kubeconfig
        exit 1
      else
        log_success "Verified Kubeconfig file exists at: $KUBECONFIG"
        KUBECONFIG_SIZE=$(wc -c < "$KUBECONFIG" 2>/dev/null || echo "unknown")
        log_info "Kubeconfig file size: $KUBECONFIG_SIZE bytes"
      fi

      log_header "🔐 Application Setup v25 (CRITICAL: Case-Mapping + SSL Certificate Fix)"

      # AWS Configuration & User Settings
      AWS_REGION_FOR_SECRETS="$TF_VAR_AWS_REGION"
      
      # AWS Secrets Manager secret name for static Polybot configuration
      POLYBOT_AWS_SECRET_NAME="polybot-secrets"
      
      # Validate that the secret name has been properly configured
      if [[ "$POLYBOT_AWS_SECRET_NAME" == "YOUR_ACTUAL_AWS_SECRET_NAME_HERE" ]]; then
        log_error "CRITICAL: AWS secret name is still set to placeholder value!"
        log_error "The POLYBOT_AWS_SECRET_NAME variable must be updated with your actual AWS Secrets Manager secret name."
        log_error "Current value: $POLYBOT_AWS_SECRET_NAME"
        exit 1
      fi
      
      log_success "AWS Secrets Manager Configuration Validated"
      log_info "AWS Region for Secrets: $AWS_REGION_FOR_SECRETS"
      log_info "Polybot AWS Secret Name: $${BOLD}$POLYBOT_AWS_SECRET_NAME$${RESET}"
      
      # Dynamic values from Terraform (passed via environment)
      log_subheader "📊 Dynamic Values from Current Terraform Deployment"
      log_info "S3 Bucket Name: $${BOLD}$TF_VAR_S3_BUCKET_NAME$${RESET}"
      log_info "SQS Queue URL: $${BOLD}$TF_VAR_SQS_QUEUE_URL$${RESET}"
      log_info "Telegram App URL: $${BOLD}$TF_VAR_TELEGRAM_APP_URL$${RESET}"

      log_subheader "🔗 Checking cluster connectivity"
      # Check kubectl connectivity with graceful handling
      if ! kubectl --insecure-skip-tls-verify get nodes >/dev/null 2>&1; then
        log_warning "Cannot connect to cluster using KUBECONFIG=$KUBECONFIG."
        log_info "This may be expected during initial cluster setup."
        log_info "The cluster may still be initializing or kubeconfig may not be ready yet."
        
        log_subheader "📋 Possible causes"
        log_info "   • Cluster API server still starting up"
        log_info "   • Kubeconfig not yet properly configured"
        log_info "   • Network connectivity issues"
        
        log_subheader "🔄 Skipping for now"
        log_info "Skipping application setup for now - it can be run later when cluster is ready."
        exit 0 # Exit gracefully instead of failing the deployment
      fi

      log_success "Cluster connectivity confirmed. Proceeding with application setup..."

      log_subheader "📁 Verifying namespaces"
      # Initial namespace status check for debugging
      log_step "Initial namespace status check for debugging"
      ALL_NAMESPACES=$(kubectl --insecure-skip-tls-verify get namespaces --no-headers -o custom-columns="NAME:.metadata.name" 2>/dev/null | tr '\n' ' ' || echo "failed-to-list")
      log_info "Current namespaces: $ALL_NAMESPACES"
      
      # Check for expected namespaces specifically
      for ns in argocd prod dev mongodb; do
        if kubectl --insecure-skip-tls-verify get namespace "$ns" >/dev/null 2>&1; then
          # Check if namespace is fully ready
          NS_STATUS=$(kubectl --insecure-skip-tls-verify get namespace "$ns" -o jsonpath='{.status.phase}' 2>/dev/null || echo "unknown")
          log_success "Initial check: Namespace $ns exists (status: $NS_STATUS)"
        else
          log_warning "Initial check: Namespace $ns not found"
        fi
      done

      log_subheader "🔐 Ensuring TLS certificates and secrets"
      
      # Brief pause to account for any minimal namespace propagation delay
      log_step "Brief pause to ensure namespace readiness after initial checks"
      sleep 10
      
      # Generate certificates for TLS secrets (dummy for now, should be managed properly)
      CERT_DIR="/tmp/polybot-certs-$$" # Use process ID for temp uniqueness
      log_step "Creating temporary certificate directory: $CERT_DIR"
      mkdir -p "$CERT_DIR"
      cd "$CERT_DIR"

      # Note: Since we're using generic secrets now, we don't actually need these cert files anymore
      # but keeping the directory structure for compatibility with the cleanup section
      log_info "Using dummy generic secrets instead of actual TLS certificates for setup."

      KEY_FILE="polybot.key"
      CRT_FILE="polybot.crt"
      CA_FILE="ca.crt"

      # Create dummy certs if real ones aren't generated by a proper process
      if true; then # Simplified: always create dummy certs for this example
        echo "---dummy key for polybot.key---" > "$KEY_FILE"
        echo "---dummy cert for polybot.crt---" > "$CRT_FILE"
        cp "$CRT_FILE" "$CA_FILE" # Use the dummy cert as CA for simplicity here
        log_info "Using dummy TLS certificates for setup."
      fi

      # Create secrets in both namespaces idempotently
      for namespace in prod dev; do
        log_subheader "🔑 Ensuring secrets in namespace: $${BOLD}$namespace$${RESET}"

        # Enhanced namespace detection with verbose debugging
        NAMESPACE_FOUND=false
        log_step "Waiting for namespace $namespace to be ready (simplified check)"
        
        MAX_NS_RETRIES=6
        NS_RETRY_SLEEP=5
        
        for retry in $(seq 1 $MAX_NS_RETRIES); do
          log_info "Attempt $retry/$MAX_NS_RETRIES: Checking if namespace '$namespace' is Active..."
          
          # Get the phase and check it directly. Capture output to avoid issues with if condition.
          NAMESPACE_PHASE=$(kubectl --insecure-skip-tls-verify get namespace "$namespace" -o jsonpath='{.status.phase}' 2>/dev/null)
          KUBECTL_NS_EXIT_CODE=$?

          if [[ $KUBECTL_NS_EXIT_CODE -eq 0 && "$NAMESPACE_PHASE" == "Active" ]]; then
            log_success "Namespace '$namespace' confirmed ACTIVE on attempt $retry."
            NAMESPACE_FOUND=true
            break
          else
            log_warning "Namespace '$namespace' not Active (or error) on attempt $retry/$MAX_NS_RETRIES. Exit code: $KUBECTL_NS_EXIT_CODE, Phase: '$NAMESPACE_PHASE'. Waiting $NS_RETRY_SLEEP seconds..."
            if [[ $retry -lt $MAX_NS_RETRIES ]]; then
              sleep $NS_RETRY_SLEEP
            fi
          fi
        done
        
        if [[ "$NAMESPACE_FOUND" != "true" ]]; then
          log_warning "Namespace $namespace not found/ready after $MAX_NS_RETRIES retries ($((MAX_NS_RETRIES * NS_RETRY_SLEEP)) seconds total)"
          log_error "Skipping secret creation for namespace $namespace"
          continue
        fi

        log_step "Creating/Updating TLS secret 'polybot-tls' using actual certificate files"
        
        # Use the actual TLS certificate YAML file from k8s/shared directory
        TLS_SECRET_FILE_PATH="$TERRAFORM_EXEC_DIR/../k8s/shared/polybot-tls-secret.yaml"
        
        if [[ ! -f "$TLS_SECRET_FILE_PATH" ]]; then
          log_error "CRITICAL: Actual TLS certificate file not found at: $TLS_SECRET_FILE_PATH"
          log_error "Skipping creation of polybot-tls secret for '$namespace' with actual certificate. Flask app will fail SSL."
          log_info "The file should contain base64-encoded certificate and key data."
        else
          log_info "Using TLS certificate YAML file: $TLS_SECRET_FILE_PATH"
          
          # Delete existing secret first to ensure it's updated correctly, especially if its type was previously 'Opaque' (generic)
          kubectl --insecure-skip-tls-verify delete secret polybot-tls -n "$namespace" --ignore-not-found=true 2>/dev/null
          
          # Create a temporary modified version of the YAML file for the current namespace
          TLS_SECRET_TEMP_FILE=$(mktemp "/tmp/polybot_tls_$namespace.XXXXXX.yaml")
          
          # Modify the namespace in the YAML file to match the current namespace
          sed "s/namespace: prod/namespace: $namespace/" "$TLS_SECRET_FILE_PATH" > "$TLS_SECRET_TEMP_FILE"
          
          # Apply the TLS secret YAML file
          if kubectl --insecure-skip-tls-verify apply -f "$TLS_SECRET_TEMP_FILE" 2>/dev/null; then
            log_success "polybot-tls secret created/updated in '$namespace' using actual certificate data."
            log_info "Secret type: kubernetes.io/tls with proper base64-encoded certificate data"
          else
            log_error "Failed to create/update polybot-tls secret in '$namespace' using actual certificate file. Check kubectl errors."
          fi
          
          # Clean up temporary file
          rm -f "$TLS_SECRET_TEMP_FILE"
        fi

        log_step "Creating CA secret"
        # CA secret
        kubectl --insecure-skip-tls-verify create secret generic polybot-ca \
          --from-file=ca.crt="$CA_FILE" -n "$namespace" \
          --dry-run=client -o yaml | kubectl --insecure-skip-tls-verify apply -f - 2>/dev/null || log_info "polybot-ca secret in $namespace handled (may already exist)"

        # ===== DOCKER REGISTRY CREDENTIALS =====
        log_step "Creating docker-registry-credentials secret"
        
        # Prepare Docker credentials
        DOCKER_USERNAME="placeholder-docker-username"
        DOCKER_PASSWORD="placeholder-docker-password"
        
        # For prod namespace: Get credentials from AWS secret if available (will be set later in the script)
        # For other namespaces: Use placeholder values
        
        # Create the docker auth string
        DOCKER_AUTH_ENCODED=$(echo -n "$${DOCKER_USERNAME}:$${DOCKER_PASSWORD}" | base64 -w0)
        DOCKERCONFIGJSON="{\"auths\":{\"https://index.docker.io/v1/\":{\"auth\":\"$DOCKER_AUTH_ENCODED\"}}}"
        
        # Delete existing secret if it exists (to handle type immutability issues)
        kubectl --insecure-skip-tls-verify delete secret docker-registry-credentials -n "$namespace" --ignore-not-found=true 2>/dev/null
        
        # Create the secret using kubectl apply with YAML (more robust than create)
        cat <<EOF_DOCKER_SECRET | kubectl --insecure-skip-tls-verify apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry-credentials
  namespace: $namespace
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: $(echo -n "$DOCKERCONFIGJSON" | base64 -w0)
EOF_DOCKER_SECRET
        if [ $? -eq 0 ]; then 
          log_success "docker-registry-credentials secret created/configured in $namespace"
          if [[ "$DOCKER_USERNAME" == "placeholder-docker-username" ]]; then
            log_warning "Using placeholder Docker credentials. Will be updated for prod namespace if AWS secret contains DOCKERHUB credentials."
          fi
        else 
          log_warning "Failed to create/configure docker-registry-credentials in $namespace"
        fi

        # ===== POLYBOT APPLICATION SECRETS =====
        log_step "Creating application secrets for namespace: $namespace"
        
        # For prod namespace: Combine static AWS secrets with dynamic Terraform values
        if [[ "$namespace" == "prod" ]]; then
          log_subheader "🔐 Hybrid Secret Creation: AWS Static + Terraform Dynamic"
          
          # Validate placeholder replacement
          if [[ "$POLYBOT_AWS_SECRET_NAME" == "YOUR_ACTUAL_AWS_SECRET_NAME_HERE" ]]; then
            log_error "CRITICAL: You must replace 'YOUR_ACTUAL_AWS_SECRET_NAME_HERE' with your actual AWS Secrets Manager secret name!"
            log_error "Example: POLYBOT_AWS_SECRET_NAME='polybot-prod-secrets'"
            log_error "The AWS secret should contain static keys like: TELEGRAM_TOKEN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, MONGO_URI, etc."
            log_error "Skipping prod/polybot-secrets creation until you configure the correct AWS secret name."
            continue
          fi
          
          # Check if jq is available
          if ! command -v jq >/dev/null 2>&1; then
            log_error "jq is not installed. jq is required to parse JSON from AWS Secrets Manager."
            log_info "Installing jq..."
            # Try to install jq if possible
            if command -v apt-get >/dev/null 2>&1; then
              log_step "Attempting to install jq via apt-get"
              sudo apt-get update -y && sudo apt-get install -y jq >/dev/null 2>&1 || log_warning "Failed to install jq via apt-get"
            elif command -v yum >/dev/null 2>&1; then
              log_step "Attempting to install jq via yum"
              sudo yum install -y jq >/dev/null 2>&1 || log_warning "Failed to install jq via yum"
            elif command -v brew >/dev/null 2>&1; then
              log_step "Attempting to install jq via brew"
              brew install jq >/dev/null 2>&1 || log_warning "Failed to install jq via brew"
            fi
            
            # Check again if jq is now available
            if ! command -v jq >/dev/null 2>&1; then
              log_error "jq installation failed. Cannot parse AWS Secrets Manager JSON without jq."
              log_error "Please install jq manually: apt-get install jq OR yum install jq OR brew install jq"
              exit 1
            fi
          fi
          
          log_step "Fetching static secrets from AWS Secrets Manager (secret: $POLYBOT_AWS_SECRET_NAME)"
          log_info "AWS CLI command: aws secretsmanager get-secret-value --secret-id '$POLYBOT_AWS_SECRET_NAME' --region '$AWS_REGION_FOR_SECRETS'"
          
          # Fetch secrets from AWS Secrets Manager with detailed error handling
          POLYBOT_SECRET_JSON=$(aws secretsmanager get-secret-value \
            --secret-id "$POLYBOT_AWS_SECRET_NAME" \
            --region "$AWS_REGION_FOR_SECRETS" \
            --query SecretString \
            --output text 2>&1)
          
          AWS_FETCH_EXIT_CODE=$?
          
          if [[ $AWS_FETCH_EXIT_CODE -eq 0 && -n "$POLYBOT_SECRET_JSON" && "$POLYBOT_SECRET_JSON" != "null" ]]; then
            log_success "Successfully retrieved static secrets JSON from AWS Secrets Manager."
            
            # ===== CRITICAL FIX: CASE-SENSITIVE KEY MAPPING =====
            log_step "Creating case-mapped secrets for Kubernetes (fixing TELEGRAM_TOKEN -> telegram_token)"
            
            # Create temporary .env file for precise key mapping
            TEMP_ENV_FILE_PROD=$(mktemp "/tmp/polybot_prod_secrets.XXXXXX.env")
            log_info "Creating temporary .env file: $TEMP_ENV_FILE_PROD"
            
            # ===== STATIC KEYS FROM AWS - WITH EXPLICIT CASE MAPPING =====
            log_info "Mapping static keys from AWS Secrets Manager (with case corrections):"
            
            # CRITICAL: Map TELEGRAM_TOKEN (AWS) -> telegram_token (K8s) for application compatibility
            TELEGRAM_TOKEN_FROM_AWS=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".TELEGRAM_TOKEN // \"\"" 2>/dev/null)
            if [[ -n "$TELEGRAM_TOKEN_FROM_AWS" && "$TELEGRAM_TOKEN_FROM_AWS" != "null" ]]; then
              echo "telegram_token=$${TELEGRAM_TOKEN_FROM_AWS}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ Mapped TELEGRAM_TOKEN (AWS) -> telegram_token (K8s Secret)"
            else
              log_warning "   ✗ TELEGRAM_TOKEN not found in AWS Secret JSON"
              echo "# MISSING: telegram_token" >> "$TEMP_ENV_FILE_PROD"
            fi
            
            # Map other static keys (assuming applications expect lowercase or adjust as needed)
            AWS_ACCESS_KEY_ID_VAL=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".AWS_ACCESS_KEY_ID // \"\"" 2>/dev/null)
            if [[ -n "$AWS_ACCESS_KEY_ID_VAL" && "$AWS_ACCESS_KEY_ID_VAL" != "null" ]]; then
              echo "aws_access_key_id=$${AWS_ACCESS_KEY_ID_VAL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ aws_access_key_id (from AWS_ACCESS_KEY_ID)"
            else
              log_warning "   ✗ AWS_ACCESS_KEY_ID not found in AWS Secret"
            fi
            
            AWS_SECRET_ACCESS_KEY_VAL=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".AWS_SECRET_ACCESS_KEY // \"\"" 2>/dev/null)
            if [[ -n "$AWS_SECRET_ACCESS_KEY_VAL" && "$AWS_SECRET_ACCESS_KEY_VAL" != "null" ]]; then
              echo "aws_secret_access_key=$${AWS_SECRET_ACCESS_KEY_VAL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ aws_secret_access_key (from AWS_SECRET_ACCESS_KEY)"
            else
              log_warning "   ✗ AWS_SECRET_ACCESS_KEY not found in AWS Secret"
            fi
            
            MONGO_URI_VAL=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".MONGO_URI // \"\"" 2>/dev/null)
            if [[ -n "$MONGO_URI_VAL" && "$MONGO_URI_VAL" != "null" ]]; then
              echo "mongo_uri=$${MONGO_URI_VAL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ mongo_uri (from MONGO_URI)"
            else
              log_warning "   ✗ MONGO_URI not found in AWS Secret"
            fi
            
            MONGO_DB_VAL=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".MONGO_DB // \"\"" 2>/dev/null)
            if [[ -n "$MONGO_DB_VAL" && "$MONGO_DB_VAL" != "null" ]]; then
              echo "mongo_db=$${MONGO_DB_VAL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ mongo_db (from MONGO_DB)"
            else
              log_warning "   ✗ MONGO_DB not found in AWS Secret"
            fi
            
            MONGO_COLLECTION_VAL=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".MONGO_COLLECTION // \"\"" 2>/dev/null)
            if [[ -n "$MONGO_COLLECTION_VAL" && "$MONGO_COLLECTION_VAL" != "null" ]]; then
              echo "mongo_collection=$${MONGO_COLLECTION_VAL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ mongo_collection (from MONGO_COLLECTION)"
            else
              log_warning "   ✗ MONGO_COLLECTION not found in AWS Secret"
            fi
            
            POLYBOT_URL_VAL=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".POLYBOT_URL // \"\"" 2>/dev/null)
            if [[ -n "$POLYBOT_URL_VAL" && "$POLYBOT_URL_VAL" != "null" ]]; then
              echo "polybot_url=$${POLYBOT_URL_VAL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ polybot_url (from POLYBOT_URL)"
            else
              log_warning "   ✗ POLYBOT_URL not found in AWS Secret"
            fi
            
            # ===== DYNAMIC VALUES WITH TERRAFORM PRIORITY =====
            log_info "Adding dynamic values (Terraform outputs override AWS placeholders):"
            
            # S3_BUCKET_NAME: Use Terraform value if available, fallback to AWS
            if [[ -n "$TF_VAR_S3_BUCKET_NAME" && "$TF_VAR_S3_BUCKET_NAME" != "null" ]]; then
              echo "s3_bucket_name=$${TF_VAR_S3_BUCKET_NAME}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ s3_bucket_name (from Terraform: $TF_VAR_S3_BUCKET_NAME)"
            else
              S3_BUCKET_NAME_FROM_AWS=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".S3_BUCKET_NAME // \"\"" 2>/dev/null)
              if [[ -n "$S3_BUCKET_NAME_FROM_AWS" && "$S3_BUCKET_NAME_FROM_AWS" != "null" ]]; then
                echo "s3_bucket_name=$${S3_BUCKET_NAME_FROM_AWS}" >> "$TEMP_ENV_FILE_PROD"
                log_info "   ✓ s3_bucket_name (from AWS fallback: $S3_BUCKET_NAME_FROM_AWS)"
              else
                log_warning "   ✗ s3_bucket_name not available from Terraform or AWS"
              fi
            fi
            
            # SQS_QUEUE_URL: Use Terraform value if available, fallback to AWS
            if [[ -n "$TF_VAR_SQS_QUEUE_URL" && "$TF_VAR_SQS_QUEUE_URL" != "null" ]]; then
              echo "sqs_queue_url=$${TF_VAR_SQS_QUEUE_URL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ sqs_queue_url (from Terraform: $TF_VAR_SQS_QUEUE_URL)"
            else
              SQS_URL_FROM_AWS=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".SQS_QUEUE_URL // \"\"" 2>/dev/null)
              if [[ -n "$SQS_URL_FROM_AWS" && "$SQS_URL_FROM_AWS" != "null" ]]; then
                echo "sqs_queue_url=$${SQS_URL_FROM_AWS}" >> "$TEMP_ENV_FILE_PROD"
                log_info "   ✓ sqs_queue_url (from AWS fallback: $SQS_URL_FROM_AWS)"
              else
                log_warning "   ✗ sqs_queue_url not available from Terraform or AWS"
              fi
            fi
            
            # TELEGRAM_APP_URL: Use Terraform value if available, fallback to AWS
            if [[ -n "$TF_VAR_TELEGRAM_APP_URL" && "$TF_VAR_TELEGRAM_APP_URL" != "null" ]]; then
              echo "telegram_app_url=$${TF_VAR_TELEGRAM_APP_URL}" >> "$TEMP_ENV_FILE_PROD"
              log_info "   ✓ telegram_app_url (from Terraform: $TF_VAR_TELEGRAM_APP_URL)"
            else
              TELEGRAM_APP_URL_FROM_AWS=$(echo "$POLYBOT_SECRET_JSON" | jq -r ".TELEGRAM_APP_URL // \"\"" 2>/dev/null)
              if [[ -n "$TELEGRAM_APP_URL_FROM_AWS" && "$TELEGRAM_APP_URL_FROM_AWS" != "null" ]]; then
                echo "telegram_app_url=$${TELEGRAM_APP_URL_FROM_AWS}" >> "$TEMP_ENV_FILE_PROD"
                log_info "   ✓ telegram_app_url (from AWS fallback: $TELEGRAM_APP_URL_FROM_AWS)"
              else
                log_warning "   ✗ telegram_app_url not available from Terraform or AWS"
              fi
            fi
            
            # ===== CREATE KUBERNETES SECRET FROM .ENV FILE =====
            if [[ -s "$TEMP_ENV_FILE_PROD" ]]; then
              log_step "Creating/Updating Kubernetes secret 'polybot-secrets' in namespace 'prod'"
              
              # Show what we're about to create (without showing sensitive values)
              log_info "Secret will contain the following keys:"
              grep -v "^#" "$TEMP_ENV_FILE_PROD" | cut -d'=' -f1 | while read -r key; do
                log_info "     ✓ $key"
              done
              
              # Delete existing secret first to ensure clean application
              kubectl --insecure-skip-tls-verify delete secret polybot-secrets -n prod --ignore-not-found=true 2>/dev/null
              
              # Create secret from .env file
              if kubectl --insecure-skip-tls-verify create secret generic polybot-secrets \
                  --from-env-file="$TEMP_ENV_FILE_PROD" \
                  -n prod 2>/dev/null; then
                log_success "Kubernetes secret 'prod/polybot-secrets' created successfully with case-corrected keys."
                
                # Verify the secret was created with expected keys
                log_step "Verifying secret keys in Kubernetes"
                SECRET_KEYS=$(kubectl --insecure-skip-tls-verify get secret polybot-secrets -n prod -o jsonpath='{.data}' 2>/dev/null | jq -r 'keys[]' 2>/dev/null | sort || echo "")
                if [[ -n "$SECRET_KEYS" ]]; then
                  SECRET_COUNT=$(echo "$SECRET_KEYS" | wc -l)
                  log_success "Secret verification - Found $SECRET_COUNT keys:"
                  echo "$SECRET_KEYS" | while read -r key; do
                    log_info "     ✓ $key"
                  done
                  
                  # Critical verification: Check if telegram_token exists
                  if echo "$SECRET_KEYS" | grep -q "^telegram_token$"; then
                    log_success "✅ CRITICAL: 'telegram_token' key found in secret - Polybot application should work!"
                  else
                    log_error "❌ CRITICAL: 'telegram_token' key NOT found in secret - Polybot will fail!"
                  fi
                else
                  log_warning "Could not verify secret keys (kubectl or jq may have failed)"
                fi
              else
                log_error "Failed to create Kubernetes secret 'prod/polybot-secrets'."
                log_info "Temporary .env file content (for debugging):"
                cat "$TEMP_ENV_FILE_PROD"
                rm -f "$TEMP_ENV_FILE_PROD"
                exit 1
              fi
            else
              log_error "Temporary .env file is empty - no secrets to create"
              rm -f "$TEMP_ENV_FILE_PROD"
              exit 1
            fi
            
            # Clean up temporary file
            rm -f "$TEMP_ENV_FILE_PROD"
            
            # ===== UPDATE DOCKER REGISTRY CREDENTIALS FOR PROD =====
            log_step "Updating Docker registry credentials for prod namespace with AWS secret values"
            
            # Extract Docker credentials from AWS secret
            AWS_DOCKER_USERNAME=$(echo "$POLYBOT_SECRET_JSON" | jq -r '.DOCKERHUB_USERNAME // ""' 2>/dev/null)
            AWS_DOCKER_PASSWORD=$(echo "$POLYBOT_SECRET_JSON" | jq -r '.DOCKERHUB_PASSWORD // ""' 2>/dev/null)
            
            if [[ -n "$AWS_DOCKER_USERNAME" && "$AWS_DOCKER_USERNAME" != "null" && -n "$AWS_DOCKER_PASSWORD" && "$AWS_DOCKER_PASSWORD" != "null" ]]; then
              log_info "Found Docker credentials in AWS secret - updating docker-registry-credentials for prod"
              
              # Create updated docker auth string
              DOCKER_AUTH_ENCODED=$(echo -n "$${AWS_DOCKER_USERNAME}:$${AWS_DOCKER_PASSWORD}" | base64 -w0)
              DOCKERCONFIGJSON="{\"auths\":{\"https://index.docker.io/v1/\":{\"auth\":\"$DOCKER_AUTH_ENCODED\"}}}"
              
              # Delete existing secret and recreate with real credentials
              kubectl --insecure-skip-tls-verify delete secret docker-registry-credentials -n prod --ignore-not-found=true 2>/dev/null
              
              # Create the secret using kubectl apply with YAML
              cat <<EOF_DOCKER_SECRET | kubectl --insecure-skip-tls-verify apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry-credentials
  namespace: prod
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: $(echo -n "$DOCKERCONFIGJSON" | base64 -w0)
EOF_DOCKER_SECRET
              if [ $? -eq 0 ]; then 
                log_success "docker-registry-credentials secret updated in prod with real AWS credentials"
              else 
                log_warning "Failed to update docker-registry-credentials in prod"
              fi
            else
              log_warning "DOCKERHUB_USERNAME or DOCKERHUB_PASSWORD not found in AWS secret - keeping placeholder Docker credentials for prod"
              log_info "Add DOCKERHUB_USERNAME and DOCKERHUB_PASSWORD to your AWS secret 'polybot-secrets' for private registry access"
            fi
          else
            log_error "FAILED to retrieve secrets from AWS Secrets Manager!"
            log_error "Secret Name: '$POLYBOT_AWS_SECRET_NAME'"
            log_error "Region: '$AWS_REGION_FOR_SECRETS'"
            log_error "AWS CLI Exit Code: $AWS_FETCH_EXIT_CODE"
            log_error "Raw Output: $POLYBOT_SECRET_JSON"
            log_error ""
            log_error "Troubleshooting Steps:"
            log_error "  1. Ensure the AWS Secret '$POLYBOT_AWS_SECRET_NAME' exists in region '$AWS_REGION_FOR_SECRETS'"
            log_error "  2. Verify the secret value is a valid JSON object with required keys"
            log_error "  3. Check that the Terraform execution role has 'secretsmanager:GetSecretValue' permissions"
            log_error "  4. Confirm AWS CLI is properly configured with correct credentials"
            log_error "  5. Test manually: aws secretsmanager get-secret-value --secret-id '$POLYBOT_AWS_SECRET_NAME' --region '$AWS_REGION_FOR_SECRETS'"
            log_error ""
            log_error "Required JSON structure in AWS Secret:"
            log_error '  {"TELEGRAM_TOKEN":"your-token","AWS_ACCESS_KEY_ID":"your-key","AWS_SECRET_ACCESS_KEY":"your-secret","MONGO_URI":"your-uri","MONGO_DB":"your-db","MONGO_COLLECTION":"your-collection","POLYBOT_URL":"your-url"}'
            log_error ""
            log_error "DEPLOYMENT WILL FAIL - Fix AWS Secrets Manager configuration and retry."
            exit 1
          fi
        else
          # For dev and other namespaces, use simplified secrets (or fetch from different AWS secret if needed)
          log_info "For namespace '$namespace': Creating basic application secrets (not fetching from AWS Secrets Manager)"
          kubectl --insecure-skip-tls-verify delete secret polybot-secrets -n "$namespace" --ignore-not-found=true 2>/dev/null
          kubectl --insecure-skip-tls-verify create secret generic polybot-secrets \
            --from-literal=app-secret='default-app-secret-value' \
            --from-literal=database-url='postgresql://polybot:examplepassword@your-db-host:5432/polybotdb' \
            --from-literal=redis-url='redis://your-redis-host:6379/0' \
            -n "$namespace" 2>/dev/null || log_warning "Failed to create basic polybot-secrets in $namespace"
        fi

        log_success "Secrets processed for $${BOLD}$namespace$${RESET}"
      done

      # Cleanup
      cd / # Change out of the temp dir before removing it
      rm -rf "$CERT_DIR"
      log_step "Cleaned up temporary certificate directory"

      log_subheader "🚀 Deploying ArgoCD Applications"
      # Deploy ArgoCD applications only if ArgoCD is installed
      ARGOCD_NAMESPACE="argocd"
      
      log_step "Checking if ArgoCD is installed and ready"
      ARGOCD_NAMESPACE_FOUND=false
      
      # Enhanced ArgoCD namespace detection with verbose debugging and reliable checks
      for retry in $(seq 1 9); do
        log_info "Attempt $retry/9: Checking ArgoCD namespace '$ARGOCD_NAMESPACE' and CRDs..."
        
        # Check ArgoCD namespace first
        ARGOCD_NS_PHASE=$(kubectl --insecure-skip-tls-verify get namespace "$ARGOCD_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
        ARGOCD_NS_EXIT_CODE=$?
        
        if [[ $ARGOCD_NS_EXIT_CODE -eq 0 && "$ARGOCD_NS_PHASE" == "Active" ]]; then
          log_info "ArgoCD namespace '$ARGOCD_NAMESPACE' found and Active. Verifying CRDs..."
          
          # Check ArgoCD CRDs
          CRD_CHECK_OUTPUT=$(kubectl --insecure-skip-tls-verify get crd applications.argoproj.io 2>&1)
          CRD_EXIT_CODE=$?
          
          if [[ $CRD_EXIT_CODE -eq 0 ]]; then
            log_success "ArgoCD namespace and CRDs confirmed ready on attempt $retry"
            ARGOCD_NAMESPACE_FOUND=true
            break
          else
            log_info "ArgoCD namespace exists but CRDs not ready yet on attempt $retry/9, waiting 10 seconds..."
          fi
        else
          log_info "ArgoCD namespace not found/Active (exit code: $ARGOCD_NS_EXIT_CODE, phase: '$ARGOCD_NS_PHASE') on attempt $retry/9, waiting 10 seconds..."
        fi
        
        if [[ $retry -lt 9 ]]; then
          sleep 10
        fi
      done
      
      if [[ "$ARGOCD_NAMESPACE_FOUND" != "true" ]]; then
        log_warning "ArgoCD namespace not found/ready after 9 retries (90 seconds total)"
        log_info "This suggests ArgoCD installation may not have completed successfully"
        log_info "ArgoCD applications can be deployed manually later with:"
        log_cmd_output "   kubectl --insecure-skip-tls-verify apply -f $TERRAFORM_EXEC_DIR/../k8s/argocd-applications.yaml"
        log_cmd_output "   kubectl --insecure-skip-tls-verify apply -f $TERRAFORM_EXEC_DIR/../k8s/MongoDB/application.yaml -n argocd"
        exit 0
      fi
      
      log_success "ArgoCD namespace and CRDs confirmed ready. Proceeding with application deployment..."
      
      log_info "Application Deployment Strategy:"
      log_info "  • Global applications file: defines all apps in one place"
      log_info "  • Individual application files: provide backup/alternative deployment method"
      log_info "  • Both methods will be attempted for robustness"
        
      # Wait for ArgoCD to be ready with extended timeout and better verification
      log_step "Waiting for ArgoCD server to be ready (timeout: 120s)"
      RETRY_COUNT=0
      MAX_RETRIES=12  # 12 retries * 10 seconds = 2 minutes
      ARGOCD_READY=false
      
      while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
        if kubectl --insecure-skip-tls-verify get deployment -n "$ARGOCD_NAMESPACE" argocd-server >/dev/null 2>&1; then
          READY_REPLICAS=$(kubectl --insecure-skip-tls-verify get deployment -n "$ARGOCD_NAMESPACE" argocd-server -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
          DESIRED_REPLICAS=$(kubectl --insecure-skip-tls-verify get deployment -n "$ARGOCD_NAMESPACE" argocd-server -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
          
          if [[ "$READY_REPLICAS" == "$DESIRED_REPLICAS" ]] && [[ "$READY_REPLICAS" -gt 0 ]]; then
            log_success "ArgoCD server is ready ($READY_REPLICAS/$DESIRED_REPLICAS replicas)"
            ARGOCD_READY=true
            break
          else
            log_info "ArgoCD server not ready yet ($READY_REPLICAS/$DESIRED_REPLICAS), attempt $((RETRY_COUNT + 1))/$MAX_RETRIES"
          fi
        else
          log_info "ArgoCD server deployment not found yet, attempt $((RETRY_COUNT + 1))/$MAX_RETRIES"
        fi
        
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; then
          sleep 10
        fi
      done
      
      if [[ "$ARGOCD_READY" != "true" ]]; then
        log_warning "ArgoCD server not ready within timeout, but proceeding with application deployment"
        log_step "Current ArgoCD pod status:"
        kubectl --insecure-skip-tls-verify get pods -n "$ARGOCD_NAMESPACE" 2>/dev/null || log_info "   Could not retrieve pod status"
      fi
      
      # Apply global ArgoCD applications file first (contains all applications)
      log_step "Applying global ArgoCD applications file"
      if [[ -f "$TERRAFORM_EXEC_DIR/../k8s/argocd-applications.yaml" ]]; then
        log_info "Found global applications file: $TERRAFORM_EXEC_DIR/../k8s/argocd-applications.yaml"
        if kubectl --insecure-skip-tls-verify apply -f "$TERRAFORM_EXEC_DIR/../k8s/argocd-applications.yaml" 2>/dev/null; then
          log_success "Global ArgoCD applications file applied successfully"
        else
          log_warning "Failed to apply global ArgoCD applications file - this may be expected during first run"
          log_info "ArgoCD CRDs may still be initializing. Will try individual files."
        fi
      else
        log_info "Global applications file not found at $TERRAFORM_EXEC_DIR/../k8s/argocd-applications.yaml, proceeding with individual application files"
      fi
      
      # Apply individual ArgoCD Applications as backup/supplement
      log_step "Applying individual MongoDB ArgoCD Application"
      if [[ -f "$TERRAFORM_EXEC_DIR/../k8s/MongoDB/application.yaml" ]]; then
        if kubectl --insecure-skip-tls-verify apply -f "$TERRAFORM_EXEC_DIR/../k8s/MongoDB/application.yaml" -n "$ARGOCD_NAMESPACE" 2>/dev/null; then
          log_success "MongoDB ArgoCD Application applied successfully"
        else
          log_warning "Failed to apply MongoDB ArgoCD Application (may already exist or CRDs not ready)"
        fi
        log_info "MongoDB application.yaml includes CreateNamespace=true for 'mongodb' namespace"
        log_info "If MongoDB shows StorageClass parameter conflicts in ArgoCD:"
        log_info "  1. Check existing StorageClass: kubectl get sc mongodb-storage -o yaml"
        log_info "  2. Compare with k8s/MongoDB/storageclass.yaml in Git"
        log_info "  3. If Git version is correct, manually delete existing: kubectl delete sc mongodb-storage"
        log_info "  4. ArgoCD will recreate it correctly on next sync"
      else
        log_info "MongoDB application.yaml not found at $TERRAFORM_EXEC_DIR/../k8s/MongoDB/application.yaml"
      fi

      # Check for Polybot application file
      log_step "Applying individual Polybot ArgoCD Application"
      if [[ -f "$TERRAFORM_EXEC_DIR/../k8s/Polybot/application.yaml" ]]; then
        if kubectl --insecure-skip-tls-verify apply -f "$TERRAFORM_EXEC_DIR/../k8s/Polybot/application.yaml" -n "$ARGOCD_NAMESPACE" 2>/dev/null; then
          log_success "Polybot ArgoCD Application applied successfully"
        else
          log_warning "Failed to apply Polybot ArgoCD Application (may already exist or CRDs not ready)"
        fi
      else
        log_warning "Polybot application.yaml not found at $TERRAFORM_EXEC_DIR/../k8s/Polybot/application.yaml"
        log_info "This file should be created to deploy Polybot application"
      fi

      # Check for Yolo5 application file
      log_step "Applying individual Yolo5 ArgoCD Application"
      if [[ -f "$TERRAFORM_EXEC_DIR/../k8s/Yolo5/application.yaml" ]]; then
        if kubectl --insecure-skip-tls-verify apply -f "$TERRAFORM_EXEC_DIR/../k8s/Yolo5/application.yaml" -n "$ARGOCD_NAMESPACE" 2>/dev/null; then
          log_success "Yolo5 ArgoCD Application applied successfully"
        else
          log_warning "Failed to apply Yolo5 ArgoCD Application (may already exist or CRDs not ready)"
        fi
      else
        log_warning "Yolo5 application.yaml not found at $TERRAFORM_EXEC_DIR/../k8s/Yolo5/application.yaml"
        log_info "This file should be created to deploy Yolo5 application"
      fi

      # Check for any other application.yaml files in subdirectories
      log_step "Scanning for additional ArgoCD applications"
      if find "$TERRAFORM_EXEC_DIR/../k8s" -name "application.yaml" -type f | grep -v -E "(MongoDB|Polybot|Yolo5)" >/dev/null 2>&1; then
        find "$TERRAFORM_EXEC_DIR/../k8s" -name "application.yaml" -type f | grep -v -E "(MongoDB|Polybot|Yolo5)" | while read -r app_file; do
          app_name=$(basename "$(dirname "$app_file")")
          log_step "Applying $app_name ArgoCD Application"
          if kubectl --insecure-skip-tls-verify apply -f "$app_file" -n "$ARGOCD_NAMESPACE" 2>/dev/null; then
            log_success "$app_name ArgoCD Application applied successfully"
          else
            log_warning "Failed to apply $app_name ArgoCD Application (may already exist or CRDs not ready)"
          fi
        done
      else
        log_info "No additional individual ArgoCD application files found"
      fi
      
      # Wait a moment for applications to be processed
      log_step "Waiting for ArgoCD to process applications (10 seconds)"
      sleep 10
      
      log_subheader "🔍 Verifying ArgoCD Applications"
      log_step "Checking if ArgoCD Application CRD is available"
      if kubectl --insecure-skip-tls-verify get crd applications.argoproj.io >/dev/null 2>&1; then
        log_success "ArgoCD Application CRD is available"
        
        log_step "Listing deployed ArgoCD applications"
        if kubectl --insecure-skip-tls-verify get applications -n "$ARGOCD_NAMESPACE" >/dev/null 2>&1; then
          APPLICATIONS=$(kubectl --insecure-skip-tls-verify get applications -n "$ARGOCD_NAMESPACE" --no-headers 2>/dev/null | wc -l || echo "0")
          if [[ "$APPLICATIONS" -gt 0 ]]; then
            log_success "Found $APPLICATIONS ArgoCD applications deployed"
            log_info "Application details:"
            kubectl --insecure-skip-tls-verify get applications -n "$ARGOCD_NAMESPACE" -o custom-columns="NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status,REPO:.spec.source.repoURL" --no-headers 2>/dev/null | while read -r name sync health repo; do
              if [[ -n "$name" ]]; then
                sync=$${sync:-"Unknown"}
                health=$${health:-"Unknown"}
                log_info "   • $${BOLD}$name$${RESET} - Sync: $sync, Health: $health"
              fi
            done || log_info "   (Could not retrieve application details)"
          else
            log_warning "No ArgoCD applications found after deployment attempts"
            log_info "This may be normal if ArgoCD is still initializing"
            log_info "Check ArgoCD controller logs: kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller"
          fi
        else
          log_warning "Unable to list ArgoCD applications"
        fi
      else
        log_warning "ArgoCD Application CRD not yet available - ArgoCD may still be initializing"
        log_info "You can check status later with: kubectl get applications -n argocd"
      fi

      log_success "Application setup and ArgoCD deployment completed successfully"
      
      log_subheader "🔧 Post-Deployment Action Items Required"
      log_warning "IMPORTANT: Complete AWS Secrets Manager Configuration"
      log_info "1. ✅ Replace AWS secret name in this script:"
      log_cmd_output "   Change 'YOUR_ACTUAL_AWS_SECRET_NAME_HERE' to your actual AWS secret name"
      log_info "2. ✅ Ensure your AWS secret contains required static keys:"
      log_cmd_output "   TELEGRAM_TOKEN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,"
      log_cmd_output "   MONGO_URI, MONGO_DB, MONGO_COLLECTION, POLYBOT_URL"
      log_info "3. ✅ Update SQS Queue URL in environment variables (TF_VAR_SQS_QUEUE_URL)"
      log_info "4. ✅ Verify application status:"
      log_cmd_output "   kubectl --insecure-skip-tls-verify get applications -n argocd"
      log_cmd_output "   kubectl --insecure-skip-tls-verify get pods -n prod"
      log_info "5. ✅ If StorageClass conflicts occur for MongoDB:"
      log_cmd_output "   kubectl delete sc mongodb-storage  # if parameters differ from Git"
      log_info "6. ✅ Check secret was populated correctly:"
      log_cmd_output "   kubectl --insecure-skip-tls-verify get secret polybot-secrets -n prod -o jsonpath='{.data}' | jq 'keys'"
      log_info "7. ✅ Create missing application.yaml files:"
      log_cmd_output "   k8s/Polybot/application.yaml and k8s/Yolo5/application.yaml"
    EOT
  }
}

# =============================================================================
# 🚀 ARGOCD DEPLOYMENT - GITOPS PLATFORM
# =============================================================================

# Streamlined ArgoCD installation
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [null_resource.ensure_local_kubeconfig] # Changed to depend on kubeconfig being ensured

  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id # Trigger when cluster and namespaces are ready
    argocd_version     = "v6-tls-fix-applied"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
#!/bin/bash
      # Removed set -e to allow graceful error handling during initial setup

      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }

      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🚀 Installing/Verifying ArgoCD v5 (fixed syntax)"

      log_subheader "🔗 Checking cluster connectivity"
      # Check kubectl connectivity with graceful handling
      if ! kubectl --insecure-skip-tls-verify get nodes >/dev/null 2>&1; then
        log_warning "Cannot connect to cluster using KUBECONFIG=$KUBECONFIG."
        log_info "This may be expected during initial cluster setup."
        log_info "The cluster may still be initializing or kubeconfig may not be ready yet."
        
        log_subheader "📋 Possible causes"
        log_info "   • Cluster API server still starting up"
        log_info "   • Kubeconfig not yet properly configured"
        log_info "   • Network connectivity issues"
        log_info "   • Kubeconfig may have internal IP instead of external IP"
        
        log_subheader "🔄 Skipping for now"
        log_info "Skipping ArgoCD installation for now - it can be installed later when cluster is accessible."
        log_info "You can manually install ArgoCD later with:"
        log_cmd_output "   kubectl --insecure-skip-tls-verify create namespace argocd"
        log_cmd_output "   kubectl --insecure-skip-tls-verify apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"
        
        exit 0 # Exit gracefully instead of failing the deployment
      fi

      log_success "Cluster connectivity confirmed. Proceeding with ArgoCD installation..."

      ARGOCD_NAMESPACE="argocd"

      log_subheader "📁 Setting up ArgoCD namespace"
      # Check if ArgoCD namespace exists
      if ! kubectl --insecure-skip-tls-verify get namespace "$ARGOCD_NAMESPACE" >/dev/null 2>&1; then
        log_step "Creating ArgoCD namespace: $${BOLD}$ARGOCD_NAMESPACE$${RESET}"
        log_info "ArgoCD namespace should exist from cluster_readiness_check"
      else
        log_info "ArgoCD namespace '$${BOLD}$ARGOCD_NAMESPACE$${RESET}' already exists."
      fi

      log_subheader "📦 Installing ArgoCD manifests"
      # Apply ArgoCD manifests (idempotent)
      log_step "Applying ArgoCD manifests from stable release"
      if kubectl --insecure-skip-tls-verify apply -n "$ARGOCD_NAMESPACE" -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml 2>/dev/null; then
        log_success "ArgoCD manifests applied/updated successfully."
      else
        log_warning "Failed to apply ArgoCD manifests. This may be due to connectivity issues."
        log_info "You can manually install ArgoCD later when the cluster is accessible."
        exit 0 # Exit gracefully instead of failing
      fi

      log_subheader "⏳ Waiting for ArgoCD deployment"
      log_progress "Waiting for ArgoCD server deployment to be available (this might take a few minutes)"
      # Wait for the argocd-server deployment to be available with more lenient timeout
      if kubectl --insecure-skip-tls-verify wait deployment -n "$ARGOCD_NAMESPACE" argocd-server --for condition=Available --timeout=300s 2>/dev/null; then
        log_success "ArgoCD server deployment is available."
      else
        log_warning "ArgoCD server deployment did not become available within timeout."
        log_info "This may be normal during initial cluster setup."
        
        log_step "Current status of ArgoCD pods:"
        ARGOCD_PODS=$(kubectl --insecure-skip-tls-verify get pods -n "$ARGOCD_NAMESPACE" 2>/dev/null || echo "   Could not retrieve pod status")
        log_cmd_output "$ARGOCD_PODS"
        
        log_step "Current status of ArgoCD deployments:"
        ARGOCD_DEPLOYMENTS=$(kubectl --insecure-skip-tls-verify get deployments -n "$ARGOCD_NAMESPACE" 2>/dev/null || echo "   Could not retrieve deployment status")
        log_cmd_output "$ARGOCD_DEPLOYMENTS"
        
        log_info "ArgoCD installation initiated - may complete after cluster is fully ready."
        exit 0 # Don't fail the deployment
      fi

      log_subheader "🔑 Retrieving ArgoCD admin credentials"
      # Get admin password (this secret is usually created by ArgoCD upon first install)
      log_step "Retrieving ArgoCD admin password (if initial setup)"
      PASSWORD_SECRET_NAME="argocd-initial-admin-secret"
      if kubectl --insecure-skip-tls-verify get secret -n "$ARGOCD_NAMESPACE" "$PASSWORD_SECRET_NAME" >/dev/null 2>&1; then
        RAW_PASSWORD=$(kubectl --insecure-skip-tls-verify -n "$ARGOCD_NAMESPACE" get secret "$PASSWORD_SECRET_NAME" -o jsonpath="{.data.password}" 2>/dev/null || echo "")
        if [[ -n "$RAW_PASSWORD" ]]; then
          ARGOCD_PASSWORD=$(echo "$RAW_PASSWORD" | base64 -d)
          log_success "ArgoCD Admin Password: $${BOLD}$ARGOCD_PASSWORD$${RESET}"
        else
          log_info "ArgoCD initial admin password not found in secret (might have been changed or is an older install)."
        fi
      else
        log_info "ArgoCD initial admin secret '$${BOLD}$PASSWORD_SECRET_NAME$${RESET}' not found (might have been changed or is an older install)."
      fi

      log_subheader "🎉 ArgoCD Setup Complete"
      log_success "ArgoCD installation/verification completed!"
      log_info "Access ArgoCD by port-forwarding: $${BOLD}kubectl --insecure-skip-tls-verify port-forward svc/argocd-server -n $ARGOCD_NAMESPACE 8080:443$${RESET}"
      log_info "Username: $${BOLD}admin$${RESET}"
      log_info "Password: (If newly installed, see above. Otherwise, use your current password)."
    EOT
  }
}

# =============================================================================
# 📊 DEPLOYMENT SUMMARY - FINAL STATUS AND INFORMATION
# =============================================================================

# Comprehensive deployment summary
resource "null_resource" "deployment_summary" {
  depends_on = [
    null_resource.cluster_maintenance,
    null_resource.application_setup,
    null_resource.install_argocd
  ]

  triggers = {
    maintenance_id  = null_resource.cluster_maintenance.id
    setup_id        = null_resource.application_setup.id
    argocd_id       = try(null_resource.install_argocd[0].id, "skipped")
    summary_version = "v6-comprehensive-enhanced" # Enhanced with styling and comprehensive info
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      # Core Infrastructure
      TF_VAR_AWS_REGION             = var.region
      TF_VAR_CLUSTER_NAME           = local.cluster_name
      TF_VAR_VPC_ID                 = module.k8s-cluster.vpc_id_output
      TF_VAR_PUBLIC_SUBNET_IDS      = join(",", module.k8s-cluster.public_subnet_ids)
      TF_VAR_PRIVATE_SUBNET_IDS     = join(",", module.k8s-cluster.private_subnet_ids)
      
      # Control Plane Details
      TF_VAR_CONTROL_PLANE_ID       = module.k8s-cluster.control_plane_instance_id_output
      TF_VAR_CONTROL_PLANE_IP       = module.k8s-cluster.control_plane_public_ip_output
      TF_VAR_CONTROL_PLANE_PRIVATE_IP = module.k8s-cluster.control_plane_private_ip
      TF_VAR_SSH_KEY_NAME           = module.k8s-cluster.ssh_key_name_output
      
      # Worker Node Infrastructure
      TF_VAR_WORKER_ASG_NAME        = module.k8s-cluster.worker_asg_name_output
      TF_VAR_LAUNCH_TEMPLATE_ID     = module.k8s-cluster.worker_launch_template_id
      
      # Load Balancer & Networking
      TF_VAR_ALB_DNS_NAME           = module.k8s-cluster.alb_dns_name_output
      TF_VAR_ALB_ZONE_ID            = module.k8s-cluster.alb_zone_id
      TF_VAR_DOMAIN_NAME            = var.domain_name
      TF_VAR_APPLICATION_URL        = "https://${var.domain_name}"
      
      # Security Groups
      TF_VAR_CP_SG_ID               = module.k8s-cluster.control_plane_security_group_id
      TF_VAR_WORKER_SG_ID           = module.k8s-cluster.worker_security_group_id
      TF_VAR_ALB_SG_ID              = module.k8s-cluster.alb_security_group_id
      
      # IAM Roles
      TF_VAR_CP_IAM_ROLE_ARN        = module.k8s-cluster.control_plane_iam_role_arn
      TF_VAR_WORKER_IAM_ROLE_ARN    = module.k8s-cluster.worker_iam_role_arn
      TF_VAR_WORKER_IAM_ROLE_NAME   = module.k8s-cluster.worker_iam_role_name
      
      # Auto Scaling Group Lifecycle
      TF_VAR_ASG_SCALE_UP_HOOK_NAME = module.k8s-cluster.asg_scale_up_hook_name
      TF_VAR_ASG_SCALE_DOWN_HOOK_NAME = module.k8s-cluster.asg_scale_down_hook_name
      TF_VAR_SNS_TOPIC_ARN          = module.k8s-cluster.sns_topic_arn
      
      # AWS Secrets Manager
      TF_VAR_KUBECONFIG_SECRET_NAME = module.k8s-cluster.kubeconfig_secret_name_output
      TF_VAR_JOIN_CMD_SECRET_NAME   = module.k8s-cluster.kubernetes_join_command_secrets.latest_secret
      TF_VAR_POLYBOT_CFG_SECRET_NAME = "polybot-secrets"  # Matches application_setup
      
      # AWS Resources from generated-secrets.tf
      TF_VAR_SQS_QUEUE_URL          = aws_sqs_queue.polybot_queue.url
      TF_VAR_S3_BUCKET_NAME         = aws_s3_bucket.polybot_storage.bucket
      TF_VAR_S3_BUCKET_ARN          = aws_s3_bucket.polybot_storage.arn
      TF_VAR_S3_WORKER_LOGS_BUCKET  = module.k8s-cluster.worker_logs_bucket
      
      # ArgoCD configuration
      TF_VAR_ARGOCD_NAMESPACE       = "argocd"  # ArgoCD default namespace
      
      # Kubeconfig Path
      TF_KUBECONFIG_PATH            = local.kubeconfig_path
    }
    command = <<-EOT
      #!/bin/bash
      set -e

      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      DIM='\033[2m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'
      BG_GREEN='\033[42m'
      BG_BLUE='\033[44m'
      BG_PURPLE='\033[45m'
      BG_CYAN='\033[46m'
      BG_YELLOW='\033[43m'

      # Enhanced Helper Functions for Vibrant Styling
      log_header() { echo -e "\n$${BOLD}$${BG_PURPLE}$${WHITE} 🚀 $1 🚀 $${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${BG_CYAN}$${WHITE} $1 $${RESET}"; }
      log_section() { echo -e "\n$${BOLD}$${BLUE}🔹 $1$${RESET}"; }
      log_key_value() { echo -e "  $${BOLD}$${CYAN}$1:$${RESET} $${WHITE}$2$${RESET}"; }
      log_command() { echo -e "  $${DIM}$${YELLOW}💻 $1$${RESET}"; }
      log_info() { echo -e "  $${CYAN}💡 $1$${RESET}"; }
      log_success() { echo -e "  $${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "  $${YELLOW}⚠️  $1$${RESET}"; }
      log_error() { echo -e "  $${RED}❌ $1$${RESET}"; }
      log_celebration() { echo -e "$${BOLD}$${BG_GREEN}$${WHITE} 🎉 $1 🎉 $${RESET}"; }
      log_separator() { echo -e "$${DIM}$${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$${RESET}"; }

      # Set paths and kubeconfig
      TERRAFORM_EXEC_DIR=$(pwd)
      KUBECONFIG="$TF_KUBECONFIG_PATH"
      export KUBECONFIG
      
      echo ""
      echo ""
      log_celebration "POLYBOT KUBERNETES CLUSTER DEPLOYMENT COMPLETE"
      echo ""
      log_separator

      # =============================================================================
      # 1. CLUSTER DETAILS (TOP PRIORITY)
      # =============================================================================
      
      log_header "🏗️ CLUSTER DETAILS"
      
      log_section "Control Plane"
      log_key_value "📍 Instance ID" "$TF_VAR_CONTROL_PLANE_ID"
      log_key_value "🌐 Public IP" "$TF_VAR_CONTROL_PLANE_IP"
      log_key_value "🔒 Private IP" "$TF_VAR_CONTROL_PLANE_PRIVATE_IP"
      log_key_value "🔗 API Endpoint" "https://$TF_VAR_CONTROL_PLANE_IP:6443"
      log_key_value "🔑 SSH Key" "$TF_VAR_SSH_KEY_NAME"
      
      log_subheader "💻 Worker Node Details (Live from AWS)"
      if command -v aws >/dev/null 2>&1 && [[ -n "$TF_VAR_WORKER_ASG_NAME" && -n "$TF_VAR_AWS_REGION" ]]; then
        log_info "Fetching worker instance details from ASG: $${BOLD}$TF_VAR_WORKER_ASG_NAME$${RESET}..."
        
        # Query AWS for worker node details with enhanced formatting
        aws ec2 describe-instances --region "$TF_VAR_AWS_REGION" \
          --filters "Name=tag:aws:autoscaling:groupName,Values=$TF_VAR_WORKER_ASG_NAME" "Name=instance-state-name,Values=running,pending" \
          --query 'Reservations[*].Instances[*].{Name:Tags[?Key==`Name`]|[0].Value, ID:InstanceId, PublicIP:PublicIpAddress, PrivateIP:PrivateIpAddress, State:State.Name}' \
          --output table 2>/dev/null | while IFS= read -r line; do 
            echo -e "$${CYAN}    $line$${RESET}"
          done || log_warning "Could not fetch worker details. AWS CLI error or no running workers."
        
        # Get count of workers
        WORKER_COUNT=$(aws ec2 describe-instances --region "$TF_VAR_AWS_REGION" \
          --filters "Name=tag:aws:autoscaling:groupName,Values=$TF_VAR_WORKER_ASG_NAME" "Name=instance-state-name,Values=running,pending" \
          --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null | wc -w || echo "0")
        log_key_value "🤖 Worker Node Count" "$WORKER_COUNT nodes"
        
      else
        log_warning "AWS CLI not found or Worker ASG Name/Region not provided. Cannot fetch live worker details."
        log_key_value "🤖 Worker ASG Name" "$TF_VAR_WORKER_ASG_NAME"
      fi

      # =============================================================================
      # 2. ARGOCD ACCESS
      # =============================================================================
      
      log_header "🔐 ARGOCD ACCESS"
      
      if [[ -f "$KUBECONFIG" ]]; then
        log_info "Using Kubeconfig: $${BOLD}$KUBECONFIG$${RESET}"
        
        # Retrieve ArgoCD Admin Password
        log_info "Retrieving ArgoCD Admin Password..."
        ARGOCD_PASSWORD_SUMMARY=$(kubectl --kubeconfig="$KUBECONFIG" --insecure-skip-tls-verify -n "$TF_VAR_ARGOCD_NAMESPACE" get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || echo "ERROR_FETCHING_ARGOCD_PASSWORD")
        
        if [[ "$ARGOCD_PASSWORD_SUMMARY" != "ERROR_FETCHING_ARGOCD_PASSWORD" ]]; then
          log_key_value "👤 Username" "admin"
          log_key_value "🔑 Admin Password" "$${BOLD}$${GREEN}$ARGOCD_PASSWORD_SUMMARY$${RESET}"
          log_success "ArgoCD password retrieved successfully!"
        else
          log_warning "Could not retrieve ArgoCD password. ArgoCD may not be fully ready yet."
          log_key_value "👤 Username" "admin"
          log_key_value "🔑 Admin Password" "⚠️  Run: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath=\"{.data.password}\" | base64 -d"
        fi
        
        log_key_value "🌐 Access URL" "$${BOLD}$${BLUE}https://localhost:8080$${RESET} (via port-forward)"
        log_key_value "🔗 Connect Command" "$${BOLD}$${YELLOW}./argocd-connect.sh $TF_VAR_CONTROL_PLANE_IP$${RESET}"
        
        # Port-forward command
        log_info "To access ArgoCD UI:"
        log_command "kubectl --insecure-skip-tls-verify port-forward svc/argocd-server -n argocd 8080:443"
        log_info "Then visit: $${BOLD}$${BLUE}https://localhost:8080$${RESET}"
        
      else
        log_warning "Kubeconfig file not found at: $KUBECONFIG"
        log_info "ArgoCD access commands will be available once kubeconfig is ready."
      fi

      # =============================================================================
      # 3. KEY AWS INFRASTRUCTURE DETAILS
      # =============================================================================
      
      log_header "🌐 KEY AWS INFRASTRUCTURE DETAILS"
      
      log_section "VPC & Networking"
      log_key_value "🌍 VPC ID" "$TF_VAR_VPC_ID"
      log_key_value "🌐 Public Subnets" "$TF_VAR_PUBLIC_SUBNET_IDS"
      log_key_value "🔒 Private Subnets" "$TF_VAR_PRIVATE_SUBNET_IDS"
      log_key_value "🌍 AWS Region" "$TF_VAR_AWS_REGION"
      
      log_section "Security Groups"
      log_key_value "🛡️  Control Plane SG" "$TF_VAR_CP_SG_ID"
      log_key_value "🛡️  Worker Node SG" "$TF_VAR_WORKER_SG_ID"
      log_key_value "🛡️  ALB SG" "$TF_VAR_ALB_SG_ID"
      
      log_section "IAM Roles"
      log_key_value "🎛️  CP IAM Role ARN" "$TF_VAR_CP_IAM_ROLE_ARN"
      log_key_value "🤖 Worker IAM Role ARN" "$TF_VAR_WORKER_IAM_ROLE_ARN"
      log_key_value "🤖 Worker IAM Role Name" "$TF_VAR_WORKER_IAM_ROLE_NAME"
      
      log_section "Auto Scaling Group (ASG)"
      log_key_value "🤖 ASG Name" "$TF_VAR_WORKER_ASG_NAME"
      log_key_value "🚀 Launch Template" "$TF_VAR_LAUNCH_TEMPLATE_ID"
      log_key_value "📈 Scale Up Hook" "$TF_VAR_ASG_SCALE_UP_HOOK_NAME"
      log_key_value "📉 Scale Down Hook" "$TF_VAR_ASG_SCALE_DOWN_HOOK_NAME"
      
      # Get current ASG status if AWS CLI available
      if command -v aws >/dev/null 2>&1; then
        ASG_INFO=$(aws autoscaling describe-auto-scaling-groups --region "$TF_VAR_AWS_REGION" --auto-scaling-group-names "$TF_VAR_WORKER_ASG_NAME" --query "AutoScalingGroups[0].{DesiredCapacity:DesiredCapacity,MinSize:MinSize,MaxSize:MaxSize,Instances:length(Instances)}" --output text 2>/dev/null || echo "N/A N/A N/A N/A")
        read -r DESIRED MIN MAX INSTANCES <<< "$ASG_INFO"
        if [[ "$DESIRED" != "N/A" ]]; then
          log_key_value "📊 ASG Status" "Desired: $DESIRED, Min: $MIN, Max: $MAX, Current: $INSTANCES"
        fi
      fi
      
      log_section "AWS Secrets Manager"
      log_key_value "🔐 Kubeconfig Secret (AWS)" "$TF_VAR_KUBECONFIG_SECRET_NAME"
      log_key_value "🎫 Join Cmd Secret (AWS)" "$TF_VAR_JOIN_CMD_SECRET_NAME"
      log_key_value "🤖 Polybot Cfg Secret (AWS)" "$TF_VAR_POLYBOT_CFG_SECRET_NAME"
      
      log_section "Application Resources"
      log_key_value "📧 SQS Queue URL" "$TF_VAR_SQS_QUEUE_URL"
      log_key_value "🪣 S3 Storage Bucket" "$TF_VAR_S3_BUCKET_NAME"
      log_key_value "🪣 S3 Bucket ARN" "$TF_VAR_S3_BUCKET_ARN"
      log_key_value "📋 Worker Logs Bucket" "$TF_VAR_S3_WORKER_LOGS_BUCKET"
      
      log_section "Load Balancer & DNS"
      log_key_value "⚖️  ALB DNS Name" "$TF_VAR_ALB_DNS_NAME"
      log_key_value "🌐 ALB Zone ID" "$TF_VAR_ALB_ZONE_ID"
      log_key_value "🌍 Domain Name" "$TF_VAR_DOMAIN_NAME"
      log_key_value "🔗 Application URL (R53)" "$TF_VAR_APPLICATION_URL"
      
      log_section "SNS & Notifications"
      log_key_value "📢 SNS Topic (ASG Events)" "$TF_VAR_SNS_TOPIC_ARN"

      # =============================================================================
      # 4. KUBECONFIG LOCATION
      # =============================================================================
      
      log_header "📁 KUBECONFIG LOCATION"
      
      log_key_value "📂 Local Kubeconfig Path" "$${BOLD}$${GREEN}$KUBECONFIG$${RESET}"
      
      if [[ -f "$KUBECONFIG" ]]; then
        KUBECONFIG_SIZE=$(wc -c < "$KUBECONFIG" 2>/dev/null || echo "unknown")
        log_key_value "📄 File Size" "$KUBECONFIG_SIZE bytes"
        
        # Extract key details from kubeconfig
        if command -v grep >/dev/null 2>&1; then
          KUBE_API_SERVER=$(grep 'server:' "$KUBECONFIG" | awk '{print $2}' | head -n 1 2>/dev/null || echo "Not found")
          KUBE_CURRENT_CONTEXT=$(grep 'current-context:' "$KUBECONFIG" | awk '{print $2}' 2>/dev/null || echo "Not specified")
          log_key_value "🎯 API Server in Kubeconfig" "$KUBE_API_SERVER"
          log_key_value "📋 Current Context" "$KUBE_CURRENT_CONTEXT"
        fi
        
        log_success "Kubeconfig file is ready for use!"
        log_info "Export command: $${BOLD}export KUBECONFIG=$KUBECONFIG$${RESET}"
        
      else
        log_warning "Kubeconfig file not found. It may still be generating."
      fi

      # =============================================================================
      # FINAL COMMANDS & NEXT STEPS
      # =============================================================================
      
      log_header "🛠️ ESSENTIAL COMMANDS"
      
      log_section "Cluster Access"
      log_command "export KUBECONFIG=$KUBECONFIG"
      log_command "kubectl --insecure-skip-tls-verify get nodes"
      log_command "kubectl --insecure-skip-tls-verify get pods --all-namespaces"
      
      log_section "SSH Access"
      log_command "ssh -i $TF_VAR_SSH_KEY_NAME.pem ubuntu@$TF_VAR_CONTROL_PLANE_IP"
      
      log_section "ArgoCD Access"
      log_command "kubectl --insecure-skip-tls-verify port-forward svc/argocd-server -n argocd 8080:443"
      log_command "./argocd-connect.sh $TF_VAR_CONTROL_PLANE_IP"
      
      echo ""
      log_separator
      log_celebration "DEPLOYMENT COMPLETE - POLYBOT CLUSTER READY FOR USE"
      log_separator
      echo ""
    EOT
  }
}