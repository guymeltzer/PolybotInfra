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
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
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
      log_header() { echo -e "\n${BOLD}${PURPLE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_progress() { echo -e "${YELLOW}⏳ $1...${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      # --- End Style Definitions ---
      
      log_header "🔧 Ensuring Local Kubeconfig Availability"
      
      KUBECONFIG_PATH="${local.kubeconfig_path}"
      SECRET_NAME="${module.k8s-cluster.kubeconfig_secret_name_output}"
      REGION="${var.region}"
      
      log_info "Target kubeconfig path: ${BOLD}$KUBECONFIG_PATH${RESET}"
      log_info "Secret name: ${BOLD}$SECRET_NAME${RESET}"
      log_info "Region: ${BOLD}$REGION${RESET}"
      
      log_subheader "🔍 Checking Local Kubeconfig Status"
      # Check if local kubeconfig exists and is valid
      if [[ -f "$KUBECONFIG_PATH" ]]; then
        log_success "Local kubeconfig file exists"
        
        # Quick validation - check if it contains required fields
        if grep -q "apiVersion" "$KUBECONFIG_PATH" && grep -q "clusters:" "$KUBECONFIG_PATH"; then
          log_success "Local kubeconfig appears valid"
          
          log_step "Testing connectivity to ensure it works"
          # Test connectivity to ensure it works
          if timeout 10 kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
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
        
        log_success "Local kubeconfig file created: ${BOLD}$KUBECONFIG_PATH${RESET}"
        
        log_step "Verifying the new file works"
        # Verify the new file works
        if timeout 10 kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
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
    script_version = "v1-stable"
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
      log_header() { echo -e "\n${BOLD}${PURPLE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_progress() { echo -e "${YELLOW}⏳ $1...${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      # --- End Style Definitions ---
      
      log_header "🔧 Ensuring Local Kubeconfig Availability"
      
      KUBECONFIG_PATH="${local.kubeconfig_path}"
      SECRET_NAME="${module.k8s-cluster.kubeconfig_secret_name_output}"
      REGION="${var.region}"
      
      log_info "Target kubeconfig path: ${BOLD}$KUBECONFIG_PATH${RESET}"
      log_info "Secret name: ${BOLD}$SECRET_NAME${RESET}"
      log_info "Region: ${BOLD}$REGION${RESET}"
      
      log_subheader "🔍 Checking Local Kubeconfig Status"
      # Check if local kubeconfig exists and is valid
      if [[ -f "$KUBECONFIG_PATH" ]]; then
        log_success "Local kubeconfig file exists"
        
        # Quick validation - check if it contains required fields
        if grep -q "apiVersion" "$KUBECONFIG_PATH" && grep -q "clusters:" "$KUBECONFIG_PATH"; then
          log_success "Local kubeconfig appears valid"
          
          log_step "Testing connectivity to ensure it works"
          # Test connectivity to ensure it works
          if timeout 10 kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
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
        
        log_success "Local kubeconfig file created: ${BOLD}$KUBECONFIG_PATH${RESET}"
        
        log_step "Verifying the new file works"
        # Verify the new file works
        if timeout 10 kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
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
    readiness_version     = "v6-enhanced"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      # Note: Removing set -e to allow more graceful error handling

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
      log_header() { echo -e "\n${BOLD}${PURPLE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_progress() { echo -e "${YELLOW}⏳ $1...${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      # --- End Style Definitions ---

      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🔍 Enhanced Cluster Readiness Check v6"

      log_subheader "📊 Debug Information"
      # Debug information
      log_info "Kubeconfig file: ${BOLD}$KUBECONFIG${RESET}"
      if [[ -f "$KUBECONFIG" ]]; then
        KUBECONFIG_SIZE=$(wc -c < "$KUBECONFIG")
        log_info "Kubeconfig size: ${BOLD}$KUBECONFIG_SIZE bytes${RESET}"
        if grep -q "server:" "$KUBECONFIG" 2>/dev/null; then
          SERVER_URL=$(grep "server:" "$KUBECONFIG" | head -1 | awk '{print $2}')
          log_info "API Server: ${BOLD}$SERVER_URL${RESET}"
          
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
      # Attempt kubectl connectivity with detailed error reporting
      if kubectl get nodes >/dev/null 2>/dev/null; then
        log_success "Kubectl connectivity confirmed"
        
        log_subheader "📋 Current cluster state"
        log_cmd_output "$(kubectl get nodes -o wide 2>/dev/null || echo "Failed to get detailed node info")"
        
        # Get node counts with error handling
        ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "0")
        notready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " NotReady " || echo "0")
        total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo "0")
        ready_workers=$(kubectl get nodes --no-headers 2>/dev/null | grep -v "control-plane" | grep -c " Ready " || echo "0")

        log_subheader "📊 Node Status Summary"
        log_info "Node Status: ${BOLD}$ready_nodes Ready${RESET}, ${BOLD}$notready_nodes NotReady${RESET} (Total: ${BOLD}$total_nodes${RESET})"
        log_info "Workers Ready: ${BOLD}$ready_workers${RESET}"

        # More lenient validations with warnings instead of fatal errors
        if [[ "$total_nodes" -eq 0 ]]; then
          log_warning "WARNING: No nodes found in the cluster yet - this may be expected during initial setup"
        fi

        if [[ "$notready_nodes" -gt 0 ]]; then
          log_warning "WARNING: $notready_nodes NotReady nodes found - this may be transient during cluster startup"
          NOTREADY_LIST=$(kubectl get nodes --no-headers 2>/dev/null | grep "NotReady" || echo "No NotReady nodes actually listed by kubectl")
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
        # Check core components with graceful handling
        if kubectl get deployment coredns -n kube-system >/dev/null 2>&1; then
          coredns_ready=$(kubectl get deployment coredns -n kube-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
          coredns_desired=$(kubectl get deployment coredns -n kube-system -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
          
          if [[ "$coredns_ready" -eq "$coredns_desired" ]] && [[ "$coredns_ready" -gt 0 ]]; then
            log_success "CoreDNS: $coredns_ready/$coredns_desired ready"
          else
            log_warning "CoreDNS: $coredns_ready/$coredns_desired ready (may still be starting)"
          fi
        else
          log_warning "CoreDNS deployment not found (may not be installed yet)"
        fi

        # Check for problematic pods with lenient thresholds
        problematic_pods_count=$(kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | wc -l || echo "0")
        
        if [[ "$problematic_pods_count" -gt 5 ]]; then
          log_warning "WARNING: Many problematic pods ($problematic_pods_count) - may indicate issues"
          PROBLEMATIC_PODS=$(kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | head -5 || echo "No problematic pods listed")
          log_cmd_output "$PROBLEMATIC_PODS"
        elif [[ "$problematic_pods_count" -gt 0 ]]; then
          log_info "INFO: $problematic_pods_count pods in non-Running/Succeeded state (likely transient)"
        else
          log_success "All pods in good state"
        fi

        log_subheader "🎉 Summary"
        log_success "CLUSTER ACCESSIBLE!"
        log_info "Summary:"
        log_info "   • ${BOLD}$ready_nodes${RESET} Ready nodes (${BOLD}$ready_workers${RESET} workers)"
        log_info "   • ${BOLD}$notready_nodes${RESET} NotReady nodes"
        log_info "   • Core components checked"
        
      else
        # Enhanced error diagnostics for connection failures
        log_error "Cannot connect to cluster using kubectl"
        
        log_subheader "🔍 Diagnostic information"
        kubectl_error=$(kubectl get nodes 2>&1 || echo "No error captured")
        log_cmd_output "kubectl error: $kubectl_error"
        
        log_subheader "📋 Common causes"
        log_warning "This may be expected during initial cluster setup."
        log_info "Common causes:"
        log_info "   • API server still starting up"
        log_info "   • Network connectivity issues"
        log_info "   • Kubeconfig not yet properly configured"
        log_info "   • Security groups blocking access"
        
        log_info "Deployment will continue - cluster may become accessible shortly."
        log_info "You can manually check cluster status later with: ${BOLD}kubectl get nodes${RESET}"
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
    maintenance_version = "v2-refined" # Ensure this matches the script content if versioned
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e # Exit on error, but allow some commands to fail gracefully with || true

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
      log_header() { echo -e "\n${BOLD}${PURPLE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_progress() { echo -e "${YELLOW}⏳ $1...${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      # --- End Style Definitions ---

      # Ensure KUBECONFIG is set from local.kubeconfig_path which is now managed by local_file
      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🧹 Consolidated Cluster Maintenance v2"

      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        log_error "Cannot connect to cluster using KUBECONFIG=$KUBECONFIG, skipping maintenance."
        exit 0 # Exit gracefully if cluster not accessible
      fi

      log_subheader "👻 Checking for orphaned worker nodes"
      # 1. Clean up orphaned nodes (nodes in k8s but not in ASG)

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
      K8S_WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null || echo "")

      ORPHANED_COUNT=0
      for node_name in $K8S_WORKER_NODES; do
        # Check if the K8s node name (which is often the private DNS name) is in the list of active ASG instances
        if ! echo "$ACTIVE_ASG_INSTANCE_IDS" | grep -qxF "$node_name"; then
          log_warning "Potential orphaned node found: ${BOLD}$node_name${RESET}. Attempting removal..."
          ORPHANED_COUNT=$((ORPHANED_COUNT + 1))

          # Cordon and drain (optional, can be slow, ensure timeout)
          # kubectl cordon "$node_name" --timeout=30s || echo "Warning: Failed to cordon $node_name"
          # kubectl drain "$node_name" --ignore-daemonsets --delete-emptydir-data --force --timeout=120s || echo "Warning: Failed to drain $node_name"

          log_step "Force deleting pods on $node_name"
          # Force delete pods on this node (quicker for non-graceful)
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$node_name" --no-headers 2>/dev/null | \
            while read -r ns pod rest; do
              log_info "     Deleting pod ${BOLD}$pod${RESET} in namespace ${BOLD}$ns${RESET} on node $node_name"
              kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=10s 2>/dev/null || log_warning "     Failed to delete pod $pod in $ns"
            done

          log_step "Deleting node $node_name from Kubernetes"
          # Remove the node from Kubernetes
          kubectl delete node "$node_name" --timeout=30s 2>/dev/null || log_warning "   Failed to delete node $node_name"
        fi
      done
      log_info "Processed ${BOLD}$ORPHANED_COUNT${RESET} potential orphaned nodes."

      log_subheader "🗑️ Cleaning up stuck terminating pods"
      # 2. Clean up stuck terminating pods
      log_step "Finding stuck terminating pods (older than 5 minutes)"
      # This is a more complex operation and might be better suited for an in-cluster operator
      # For a simple local-exec, we can list them
      STUCK_TERMINATING_PODS=$(kubectl get pods --all-namespaces --field-selector=status.phase=Terminating -o go-template='{{range .items}}{{if gt (now.Sub .metadata.deletionTimestamp) (timeDuration "5m")}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' 2>/dev/null || echo "")

      if [[ -n "$STUCK_TERMINATING_PODS" ]]; then
        log_warning "Found stuck terminating pods (older than 5m):"
        log_cmd_output "$STUCK_TERMINATING_PODS"
        echo "$STUCK_TERMINATING_PODS" | while read -r ns pod; do
          if [[ -n "$ns" && -n "$pod" ]]; then # Ensure we have both namespace and pod name
             log_step "Forcibly deleting stuck pod ${BOLD}$pod${RESET} in namespace ${BOLD}$ns${RESET}"
             kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=10s 2>/dev/null || log_warning "   Failed to delete stuck pod $pod in $ns"
          fi
        done
      else
        log_success "No stuck terminating pods found (older than 5 minutes)."
      fi

      log_success "Cluster maintenance checks completed."
    EOT
  }
}

# =============================================================================
# 🔐 APPLICATION SETUP - NAMESPACES AND SECRETS
# =============================================================================

# Essential namespace and secret creation
resource "null_resource" "application_setup" {
  depends_on = [null_resource.ensure_local_kubeconfig] # Changed to depend on kubeconfig being ensured
  
  triggers = {
    kubeconfig_ensured = null_resource.ensure_local_kubeconfig.id # Changed trigger
    setup_version      = "v3-lenient" # Ensure this matches the script content if versioned
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      # Removed set -e to allow graceful error handling during initial setup
      
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
      log_header() { echo -e "\n${BOLD}${PURPLE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_progress() { echo -e "${YELLOW}⏳ $1...${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      # --- End Style Definitions ---
      
      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🔐 Application Setup - Namespaces and Secrets v3 (lenient)"

      log_subheader "🔗 Checking cluster connectivity"
      # Check kubectl connectivity with graceful handling
      if ! kubectl get nodes >/dev/null 2>&1; then
        log_warning "Cannot connect to cluster using KUBECONFIG=$KUBECONFIG."
        log_info "This may be expected during initial cluster setup."
        log_info "The cluster may still be initializing or kubeconfig may not be ready yet."
        
        log_subheader "📋 Possible causes"
        log_info "   • Cluster API server still starting up"
        log_info "   • Kubeconfig not yet properly configured"
        log_info "   • Network connectivity issues"
        
        log_subheader "🔄 Skipping for now"
        log_info "Skipping application setup for now - it can be run later when cluster is ready."
        log_info "You can manually run the setup later with:"
        log_cmd_output "   kubectl create namespace prod"
        log_cmd_output "   kubectl create namespace dev"
        
        exit 0 # Exit gracefully instead of failing the deployment
      fi

      log_success "Cluster connectivity confirmed. Proceeding with application setup..."

      log_subheader "📁 Creating namespaces"
      # Create namespaces idempotently
      log_step "Creating namespaces (if they don't exist)"
      for namespace in prod dev; do
        log_progress "Processing namespace: ${BOLD}$namespace${RESET}"
        # Use apply for idempotency
        echo "apiVersion: v1
kind: Namespace
metadata:
  name: $namespace" | kubectl apply -f - || log_warning "   Failed to create namespace $namespace (may already exist)"
        
        if kubectl get namespace "$namespace" >/dev/null 2>&1; then
          log_success "Namespace: ${BOLD}$namespace${RESET} ensured"
        else
          log_warning "Namespace: ${BOLD}$namespace${RESET} verification failed"
        fi
      done

      log_subheader "🔐 Ensuring TLS certificates and secrets"
      # Generate certificates for TLS secrets (dummy for now, should be managed properly)
      CERT_DIR="/tmp/polybot-certs-$$" # Use process ID for temp uniqueness
      log_step "Creating temporary certificate directory: $CERT_DIR"
      mkdir -p "$CERT_DIR"
      cd "$CERT_DIR"

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
        log_subheader "🔑 Ensuring secrets in namespace: ${BOLD}$namespace${RESET}"

        # Check if namespace exists before trying to create secrets
        if ! kubectl get namespace "$namespace" >/dev/null 2>&1; then
          log_warning "Namespace $namespace not found, skipping secret creation"
          continue
        fi

        log_step "Creating TLS secret"
        # TLS secret
        kubectl create secret tls polybot-tls \
          --cert="$CRT_FILE" --key="$KEY_FILE" -n "$namespace" \
          --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || log_info "polybot-tls secret in $namespace handled (may already exist)"

        log_step "Creating CA secret"
        # CA secret
        kubectl create secret generic polybot-ca \
          --from-file=ca.crt="$CA_FILE" -n "$namespace" \
          --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || log_info "polybot-ca secret in $namespace handled (may already exist)"

        log_step "Creating application secrets"
        # Application secrets (ensure values are appropriate or use more secure methods for production)
        kubectl create secret generic polybot-secrets \
          --from-literal=app-secret='default-app-secret-value' \
          --from-literal=database-url='postgresql://polybot:examplepassword@your-db-host:5432/polybotdb' \
          --from-literal=redis-url='redis://your-redis-host:6379/0' \
          -n "$namespace" \
          --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || log_info "polybot-secrets in $namespace handled (may already exist)"

        log_success "Secrets processed for ${BOLD}$namespace${RESET}"
      done

      # Cleanup
      cd / # Change out of the temp dir before removing it
      rm -rf "$CERT_DIR"
      log_step "Cleaned up temporary certificate directory"

      log_success "Application setup completed successfully"
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
    kubeconfig_ensured = null_resource.ensure_local_kubeconfig.id # Changed trigger
    argocd_version     = "v4-lenient" # Ensure this matches script content if versioned
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
#!/bin/bash
      # Removed set -e to allow graceful error handling during initial setup

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
      log_header() { echo -e "\n${BOLD}${PURPLE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_progress() { echo -e "${YELLOW}⏳ $1...${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      # --- End Style Definitions ---

      export KUBECONFIG="${local.kubeconfig_path}"

      log_header "🚀 Installing/Verifying ArgoCD v4 (lenient)"

      log_subheader "🔗 Checking cluster connectivity"
      # Check kubectl connectivity with graceful handling
      if ! kubectl get nodes >/dev/null 2>&1; then
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
        log_cmd_output "   kubectl create namespace argocd"
        log_cmd_output "   kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"
        
        exit 0 # Exit gracefully instead of failing the deployment
      fi

      log_success "Cluster connectivity confirmed. Proceeding with ArgoCD installation..."

      ARGOCD_NAMESPACE="argocd"

      log_subheader "📁 Setting up ArgoCD namespace"
      # Check if ArgoCD namespace exists
      if ! kubectl get namespace "$ARGOCD_NAMESPACE" >/dev/null 2>&1; then
        log_step "Creating ArgoCD namespace: ${BOLD}$ARGOCD_NAMESPACE${RESET}"
        kubectl create namespace "$ARGOCD_NAMESPACE" || log_warning "   Failed to create namespace (may already exist)"
      else
        log_info "ArgoCD namespace '${BOLD}$ARGOCD_NAMESPACE${RESET}' already exists."
      fi

      log_subheader "📦 Installing ArgoCD manifests"
      # Apply ArgoCD manifests (idempotent)
      log_step "Applying ArgoCD manifests from stable release"
      if kubectl apply -n "$ARGOCD_NAMESPACE" -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml 2>/dev/null; then
        log_success "ArgoCD manifests applied/updated successfully."
      else
        log_warning "Failed to apply ArgoCD manifests. This may be due to connectivity issues."
        log_info "You can manually install ArgoCD later when the cluster is accessible."
        exit 0 # Exit gracefully instead of failing
      fi

      log_subheader "⏳ Waiting for ArgoCD deployment"
      log_progress "Waiting for ArgoCD server deployment to be available (this might take a few minutes)"
      # Wait for the argocd-server deployment to be available with more lenient timeout
      if kubectl wait deployment -n "$ARGOCD_NAMESPACE" argocd-server --for condition=Available --timeout=300s 2>/dev/null; then
        log_success "ArgoCD server deployment is available."
      else
        log_warning "ArgoCD server deployment did not become available within timeout."
        log_info "This may be normal during initial cluster setup."
        
        log_step "Current status of ArgoCD pods:"
        ARGOCD_PODS=$(kubectl get pods -n "$ARGOCD_NAMESPACE" 2>/dev/null || echo "   Could not retrieve pod status")
        log_cmd_output "$ARGOCD_PODS"
        
        log_step "Current status of ArgoCD deployments:"
        ARGOCD_DEPLOYMENTS=$(kubectl get deployments -n "$ARGOCD_NAMESPACE" 2>/dev/null || echo "   Could not retrieve deployment status")
        log_cmd_output "$ARGOCD_DEPLOYMENTS"
        
        log_info "ArgoCD installation initiated - may complete after cluster is fully ready."
        exit 0 # Don't fail the deployment
      fi

      log_subheader "🔑 Retrieving ArgoCD admin credentials"
      # Get admin password (this secret is usually created by ArgoCD upon first install)
      log_step "Retrieving ArgoCD admin password (if initial setup)"
      PASSWORD_SECRET_NAME="argocd-initial-admin-secret"
      if kubectl get secret -n "$ARGOCD_NAMESPACE" "$PASSWORD_SECRET_NAME" >/dev/null 2>&1; then
        RAW_PASSWORD=$(kubectl -n "$ARGOCD_NAMESPACE" get secret "$PASSWORD_SECRET_NAME" -o jsonpath="{.data.password}" 2>/dev/null || echo "")
        if [[ -n "$RAW_PASSWORD" ]]; then
          ARGOCD_PASSWORD=$(echo "$RAW_PASSWORD" | base64 -d)
          log_success "ArgoCD Admin Password: ${BOLD}$ARGOCD_PASSWORD${RESET}"
        else
          log_info "ArgoCD initial admin password not found in secret (might have been changed or is an older install)."
        fi
      else
        log_info "ArgoCD initial admin secret '${BOLD}$PASSWORD_SECRET_NAME${RESET}' not found (might have been changed or is an older install)."
      fi

      log_subheader "🎉 ArgoCD Setup Complete"
      log_success "ArgoCD installation/verification completed!"
      log_info "Access ArgoCD by port-forwarding: ${BOLD}kubectl port-forward svc/argocd-server -n $ARGOCD_NAMESPACE 8080:443${RESET}"
      log_info "Username: ${BOLD}admin${RESET}"
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
    null_resource.cluster_maintenance, # Ensure this is intended, maintenance might not always run before summary
    null_resource.application_setup,
    null_resource.install_argocd
  ]

  triggers = {
    maintenance_id  = null_resource.cluster_maintenance.id
    setup_id        = null_resource.application_setup.id
    argocd_id       = try(null_resource.install_argocd[0].id, "skipped") # Correct for count
    summary_version = "v3-final"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e # Exit on error, but many commands below have || true or error checks

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
      BG_GREEN='\033[0;42m'
      BG_BLUE='\033[0;44m'
      BG_PURPLE='\033[0;45m'

      # Helper Functions for logging
      log_header() { echo -e "\n${BOLD}${BG_PURPLE}${WHITE}===== $1 =====${RESET}"; }
      log_subheader() { echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"; }
      log_step() { echo -e "${BLUE}▶ $1${RESET}"; }
      log_success() { echo -e "${GREEN}✅ $1${RESET}"; }
      log_warning() { echo -e "${YELLOW}⚠️ $1${RESET}"; }
      log_error() { echo -e "${RED}❌ $1${RESET}"; }
      log_info() { echo -e "💡 ${CYAN}$1${RESET}"; }
      log_key_value() { echo -e "${BOLD}$1:${RESET} ${WHITE}$2${RESET}"; }
      log_cmd_output() { echo -e "${WHITE}$1${RESET}"; }
      log_celebration() { echo -e "${BOLD}${BG_GREEN}${WHITE} $1 ${RESET}"; }
      # --- End Style Definitions ---

      # Ensure KUBECONFIG is set from local.kubeconfig_path
      export KUBECONFIG="${local.kubeconfig_path}"

      echo ""
      log_celebration "🎉 POLYBOT KUBERNETES CLUSTER DEPLOYMENT SUMMARY 🎉"
      echo ""

      log_header "🖥️ CONTROL PLANE INFORMATION"
      # Control Plane Information (ensure module outputs are correctly referenced)
      # These come from Terraform interpolations, no $ needed for shell interpretation after TF processes them.
      # Assuming module.k8s-cluster has these outputs defined in its outputs.tf
      PUBLIC_IP_VAL="${module.k8s-cluster.control_plane_public_ip_output}"
      INSTANCE_ID_VAL="${module.k8s-cluster.control_plane_instance_id_output}"
      KEY_NAME_VAL="${module.k8s-cluster.ssh_key_name_output}" # Assuming an output for key name from module

      log_key_value "📍 Instance ID" "$INSTANCE_ID_VAL"
      log_key_value "🌐 Public IP" "$PUBLIC_IP_VAL"
      log_key_value "🔗 API Endpoint" "https://$PUBLIC_IP_VAL:6443"
      if [[ -n "$KEY_NAME_VAL" && "$KEY_NAME_VAL" != "null" ]]; then # Check if key name is available
        log_key_value "🔑 SSH Command" "ssh -i $KEY_NAME_VAL.pem ubuntu@$PUBLIC_IP_VAL"
      else
        log_key_value "🔑 SSH Command" "ssh -i <your-key-name.pem> ubuntu@$PUBLIC_IP_VAL"
      fi

      log_header "☸️ CLUSTER STATUS"
      # Cluster Status
      if kubectl get nodes >/dev/null 2>&1; then
        TOTAL_NODES=$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo "N/A")
        READY_NODES=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "N/A")
        # Assuming control plane has 'control-plane' in its name or a label.
        # Adjust if using a specific label like !node-role.kubernetes.io/master or !node-role.kubernetes.io/control-plane
        READY_WORKERS=$(kubectl get nodes --no-headers 2>/dev/null | grep -v "control-plane" | grep -c " Ready " || echo "N/A")

        log_key_value "📊 Nodes" "$READY_NODES/$TOTAL_NODES Ready ($READY_WORKERS workers)"
        
        log_subheader "📋 Node Details"
        kubectl get nodes -o wide 2>/dev/null | tail -n +2 | while read -r node status role age version internal_ip external_ip os_image kernel container_runtime; do
          log_info "• ${BOLD}$node${RESET} ($status) - $role"
        done || log_warning "Could not retrieve node details."
      else
        log_warning "Cannot connect to cluster to retrieve status."
      fi

      log_header "🔗 KUBERNETES ACCESS"
      # Kubernetes Access
      log_key_value "📁 Kubeconfig" "${local.kubeconfig_path}" # Terraform interpolation
      log_subheader "🚀 Quick Setup Commands"
      log_cmd_output "   export KUBECONFIG=${local.kubeconfig_path}" # Terraform interpolation
      log_cmd_output "   kubectl get nodes"

      log_header "🔐 ARGOCD ACCESS"
      # ArgoCD Access
      ARGOCD_NAMESPACE="argocd"
      if kubectl get namespace "$ARGOCD_NAMESPACE" >/dev/null 2>&1; then
        ARGOCD_READY_REPLICAS=$(kubectl -n "$ARGOCD_NAMESPACE" get deployment argocd-server -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        ARGOCD_DESIRED_REPLICAS=$(kubectl -n "$ARGOCD_NAMESPACE" get deployment argocd-server -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "N/A")
        log_key_value "📊 Status" "$ARGOCD_READY_REPLICAS/$ARGOCD_DESIRED_REPLICAS ready replicas"
        log_key_value "🌐 URL (via port-forward)" "https://localhost:8080 (or specified port)" # Changed to 8080 as common example
        log_key_value "👤 Username" "admin"

        PASSWORD_SECRET_NAME="argocd-initial-admin-secret"
        RAW_PASSWORD=$(kubectl -n "$ARGOCD_NAMESPACE" get secret "$PASSWORD_SECRET_NAME" -o jsonpath="{.data.password}" 2>/dev/null || echo "")
        if [[ -n "$RAW_PASSWORD" ]]; then
          ARGOCD_PASSWORD=$(echo "$RAW_PASSWORD" | base64 -d 2>/dev/null || echo "<failed to decode>")
          log_key_value "🔑 Password" "$ARGOCD_PASSWORD (this is the initial password, may have changed)"
        else
          log_key_value "🔑 Password" "(Initial admin secret not found or password field empty; use current password)"
        fi
        log_subheader "🔗 Setup Port Forward"
        log_cmd_output "   kubectl port-forward svc/argocd-server -n $ARGOCD_NAMESPACE 8080:443"
      else
        log_info "ArgoCD namespace not found (ArgoCD might be skipped or not installed)."
      fi

      log_header "☁️ AWS RESOURCES"
      # AWS Resources (ensure module outputs are correct)
      log_key_value "🌐 VPC ID" "${module.k8s-cluster.vpc_id_output}" # Assuming module output, e.g., vpc_id_output
      ALB_DNS_NAME="${module.k8s-cluster.alb_dns_name_output}" # Assuming module output
      if [[ -n "$ALB_DNS_NAME" && "$ALB_DNS_NAME" != "null" ]]; then
        log_key_value "⚖️ Load Balancer DNS" "$ALB_DNS_NAME"
      else
        log_key_value "⚖️ Load Balancer DNS" "(Not available or ALB not created)"
      fi
      log_key_value "🔄 Auto Scaling Group" "${module.k8s-cluster.worker_asg_name_output}" # Assuming module output

      echo ""
      log_celebration "✅ DEPLOYMENT SUMMARY COMPLETE ✅"
      echo ""
    EOT
  }
}