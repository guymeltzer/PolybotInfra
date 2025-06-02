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
      echo "⏳ Waiting for kubeconfig (secret: ${self.triggers.secret_name}) in region ${self.triggers.region}..."

      for i in {1..90}; do # Try for 15 minutes (90 * 10s)
        KUBECONFIG_CONTENT=$(aws secretsmanager get-secret-value --secret-id "${self.triggers.secret_name}" --region "${self.triggers.region}" --query SecretString --output text 2>/dev/null || echo "")
        if echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion"; then
          echo "✅ Kubeconfig successfully retrieved from Secrets Manager!"
          exit 0
        fi
        echo "Kubeconfig not yet available or invalid (attempt $i/90). Waiting 10s..."
        sleep 10
      done

      echo "❌ ERROR: Timeout waiting for valid kubeconfig in Secrets Manager."
      exit 1
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


# =============================================================================
# 🔍 CLUSTER VALIDATION - HEALTH AND READINESS CHECKS
# =============================================================================

# Comprehensive cluster readiness validation
resource "null_resource" "cluster_readiness_check" {
  depends_on = [
    local_file.kubeconfig,
    null_resource.wait_for_kubeconfig_secret # Ensure kubeconfig is available in Secrets Manager
  ]

  triggers = {
    kubeconfig_file_id    = local_file.kubeconfig.id # Trigger when kubeconfig file changes
    readiness_version     = "v5-with-proper-wait"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e

      export KUBECONFIG="${local.kubeconfig_path}"

      echo "🔍 STRICT Cluster Readiness Validation v4"
      echo "========================================"

      # Validate kubectl connectivity
      echo "Attempting: kubectl get nodes"
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ FATAL: Cannot connect to cluster using KUBECONFIG=${local.kubeconfig_path}"
        exit 1
      fi
      echo "✅ Kubectl connectivity confirmed."

      echo "📋 Current cluster state:"
      kubectl get nodes -o wide
      echo ""

      # Get node counts
      # Added error handling for kubectl commands
      ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "0")
      notready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " NotReady " || echo "0")
      total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo "0")
      ready_workers=$(kubectl get nodes --no-headers 2>/dev/null | grep -v "control-plane" | grep -c " Ready " || echo "0") # Assuming control-plane nodes have 'control-plane' in their name or role label

      echo "📊 Node Status: $ready_nodes Ready, $notready_nodes NotReady (Total: $total_nodes)"
      echo "🤖 Workers Ready: $ready_workers"

      # STRICT VALIDATIONS (adjust thresholds as needed)
      # Wait for at least one node to be ready first
      if [[ "$total_nodes" -eq 0 ]]; then
        echo "❌ FATAL: No nodes found in the cluster yet."
        exit 1
      fi

      if [[ "$notready_nodes" -gt 0 ]]; then
        echo "❌ FATAL: $notready_nodes NotReady nodes found."
        kubectl get nodes --no-headers 2>/dev/null | grep "NotReady" || echo "No NotReady nodes actually listed by kubectl."
        exit 1
      fi

      # Check based on desired counts (assuming 1 control plane + desired_worker_nodes)
      expected_ready_nodes=$((1 + ${var.desired_worker_nodes}))
      if [[ "$ready_nodes" -lt "$expected_ready_nodes" ]]; then
        echo "⚠️ WARNING: Only $ready_nodes Ready nodes found, expected at least $expected_ready_nodes (1 CP + ${var.desired_worker_nodes} workers)."
        # Decide if this should be fatal based on your requirements. For now, it's a warning.
      fi

      if [[ "$ready_workers" -lt "${var.desired_worker_nodes}" ]]; then
        echo "⚠️ WARNING: Only $ready_workers worker nodes Ready, desired ${var.desired_worker_nodes}."
      fi

      # Check core components
      echo "🔍 Validating core components..."

      # CoreDNS check
      coredns_ready=$(kubectl get deployment coredns -n kube-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
      coredns_desired=$(kubectl get deployment coredns -n kube-system -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1") # Typically 1 or 2 desired

      if [[ "$coredns_ready" -lt "$coredns_desired" ]] || [[ "$coredns_ready" == "0" ]]; then
        echo "❌ FATAL: CoreDNS not ready ($coredns_ready/$coredns_desired)."
        exit 1
      fi
      echo "   ✅ CoreDNS: $coredns_ready/$coredns_desired ready"

      # Check for problematic pods (example: more than 2 in a bad state)
      problematic_pods_count=$(kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | wc -l || echo "0")

      if [[ "$problematic_pods_count" -gt 2 ]]; then # Allow for a few transient problematic pods
        echo "❌ FATAL: Too many problematic pods ($problematic_pods_count)."
        kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | head -10 || echo "No problematic pods listed."
        exit 1
      elif [[ "$problematic_pods_count" -gt 0 ]]; then
        echo "⚠️ WARNING: $problematic_pods_count pods in non-Running/Succeeded/Completed state."
         kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null | grep -v "Completed" | tail -n +2 | head -5 || echo "No problematic pods listed."
      fi

      echo ""
      echo "✅ CLUSTER READY (based on current checks)!"
      echo "🎉 All critical validations passed:"
      echo "   • $ready_nodes Ready nodes ($ready_workers workers)"
      echo "   • 0 NotReady nodes"
      echo "   • CoreDNS operational"
    EOT
  }
}

# =============================================================================
# 🧹 CLUSTER MAINTENANCE - CLEANUP AND OPTIMIZATION
# =============================================================================

resource "null_resource" "cluster_maintenance" {
  depends_on = [null_resource.cluster_readiness_check]

  triggers = {
    cluster_ready_id    = null_resource.cluster_readiness_check.id
    maintenance_version = "v2-refined" # Ensure this matches the script content if versioned
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e # Exit on error, but allow some commands to fail gracefully with || true

      # Ensure KUBECONFIG is set from local.kubeconfig_path which is now managed by local_file
      export KUBECONFIG="${local.kubeconfig_path}"

      echo "🧹 Consolidated Cluster Maintenance v2"
      echo "================================="

      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster using KUBECONFIG=$KUBECONFIG, skipping maintenance."
        exit 0 # Exit gracefully if cluster not accessible
      fi

      # 1. Clean up orphaned nodes (nodes in k8s but not in ASG)
      echo "👻 Checking for orphaned worker nodes..."

      # Get active ASG instances (ensure local.worker_asg_name is correct)
      # Using AWS CLI to get instance IDs from ASG
      ACTIVE_ASG_INSTANCE_IDS=$(aws ec2 describe-instances \
        --region "${var.region}" \
        --filters "Name=tag:aws:autoscaling:groupName,Values=${local.worker_asg_name}" \
                  "Name=instance-state-name,Values=running,pending" \
        --query "Reservations[*].Instances[*].PrivateDnsName" \
        --output text 2>/dev/null | tr '\\t' '\\n' || echo "")
        # Using PrivateDnsName as node names often match this. Adjust if your node names are different.

      # Get worker nodes from Kubernetes
      K8S_WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null || echo "")

      ORPHANED_COUNT=0
      for node_name in $K8S_WORKER_NODES; do
        # Check if the K8s node name (which is often the private DNS name) is in the list of active ASG instances
        if ! echo "$ACTIVE_ASG_INSTANCE_IDS" | grep -qxF "$node_name"; then
          echo "🗑️ Potential orphaned node found: $node_name. Attempting removal..."
          ORPHANED_COUNT=$((ORPHANED_COUNT + 1))

          # Cordon and drain (optional, can be slow, ensure timeout)
          # kubectl cordon "$node_name" --timeout=30s || echo "Warning: Failed to cordon $node_name"
          # kubectl drain "$node_name" --ignore-daemonsets --delete-emptydir-data --force --timeout=120s || echo "Warning: Failed to drain $node_name"

          # Force delete pods on this node (quicker for non-graceful)
          echo "   Force deleting pods on $node_name..."
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$node_name" --no-headers 2>/dev/null | \
            while read -r ns pod rest; do
              echo "     Deleting pod $pod in namespace $ns on node $node_name..."
              kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=10s 2>/dev/null || echo "     Warning: Failed to delete pod $pod in $ns"
            done

          # Remove the node from Kubernetes
          echo "   Deleting node $node_name from Kubernetes..."
          kubectl delete node "$node_name" --timeout=30s 2>/dev/null || echo "   Warning: Failed to delete node $node_name"
        fi
      done
      echo "   Processed $ORPHANED_COUNT potential orphaned nodes."

      # 2. Clean up stuck terminating pods
      echo "🗑️ Cleaning up stuck terminating pods (older than 5 minutes)..."
      # This is a more complex operation and might be better suited for an in-cluster operator
      # For a simple local-exec, we can list them
      STUCK_TERMINATING_PODS=$(kubectl get pods --all-namespaces --field-selector=status.phase=Terminating -o go-template='{{range .items}}{{if gt (now.Sub .metadata.deletionTimestamp) (timeDuration "5m")}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' 2>/dev/null || echo "")

      if [[ -n "$STUCK_TERMINATING_PODS" ]]; then
        echo "Found stuck terminating pods (older than 5m):"
        echo "$STUCK_TERMINATING_PODS"
        echo "$STUCK_TERMINATING_PODS" | while read -r ns pod; do
          if [[ -n "$ns" && -n "$pod" ]]; then # Ensure we have both namespace and pod name
             echo "   Forcibly deleting stuck pod $pod in namespace $ns..."
             kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=10s 2>/dev/null || echo "   Warning: Failed to delete stuck pod $pod in $ns"
          fi
        done
      else
        echo "   No stuck terminating pods found (older than 5 minutes)."
      fi

      echo "✅ Cluster maintenance checks completed."
    EOT
  }
}

# =============================================================================
# 🔐 APPLICATION SETUP - NAMESPACES AND SECRETS
# =============================================================================

# Essential namespace and secret creation
resource "null_resource" "application_setup" {
  depends_on = [null_resource.cluster_readiness_check] # Depends on cluster being ready

  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id
    setup_version    = "v2-idempotent" # Ensure this matches the script content if versioned
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e # Exit on error

      export KUBECONFIG="${local.kubeconfig_path}"

      echo "🔐 Application Setup - Namespaces and Secrets v2"
      echo "============================================"

      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster using KUBECONFIG=$KUBECONFIG."
        exit 1
      fi

      # Create namespaces idempotently
      echo "📁 Creating namespaces (if they don't exist)..."
      for namespace in prod dev; do
        # Use apply for idempotency; --dry-run=client is for local check, not needed with apply
        # Kubectl apply will create if not exists, or update if exists (though for namespaces, update is less common)
        echo "apiVersion: v1
kind: Namespace
metadata:
  name: $namespace" | kubectl apply -f -
        echo "   ✅ Namespace: $namespace ensured"
      done

      # Generate certificates for TLS secrets (dummy for now, should be managed properly)
      echo "🔐 Ensuring TLS certificates and secrets..."
      CERT_DIR="/tmp/polybot-certs-$$" # Use process ID for temp uniqueness
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
        echo "   ℹ️ Using dummy TLS certificates for setup."
      fi

      # Create secrets in both namespaces idempotently
      for namespace in prod dev; do
        echo "🔑 Ensuring secrets in namespace: $namespace"

        # TLS secret
        # Use apply for idempotency. --force might be needed if replacing, but apply handles create/update.
        kubectl create secret tls polybot-tls \
          --cert="$CRT_FILE" --key="$KEY_FILE" -n "$namespace" \
          --dry-run=client -o yaml | kubectl apply -f - || echo "   ⚠️  polybot-tls secret in $namespace might already exist or failed to apply."

        # CA secret
        kubectl create secret generic polybot-ca \
          --from-file=ca.crt="$CA_FILE" -n "$namespace" \
          --dry-run=client -o yaml | kubectl apply -f - || echo "   ⚠️  polybot-ca secret in $namespace might already exist or failed to apply."

        # Application secrets (ensure values are appropriate or use more secure methods for production)
        kubectl create secret generic polybot-secrets \
          --from-literal=app-secret='default-app-secret-value' \
          --from-literal=database-url='postgresql://polybot:examplepassword@your-db-host:5432/polybotdb' \
          --from-literal=redis-url='redis://your-redis-host:6379/0' \
          -n "$namespace" \
          --dry-run=client -o yaml | kubectl apply -f - || echo "   ⚠️  polybot-secrets in $namespace might already exist or failed to apply."

        echo "   ✅ Secrets ensured in $namespace"
      done

      # Cleanup
      cd / # Change out of the temp dir before removing it
      rm -rf "$CERT_DIR"

      echo "✅ Application setup completed"
    EOT
  }
}

# =============================================================================
# 🚀 ARGOCD DEPLOYMENT - GITOPS PLATFORM
# =============================================================================

# Streamlined ArgoCD installation
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [null_resource.application_setup]

  triggers = {
    setup_id       = null_resource.application_setup.id
    argocd_version = "v3-idempotent" # Ensure this matches script content if versioned
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e # Exit on error

      export KUBECONFIG="${local.kubeconfig_path}"

      echo "🚀 Installing/Verifying ArgoCD v3"
      echo "============================"

      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster using KUBECONFIG=$KUBECONFIG."
        exit 1
      fi

      ARGOCD_NAMESPACE="argocd"

      # Check if ArgoCD namespace exists
      if ! kubectl get namespace "$ARGOCD_NAMESPACE" >/dev/null 2>&1; then
        echo "📁 Creating ArgoCD namespace: $ARGOCD_NAMESPACE..."
        kubectl create namespace "$ARGOCD_NAMESPACE"
      else
        echo "ℹ️ ArgoCD namespace '$ARGOCD_NAMESPACE' already exists."
      fi

      # Apply ArgoCD manifests (idempotent)
      echo "📦 Applying ArgoCD manifests from stable release..."
      # Using apply is idempotent; it will create or update resources.
      if kubectl apply -n "$ARGOCD_NAMESPACE" -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml; then
        echo "✅ ArgoCD manifests applied/updated successfully."
      else
        echo "❌ Failed to apply ArgoCD manifests."
        # Consider if this should be a fatal error. If apply fails, something is wrong.
        # For robustness, you might want to check specific deployments after apply.
        kubectl get all -n "$ARGOCD_NAMESPACE" # Show status if apply fails
        exit 1
      fi

      echo "⏳ Waiting for ArgoCD server deployment to be available (this might take a few minutes)..."
      # Wait for the argocd-server deployment to be available
      if kubectl wait deployment -n "$ARGOCD_NAMESPACE" argocd-server --for condition=Available --timeout=300s; then
        echo "✅ ArgoCD server deployment is available."
      else
        echo "❌ ArgoCD server deployment did not become available within timeout."
        echo "   Current status of ArgoCD pods:"
        kubectl get pods -n "$ARGOCD_NAMESPACE"
        echo "   Current status of ArgoCD deployments:"
        kubectl get deployments -n "$ARGOCD_NAMESPACE"
        exit 1
      fi

      # Get admin password (this secret is usually created by ArgoCD upon first install)
      echo "🔑 Retrieving ArgoCD admin password (if initial setup)..."
      PASSWORD_SECRET_NAME="argocd-initial-admin-secret"
      if kubectl get secret -n "$ARGOCD_NAMESPACE" "$PASSWORD_SECRET_NAME" >/dev/null 2>&1; then
        RAW_PASSWORD=$(kubectl -n "$ARGOCD_NAMESPACE" get secret "$PASSWORD_SECRET_NAME" -o jsonpath="{.data.password}" 2>/dev/null || echo "")
        if [[ -n "$RAW_PASSWORD" ]]; then
          ARGOCD_PASSWORD=$(echo "$RAW_PASSWORD" | base64 -d)
          echo "🔑 ArgoCD Admin Password: $ARGOCD_PASSWORD"
        else
          echo "ℹ️ ArgoCD initial admin password not found in secret (might have been changed or is an older install)."
        fi
      else
        echo "ℹ️ ArgoCD initial admin secret '$PASSWORD_SECRET_NAME' not found (might have been changed or is an older install)."
      fi

      echo ""
      echo "✅ ArgoCD installation/verification completed!"
      echo "🌐 Access ArgoCD by port-forwarding: kubectl port-forward svc/argocd-server -n $ARGOCD_NAMESPACE 8080:443"
      echo "👤 Username: admin"
      echo "🔑 Password: (If newly installed, see above. Otherwise, use your current password)."
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

      # Ensure KUBECONFIG is set from local.kubeconfig_path
      export KUBECONFIG="${local.kubeconfig_path}"

      echo ""
      echo "🎉======================================================🎉"
      echo "    POLYBOT KUBERNETES CLUSTER DEPLOYMENT SUMMARY"
      echo "🎉======================================================🎉"
      echo ""

      # Control Plane Information (ensure module outputs are correctly referenced)
      echo "🖥️  CONTROL PLANE"
      echo "================="
      # These come from Terraform interpolations, no $ needed for shell interpretation after TF processes them.
      # Assuming module.k8s-cluster has these outputs defined in its outputs.tf
      PUBLIC_IP_VAL="${module.k8s-cluster.control_plane_public_ip_output}"
      INSTANCE_ID_VAL="${module.k8s-cluster.control_plane_instance_id_output}"
      KEY_NAME_VAL="${module.k8s-cluster.ssh_key_name_output}" # Assuming an output for key name from module

      echo "📍 Instance ID:  $INSTANCE_ID_VAL"
      echo "🌐 Public IP:    $PUBLIC_IP_VAL"
      echo "🔗 API Endpoint: https://$PUBLIC_IP_VAL:6443"
      if [[ -n "$KEY_NAME_VAL" && "$KEY_NAME_VAL" != "null" ]]; then # Check if key name is available
        echo "🔑 SSH Command:  ssh -i $KEY_NAME_VAL.pem ubuntu@$PUBLIC_IP_VAL"
      else
        echo "🔑 SSH Command:  ssh -i <your-key-name.pem> ubuntu@$PUBLIC_IP_VAL"
      fi
      echo ""

      # Cluster Status
      echo "☸️  CLUSTER STATUS"
      echo "================="
      if kubectl get nodes >/dev/null 2>&1; then
        TOTAL_NODES=$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo "N/A")
        READY_NODES=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "N/A")
        # Assuming control plane has 'control-plane' in its name or a label.
        # Adjust if using a specific label like !node-role.kubernetes.io/master or !node-role.kubernetes.io/control-plane
        READY_WORKERS=$(kubectl get nodes --no-headers 2>/dev/null | grep -v "control-plane" | grep -c " Ready " || echo "N/A")

        echo "📊 Nodes: $READY_NODES/$TOTAL_NODES Ready ($READY_WORKERS workers)"
        echo "📋 Node Details:"
        kubectl get nodes -o wide 2>/dev/null | tail -n +2 | while read -r node status rest; do
          echo "   • $node ($status)"
        done || echo "   Could not retrieve node details."
      else
        echo "⚠️  Cannot connect to cluster to retrieve status."
      fi
      echo ""

      # Kubernetes Access
      echo "🔗 KUBERNETES ACCESS"
      echo "==================="
      echo "📁 Kubeconfig: ${local.kubeconfig_path}" # Terraform interpolation
      echo "🚀 Quick Setup:"
      echo "   export KUBECONFIG=${local.kubeconfig_path}" # Terraform interpolation
      echo "   kubectl get nodes"
      echo ""

      # ArgoCD Access
      ARGOCD_NAMESPACE="argocd"
      echo "🔐 ARGOCD ACCESS"
      echo "==============="
      if kubectl get namespace "$ARGOCD_NAMESPACE" >/dev/null 2>&1; then
        ARGOCD_READY_REPLICAS=$(kubectl -n "$ARGOCD_NAMESPACE" get deployment argocd-server -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        ARGOCD_DESIRED_REPLICAS=$(kubectl -n "$ARGOCD_NAMESPACE" get deployment argocd-server -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "N/A")
        echo "📊 Status: $ARGOCD_READY_REPLICAS/$ARGOCD_DESIRED_REPLICAS ready replicas"
        echo "🌐 URL (via port-forward): https://localhost:8080 (or specified port)" # Changed to 8080 as common example
        echo "👤 Username: admin"

        PASSWORD_SECRET_NAME="argocd-initial-admin-secret"
        RAW_PASSWORD=$(kubectl -n "$ARGOCD_NAMESPACE" get secret "$PASSWORD_SECRET_NAME" -o jsonpath="{.data.password}" 2>/dev/null || echo "")
        if [[ -n "$RAW_PASSWORD" ]]; then
          ARGOCD_PASSWORD=$(echo "$RAW_PASSWORD" | base64 -d 2>/dev/null || echo "<failed to decode>")
          echo "🔑 Password: $ARGOCD_PASSWORD (this is the initial password, may have changed)"
        else
          echo "🔑 Password: (Initial admin secret not found or password field empty; use current password)"
        fi
        echo "🔗 Setup Port Forward: kubectl port-forward svc/argocd-server -n $ARGOCD_NAMESPACE 8080:443"
      else
        echo "ℹ️ ArgoCD namespace not found (ArgoCD might be skipped or not installed)."
      fi
      echo ""

      # AWS Resources (ensure module outputs are correct)
      echo "☁️  AWS RESOURCES"
      echo "==============="
      echo "🌐 VPC ID: ${module.k8s-cluster.vpc_id_output}" # Assuming module output, e.g., vpc_id_output
      ALB_DNS_NAME="${module.k8s-cluster.alb_dns_name_output}" # Assuming module output
      if [[ -n "$ALB_DNS_NAME" && "$ALB_DNS_NAME" != "null" ]]; then
        echo "⚖️ Load Balancer DNS: $ALB_DNS_NAME"
      else
        echo "⚖️ Load Balancer DNS: (Not available or ALB not created)"
      fi
      echo "🔄 Auto Scaling Group: ${module.k8s-cluster.worker_asg_name_output}" # Assuming module output
      echo ""

      echo "✅======================================================✅"
      echo "   🎯 DEPLOYMENT SUMMARY COMPLETE"
      echo "✅======================================================✅"
    EOT
  }
}