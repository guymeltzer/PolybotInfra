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
  k8s_version = "1.32.3"
  
  # Cluster configuration
  cluster_name = "guy-cluster"
  worker_asg_name = "guy-polybot-asg"
  
  # Paths and file management
  kubeconfig_path = "${path.module}/kubeconfig.yaml"
  ssh_private_key_path = var.key_name != "" ? (
    fileexists("${path.module}/${var.key_name}.pem") ? 
    "${path.module}/${var.key_name}.pem" : 
    (fileexists("${pathexpand("~/.ssh/${var.key_name}.pem")}") ?
      "${pathexpand("~/.ssh/${var.key_name}.pem")}" :
      "${path.module}/polybot-key.pem"
    )
  ) : "${path.module}/polybot-key.pem"
  
  # Feature flags
  skip_argocd = false
  skip_namespaces = false
  
  # Cluster readiness validation
  kubeconfig_exists = fileexists(local.kubeconfig_path)
  k8s_ready = local.kubeconfig_exists && (
    !strcontains(
      try(file(local.kubeconfig_path), ""),
      "server: https://placeholder:6443"
    )
  )
}

# =============================================================================
# 🏗️ CLUSTER MODULE - CORE INFRASTRUCTURE
# =============================================================================

module "k8s-cluster" {
  source = "./modules/k8s-cluster"
  
  # Core configuration
  region                       = var.region
  cluster_name                 = local.cluster_name
  vpc_id                       = var.vpc_id
  subnet_ids                   = var.subnet_ids
  route53_zone_id              = var.route53_zone_id
  domain_name                  = var.domain_name
  
  # Instance configuration
  control_plane_ami            = var.control_plane_ami
  worker_ami                   = var.worker_ami
  control_plane_instance_type  = var.control_plane_instance_type
  worker_instance_type         = var.worker_instance_type
  instance_type                = var.instance_type
  
  # SSH configuration
  key_name                     = var.key_name
  ssh_public_key              = var.ssh_public_key
  ssh_private_key_file_path   = local.ssh_private_key_path
  
  # Worker node configuration
  worker_count                 = var.desired_worker_nodes
  desired_worker_nodes         = var.desired_worker_nodes
  
  # Network configuration
  pod_cidr                    = var.pod_cidr
  
  # ASG control
  force_cleanup_asg           = var.force_cleanup_asg
  
  # Verification settings
  skip_api_verification       = var.skip_api_verification
  skip_token_verification     = var.skip_token_verification
  verification_max_attempts   = var.verification_max_attempts
  verification_wait_seconds   = var.verification_wait_seconds
  
  # Deployment environment
  deployment_environment      = "prod"
  
  tags = {
    Environment = "production"
    Project     = "polybot"
    ManagedBy   = "terraform"
    KubernetesVersion = local.k8s_version
  }
}

# =============================================================================
# ☸️ KUBERNETES SETUP - KUBECONFIG AND CLUSTER ACCESS
# =============================================================================

# Enhanced kubeconfig generation with robust validation
resource "terraform_data" "kubectl_provider_config" {
  count = 1

  triggers_replace = {
    control_plane_id  = module.k8s-cluster.control_plane_instance_id
    control_plane_ip  = module.k8s-cluster.control_plane_public_ip
    kubeconfig_version = "v6-refactored-robust"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      echo "🔑 Robust Kubeconfig Setup v6 - Refactored"
      echo "==========================================="
      
      INSTANCE_ID="${module.k8s-cluster.control_plane_instance_id}"
      PUBLIC_IP="${module.k8s-cluster.control_plane_public_ip}"
      REGION="${var.region}"
      
      echo "📡 Control Plane: $INSTANCE_ID (IP: $PUBLIC_IP)"
      echo "📁 Kubeconfig Path: ${local.kubeconfig_path}"
      
      # Wait for kubeadm completion with enhanced validation
      wait_for_kubeadm() {
        local max_wait=15
        local check_interval=45
        local max_checks=$((max_wait * 60 / check_interval))
        
        echo "🔍 Waiting for kubeadm init completion (max: $max_wait minutes)..."
        
        for check in $(seq 1 $max_checks); do
          local elapsed=$((check * check_interval / 60))
          echo "🔄 Check $check/$max_checks ($${elapsed}m elapsed): Verifying kubeadm completion..."
          
          COMMAND_ID=$(aws ssm send-command \
            --region "$REGION" \
            --document-name "AWS-RunShellScript" \
            --instance-ids "$INSTANCE_ID" \
            --parameters 'commands=[
              "#!/bin/bash",
              "echo \"=== KUBEADM COMPLETION CHECK ===\"",
              "# Check admin.conf exists and is valid",
              "if [ -f /etc/kubernetes/admin.conf ] && [ -s /etc/kubernetes/admin.conf ]; then",
              "  if grep -q \"apiVersion.*Config\" /etc/kubernetes/admin.conf; then",
              "    echo \"✅ admin.conf: EXISTS and VALID\"",
              "  else",
              "    echo \"❌ admin.conf: EXISTS but INVALID\"",
              "    exit 1",
              "  fi",
              "else",
              "  echo \"❌ admin.conf: MISSING\"",
              "  exit 1",
              "fi",
              "# Check kubelet is active",
              "if systemctl is-active --quiet kubelet; then",
              "  echo \"✅ kubelet: ACTIVE\"",
              "else",
              "  echo \"❌ kubelet: NOT ACTIVE\"",
              "  exit 1",
              "fi",
              "# Check API server responds",
              "if curl -k -s https://localhost:6443/healthz | grep -q ok; then",
              "  echo \"✅ API server: RESPONDING\"",
              "else",
              "  echo \"❌ API server: NOT RESPONDING\"",
              "  exit 1",
              "fi",
              "echo \"🎉 KUBEADM INIT: COMPLETE\""
            ]' \
            --output text \
            --query "Command.CommandId" 2>/dev/null)
          
          if [[ -z "$COMMAND_ID" ]]; then
            echo "   ⚠️ Failed to send SSM command, retrying..."
            sleep $check_interval
            continue
          fi
          
          echo "   ⏳ Waiting for check completion (ID: $COMMAND_ID)..."
          sleep 30
          
          RESULT=$(aws ssm get-command-invocation \
            --region "$REGION" \
            --command-id "$COMMAND_ID" \
            --instance-id "$INSTANCE_ID" \
            --output json 2>/dev/null || echo "{}")
          
          STATUS=$(echo "$RESULT" | jq -r '.ResponseCode // ""' 2>/dev/null || echo "")
          STDOUT=$(echo "$RESULT" | jq -r '.StandardOutputContent // ""' 2>/dev/null || echo "")
          
          echo "   📋 Status: $STATUS"
          echo "$STDOUT" | sed 's/^/      /'
          
          if [[ "$STATUS" == "0" ]] && echo "$STDOUT" | grep -q "KUBEADM INIT: COMPLETE"; then
            echo "   ✅ kubeadm init completed successfully!"
            return 0
          fi
          
          if [[ $check -eq $max_checks ]]; then
            echo "❌ TIMEOUT: kubeadm init did not complete after $max_wait minutes"
            return 1
          fi
          
          echo "   ⏳ Waiting $check_interval seconds before next check..."
          sleep $check_interval
        done
        
        return 1
      }
      
      # Fetch and validate kubeconfig
      fetch_kubeconfig() {
        echo "📁 Fetching kubeconfig from control plane..."
        
        for attempt in $(seq 1 3); do
          echo "🔄 Fetch attempt $attempt/3..."
          
          COMMAND_ID=$(aws ssm send-command \
            --region "$REGION" \
            --document-name "AWS-RunShellScript" \
            --instance-ids "$INSTANCE_ID" \
            --parameters 'commands=[
              "#!/bin/bash",
              "echo \"=== ADMIN.CONF CONTENT START ===\"",
              "cat /etc/kubernetes/admin.conf",
              "echo \"=== ADMIN.CONF CONTENT END ===\""
            ]' \
            --output text \
            --query "Command.CommandId")
          
          sleep 20
          
          FETCH_RESULT=$(aws ssm get-command-invocation \
            --region "$REGION" \
            --command-id "$COMMAND_ID" \
            --instance-id "$INSTANCE_ID" \
            --output json 2>/dev/null || echo "{}")
          
          FETCH_STDOUT=$(echo "$FETCH_RESULT" | jq -r '.StandardOutputContent // ""' 2>/dev/null || echo "")
          FETCH_STATUS=$(echo "$FETCH_RESULT" | jq -r '.ResponseCode // ""' 2>/dev/null || echo "")
          
          if [[ "$FETCH_STATUS" != "0" ]]; then
            echo "   ❌ Fetch failed, retrying..."
            sleep 20
            continue
          fi
          
          KUBECONFIG_CONTENT=$(echo "$FETCH_STDOUT" | \
            sed -n '/=== ADMIN.CONF CONTENT START ===/,/=== ADMIN.CONF CONTENT END ===/p' | \
            sed '1d;$d')
          
          if [[ -z "$KUBECONFIG_CONTENT" ]]; then
            echo "   ❌ No content found, retrying..."
            sleep 20
            continue
          fi
          
          # Validate and update kubeconfig
          if echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion.*Config"; then
            echo "   🔧 Updating server endpoint to public IP..."
            UPDATED_KUBECONFIG=$(echo "$KUBECONFIG_CONTENT" | \
              sed "s|server:.*|server: https://$PUBLIC_IP:6443|g")
            
            echo "$UPDATED_KUBECONFIG" > "${local.kubeconfig_path}"
            chmod 600 "${local.kubeconfig_path}"
            
            echo "   ✅ Kubeconfig created successfully!"
            return 0
          fi
          
          echo "   ❌ Invalid kubeconfig content, retrying..."
          sleep 20
        done
        
        echo "❌ Failed to fetch valid kubeconfig after 3 attempts"
        return 1
      }
      
      # Main execution
      if wait_for_kubeadm && fetch_kubeconfig; then
        echo "🎉 SUCCESS: Kubeconfig setup completed!"
        echo "📁 File: ${local.kubeconfig_path}"
        echo "🔗 Server: https://$PUBLIC_IP:6443"
      else
        echo "❌ FAILED: Kubeconfig setup failed"
        exit 1
      fi
    EOT
  }
  
  depends_on = [module.k8s-cluster]
}

# =============================================================================
# 🔍 CLUSTER VALIDATION - HEALTH AND READINESS CHECKS
# =============================================================================

# Comprehensive cluster readiness validation
resource "null_resource" "cluster_readiness_check" {
  depends_on = [terraform_data.kubectl_provider_config[0]]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    readiness_version = "v3-refactored-strict"
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔍 STRICT Cluster Readiness Validation v3"
      echo "========================================"
      
      # Validate kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ FATAL: Cannot connect to cluster"
        exit 1
      fi
      
      echo "📋 Current cluster state:"
      kubectl get nodes -o wide
      echo ""
      
      # Get node counts
      ready_nodes=$(kubectl get nodes --no-headers | grep -c " Ready " || echo "0")
      notready_nodes=$(kubectl get nodes --no-headers | grep -c " NotReady " || echo "0")
      ready_workers=$(kubectl get nodes --no-headers | grep -v "control-plane" | grep -c " Ready " || echo "0")
      
      echo "📊 Node Status: $ready_nodes Ready, $notready_nodes NotReady"
      echo "🤖 Workers Ready: $ready_workers"
      
      # STRICT VALIDATIONS
      if [[ "$notready_nodes" -gt 0 ]]; then
        echo "❌ FATAL: $notready_nodes NotReady nodes found"
        kubectl get nodes --no-headers | grep "NotReady"
        exit 1
      fi
      
      if [[ "$ready_nodes" -lt 3 ]]; then
        echo "❌ FATAL: Only $ready_nodes nodes (minimum 3 required)"
        exit 1
      fi
      
      if [[ "$ready_workers" -lt 2 ]]; then
        echo "❌ FATAL: Only $ready_workers worker nodes (minimum 2 required)"
        exit 1
      fi
      
      # Check core components
      echo "🔍 Validating core components..."
      
      # CoreDNS check
      coredns_ready=$(kubectl get deployment coredns -n kube-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
      coredns_desired=$(kubectl get deployment coredns -n kube-system -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "2")
      
      if [[ "$coredns_ready" -lt "$coredns_desired" ]]; then
        echo "❌ FATAL: CoreDNS not ready ($coredns_ready/$coredns_desired)"
        exit 1
      fi
      echo "   ✅ CoreDNS: $coredns_ready/$coredns_desired ready"
      
      # Check for problematic pods
      problematic_pods=$(kubectl get pods --all-namespaces | grep -E "(Pending|ContainerCreating|Error|CrashLoopBackOff)" | wc -l || echo "0")
      
      if [[ "$problematic_pods" -gt 5 ]]; then
        echo "❌ FATAL: Too many problematic pods ($problematic_pods)"
        kubectl get pods --all-namespaces | grep -E "(Pending|ContainerCreating|Error|CrashLoopBackOff)" | head -10
        exit 1
      fi
      
      echo ""
      echo "✅ CLUSTER READY!"
      echo "🎉 All validations passed:"
      echo "   • $ready_nodes Ready nodes ($ready_workers workers)"
      echo "   • 0 NotReady nodes"
      echo "   • CoreDNS operational"
      echo "   • $problematic_pods problematic pods (threshold: ≤5)"
    EOT
  }
}

# =============================================================================
# 🧹 CLUSTER MAINTENANCE - CLEANUP AND OPTIMIZATION
# =============================================================================

# Consolidated cluster cleanup and maintenance
resource "null_resource" "cluster_maintenance" {
  depends_on = [null_resource.cluster_readiness_check]
  
  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id
    maintenance_version = "v1-consolidated"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🧹 Consolidated Cluster Maintenance"
      echo "================================="
      
      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster, skipping maintenance"
        exit 0
      fi
      
      # 1. Clean up orphaned nodes
      echo "👻 Checking for orphaned nodes..."
      
      # Get active ASG instances
      active_instances=$(aws ec2 describe-instances \
        --region ${var.region} \
        --filters "Name=tag:aws:autoscaling:groupName,Values=${local.worker_asg_name}" \
                  "Name=instance-state-name,Values=running,pending" \
        --query "Reservations[*].Instances[*].InstanceId" \
        --output text 2>/dev/null || echo "")
      
      # Check worker nodes
      worker_nodes=$(kubectl get nodes --no-headers | grep -v "control-plane" | awk '{print $1}' || echo "")
      
      for node_name in $worker_nodes; do
        instance_id=""
        
        # Extract instance ID from node name
        if [[ "$node_name" =~ worker-([a-f0-9]{17})$ ]]; then
          instance_id="i-$${BASH_REMATCH[1]}"
        elif [[ "$node_name" =~ (i-[a-f0-9]{8,17}) ]]; then
          instance_id="$${BASH_REMATCH[1]}"
        fi
        
        # Check if instance exists in ASG
        if [[ -n "$instance_id" ]] && ! echo "$active_instances" | grep -q "$instance_id"; then
          echo "🗑️ Removing orphaned node: $node_name (instance: $instance_id)"
          
          # Force delete pods on this node
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$node_name" --no-headers 2>/dev/null | \
            while read -r ns pod rest; do
              kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=5s 2>/dev/null || true
            done
          
          # Remove the node
          kubectl delete node "$node_name" --force --grace-period=0 2>/dev/null || true
        fi
      done
      
      # 2. Clean up terminating pods
      echo "🗑️ Cleaning up stuck terminating pods..."
      terminating_pods=$(kubectl get pods --all-namespaces --field-selector=status.phase=Terminating --no-headers 2>/dev/null || echo "")
      
      if [[ -n "$terminating_pods" ]]; then
        echo "$terminating_pods" | while read -r ns pod rest; do
          kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 --timeout=5s 2>/dev/null || true
        done
      fi
      
      echo "✅ Cluster maintenance completed"
    EOT
  }
}

# =============================================================================
# 🔐 APPLICATION SETUP - NAMESPACES AND SECRETS
# =============================================================================

# Essential namespace and secret creation
resource "null_resource" "application_setup" {
  depends_on = [null_resource.cluster_readiness_check]
  
  triggers = {
    cluster_ready_id = null_resource.cluster_readiness_check.id
    setup_version = "v1-consolidated"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔐 Application Setup - Namespaces and Secrets"
      echo "============================================"
      
      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster"
        exit 1
      fi
      
      # Create namespaces
      echo "📁 Creating namespaces..."
      for namespace in prod dev; do
        kubectl create namespace $namespace --dry-run=client -o yaml | kubectl apply -f -
        echo "   ✅ Namespace: $namespace"
      done
      
      # Generate certificates for TLS secrets
      echo "🔐 Generating TLS certificates..."
      mkdir -p /tmp/polybot-certs
      cd /tmp/polybot-certs
      
      # Generate certificates (or create dummy ones if OpenSSL unavailable)
      if command -v openssl >/dev/null 2>&1; then
        openssl genrsa -out polybot.key 2048 2>/dev/null || echo "dummy-key" > polybot.key
        openssl req -new -x509 -key polybot.key -out polybot.crt -days 365 -subj "/CN=polybot.local" 2>/dev/null || echo "dummy-cert" > polybot.crt
        cp polybot.crt ca.crt
      else
        echo "dummy-key" > polybot.key
        echo "dummy-cert" > polybot.crt
        echo "dummy-ca" > ca.crt
      fi
      
      # Create secrets in both namespaces
      for namespace in prod dev; do
        echo "🔑 Creating secrets in namespace: $namespace"
        
        # TLS secret
        kubectl create secret tls polybot-tls \
          --cert=polybot.crt --key=polybot.key -n $namespace \
          --dry-run=client -o yaml | kubectl apply -f -
        
        # CA secret
        kubectl create secret generic polybot-ca \
          --from-file=ca.crt=ca.crt -n $namespace \
          --dry-run=client -o yaml | kubectl apply -f -
        
        # Application secrets
        kubectl create secret generic polybot-secrets \
          --from-literal=app-secret=default-value \
          --from-literal=database-url=postgresql://polybot:password@localhost:5432/polybot \
          --from-literal=redis-url=redis://localhost:6379/0 \
          -n $namespace \
          --dry-run=client -o yaml | kubectl apply -f -
        
        echo "   ✅ Secrets created in $namespace"
      done
      
      # Cleanup
      rm -rf /tmp/polybot-certs
      
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
    setup_id = null_resource.application_setup.id
    argocd_version = "v2-streamlined"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🚀 Installing ArgoCD v2"
      echo "====================="
      
      # Check kubectl connectivity
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster"
        exit 1
      fi
      
      # Check if ArgoCD already exists and is healthy
      if kubectl get namespace argocd >/dev/null 2>&1; then
        if kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=30s >/dev/null 2>&1; then
          echo "✅ ArgoCD already installed and healthy"
          exit 0
        else
          echo "⚠️ ArgoCD exists but unhealthy, reinstalling..."
          kubectl delete namespace argocd --timeout=120s || true
          while kubectl get namespace argocd >/dev/null 2>&1; do
            echo "   Waiting for namespace deletion..."
            sleep 5
          done
        fi
      fi
      
      # Install ArgoCD
      echo "📁 Creating ArgoCD namespace..."
      kubectl create namespace argocd
      
      echo "📦 Installing ArgoCD manifests..."
      if curl -fsSL --connect-timeout 30 --max-time 120 \
           https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml | \
           kubectl apply -n argocd -f -; then
        echo "✅ ArgoCD manifests applied"
      else
        echo "❌ Failed to install ArgoCD manifests"
        exit 1
      fi
      
      echo "⏳ Waiting for ArgoCD server to be ready..."
      if kubectl -n argocd wait --for=condition=available deployment/argocd-server --timeout=300s; then
        echo "✅ ArgoCD server is ready"
      else
        echo "❌ ArgoCD server not ready within timeout"
        exit 1
      fi
      
      # Get admin password
      echo "🔑 Retrieving ArgoCD admin password..."
      for i in {1..10}; do
        if kubectl -n argocd get secret argocd-initial-admin-secret >/dev/null 2>&1; then
          PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d 2>/dev/null || echo "")
          if [[ -n "$PASSWORD" ]]; then
            echo "Password: $PASSWORD"
            break
          fi
        fi
        echo "   Waiting for password secret... ($i/10)"
        sleep 10
      done
      
      echo "✅ ArgoCD installation completed!"
      echo "🌐 Access: kubectl port-forward svc/argocd-server -n argocd 8081:443"
      echo "👤 Username: admin"
      echo "🔑 Password: $PASSWORD"
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
    maintenance_id = null_resource.cluster_maintenance.id
    setup_id = null_resource.application_setup.id
    argocd_id = try(null_resource.install_argocd[0].id, "skipped")
    summary_version = "v2-comprehensive"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo ""
      echo "🎉======================================================🎉"
      echo "    POLYBOT KUBERNETES CLUSTER DEPLOYMENT COMPLETE"
      echo "🎉======================================================🎉"
      echo ""
      
      # Control Plane Information
      echo "🖥️ CONTROL PLANE"
      echo "================"
      PUBLIC_IP="${module.k8s-cluster.control_plane_public_ip}"
      INSTANCE_ID="${module.k8s-cluster.control_plane_instance_id}"
      echo "📍 Instance ID:  $INSTANCE_ID"
      echo "🌐 Public IP:    $PUBLIC_IP"
      echo "🔗 API Endpoint: https://$PUBLIC_IP:6443"
      echo "🔑 SSH Command:  ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@$PUBLIC_IP"
      echo ""
      
      # Cluster Status
      echo "☸️ CLUSTER STATUS"
      echo "================="
      if kubectl get nodes >/dev/null 2>&1; then
        TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l)
        READY_NODES=$(kubectl get nodes --no-headers | grep -c " Ready ")
        READY_WORKERS=$(kubectl get nodes --no-headers | grep -v "control-plane" | grep -c " Ready ")
        
        echo "📊 Nodes: $READY_NODES/$TOTAL_NODES Ready ($READY_WORKERS workers)"
        echo "📋 Node Details:"
        kubectl get nodes -o wide | tail -n +2 | while read -r node status rest; do
          echo "   • $node ($status)"
        done
      else
        echo "⚠️ Cannot connect to cluster"
      fi
      echo ""
      
      # Kubernetes Access
      echo "🔗 KUBERNETES ACCESS"
      echo "==================="
      echo "📁 Kubeconfig: ${local.kubeconfig_path}"
      echo "🚀 Quick Setup:"
      echo "   export KUBECONFIG=${local.kubeconfig_path}"
      echo "   kubectl get nodes"
      echo ""
      
      # ArgoCD Access
      echo "🔐 ARGOCD ACCESS"
      echo "==============="
      if kubectl get namespace argocd >/dev/null 2>&1; then
        ARGOCD_STATUS=$(kubectl -n argocd get deployment argocd-server -o jsonpath='{.status.readyReplicas}/{.spec.replicas}' 2>/dev/null || echo "unknown")
        echo "📊 Status: $ARGOCD_STATUS ready"
        echo "🌐 URL: https://localhost:8081"
        echo "👤 Username: admin"
        
        PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d 2>/dev/null || echo "")
        if [[ -n "$PASSWORD" ]]; then
          echo "🔑 Password: $PASSWORD"
        fi
        echo "🔗 Setup: kubectl port-forward svc/argocd-server -n argocd 8081:443"
      else
        echo "❌ ArgoCD not installed"
      fi
      echo ""
      
      # AWS Resources
      echo "☁️ AWS RESOURCES"
      echo "==============="
      echo "🌐 VPC ID: ${module.k8s-cluster.vpc_id}"
      echo "⚖️ Load Balancer: ${module.k8s-cluster.alb_dns_name}"
      echo "🔄 Auto Scaling: ${module.k8s-cluster.worker_asg_name}"
      echo "🔑 SSH Key: ${module.k8s-cluster.ssh_key_name}.pem"
      echo ""
      
      # Quick Commands
      echo "🚀 QUICK COMMANDS"
      echo "================"
      echo "1️⃣ Connect: export KUBECONFIG=${local.kubeconfig_path}"
      echo "2️⃣ Check cluster: kubectl get nodes"
      echo "3️⃣ Access ArgoCD: kubectl port-forward svc/argocd-server -n argocd 8081:443"
      echo "4️⃣ Deploy test app: kubectl create deployment nginx --image=nginx"
      echo ""
      
      echo "✅======================================================✅"
      echo "   🎯 DEPLOYMENT SUCCESSFUL - CLUSTER READY FOR USE!"
      echo "✅======================================================✅"
    EOT
  }
}
