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

# CONSOLIDATED: Enhanced cluster readiness check
# Replaces: cluster_readiness_check and pre_argocd_health_check
resource "null_resource" "cluster_readiness_check" {
  depends_on = [
    null_resource.wait_for_kubernetes,
    null_resource.install_calico,
    null_resource.install_ebs_csi_driver,
    terraform_data.kubectl_provider_config
  ]

  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    calico_id = null_resource.install_calico.id
    ebs_csi_id = null_resource.install_ebs_csi_driver.id
    readiness_version = "consolidated-v2"
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
      
      # Function to wait for resource with timeout
      wait_for_resource() {
        local resource_type="$1"
        local resource_name="$2"  
        local namespace="$3"
        local timeout="$4"
        local condition="$5"
        
        echo "⏳ Waiting for $resource_type/$resource_name in namespace $namespace..."
        
        if [[ "$condition" == "available" ]]; then
          if kubectl -n "$namespace" wait --for=condition=available "$resource_type/$resource_name" --timeout="$${timeout}s"; then
            echo "✅ $resource_type/$resource_name is available"
            return 0
          fi
        elif [[ "$condition" == "ready" ]]; then
          if kubectl -n "$namespace" wait --for=condition=ready pod -l "$resource_name" --timeout="$${timeout}s"; then
            echo "✅ Pods with label $resource_name are ready"
            return 0
          fi
        elif [[ "$condition" == "rollout" ]]; then
          if kubectl -n "$namespace" rollout status "$resource_type/$resource_name" --timeout="$${timeout}s"; then
            echo "✅ $resource_type/$resource_name rollout completed"
            return 0
          fi
        fi
        
        echo "❌ $resource_type/$resource_name failed readiness check"
        kubectl -n "$namespace" describe "$resource_type/$resource_name" || true
        return 1
      }
      
      echo ""
      echo "🔍 Phase 1: Node readiness..."
      
      # Check that we have at least 1 node Ready
      READY_NODES=$(kubectl get nodes --no-headers | grep -c " Ready " || echo "0")
      TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l || echo "0")
      NOTREADY_NODES=$(kubectl get nodes --no-headers | grep -c " NotReady " || echo "0")
      
      echo "   Ready nodes: $READY_NODES/$TOTAL_NODES"
      echo "   NotReady nodes: $NOTREADY_NODES"
      
      # CRITICAL FIX: Require ALL nodes to be Ready (not just 1)
      if [[ "$READY_NODES" -eq 0 ]]; then
        echo "❌ No nodes are Ready"
        exit 1
      fi
      
      # NEW: Fail if there are any NotReady nodes
      if [[ "$NOTREADY_NODES" -gt 0 ]]; then
        echo "❌ Found $NOTREADY_NODES NotReady nodes - cluster is not stable"
        echo "📋 NotReady nodes:"
        kubectl get nodes --no-headers | grep " NotReady " || true
        echo ""
        echo "🔍 Node conditions for NotReady nodes:"
        kubectl get nodes --no-headers | grep " NotReady " | awk '{print $1}' | while read node; do
          echo "Node: $node"
          kubectl describe node "$node" | grep -A 10 "Conditions:" || true
          echo ""
        done
        exit 1
      fi
      
      # NEW: Verify minimum expected nodes (should match ASG desired capacity)
      EXPECTED_WORKERS=${var.desired_worker_nodes}
      ACTUAL_WORKERS=$(kubectl get nodes --no-headers | grep -v "control-plane" | wc -l)
      
      echo "   Expected workers: $EXPECTED_WORKERS, Actual workers: $ACTUAL_WORKERS"
      
      if [[ "$ACTUAL_WORKERS" -lt "$EXPECTED_WORKERS" ]]; then
        echo "⚠️ Warning: Expected $EXPECTED_WORKERS workers but found $ACTUAL_WORKERS"
        echo "   This may indicate nodes are still joining or have failed to join"
        
        # Give nodes time to join if we're significantly under
        if [[ "$ACTUAL_WORKERS" -lt $(($EXPECTED_WORKERS / 2)) ]]; then
          echo "❌ Too few worker nodes joined - waiting for more nodes..."
          exit 1
        fi
      fi
      
      echo ""
      echo "🔍 Phase 2: Core system components..."
      
      # Check CoreDNS
      echo "   Checking CoreDNS..."
      if ! wait_for_resource "deployment" "coredns" "kube-system" "120" "available"; then
        echo "❌ CoreDNS not ready"
        exit 1
      fi
      
      # Verify CoreDNS pods are actually running
      COREDNS_READY=$(kubectl -n kube-system get pods -l k8s-app=kube-dns --field-selector=status.phase=Running --no-headers | wc -l)
      if [[ "$COREDNS_READY" -eq 0 ]]; then
        echo "❌ No CoreDNS pods are running"
        kubectl -n kube-system get pods -l k8s-app=kube-dns -o wide
        exit 1
      fi
      
      echo "   ✅ CoreDNS: $COREDNS_READY pods running"
      
      # Check Calico controller
      echo "   Checking Calico controller..."
      if ! wait_for_resource "deployment" "calico-kube-controllers" "kube-system" "120" "available"; then
        echo "❌ Calico controller not ready"
        exit 1
      fi
      
      # Check Calico node DaemonSet
      echo "   Checking Calico node DaemonSet..."
      if ! wait_for_resource "daemonset" "calico-node" "kube-system" "120" "rollout"; then
        echo "❌ Calico node DaemonSet not ready"
        exit 1
      fi
      
      # Verify Calico pods distribution - ENHANCED
      CALICO_READY=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector=status.phase=Running --no-headers | wc -l)
      CALICO_TOTAL=$(kubectl -n kube-system get pods -l k8s-app=calico-node --no-headers | wc -l)
      
      echo "   Calico: $CALICO_READY/$CALICO_TOTAL node pods running"
      
      # CRITICAL: Ensure Calico pod is running on EVERY Ready node
      if [[ "$CALICO_READY" -lt "$READY_NODES" ]]; then
        echo "❌ Not all nodes have a running Calico pod!"
        echo "   Ready nodes: $READY_NODES, Calico pods: $CALICO_READY"
        
        # Show which nodes are missing Calico pods
        echo "🔍 Nodes and their Calico pod status:"
        kubectl get nodes --no-headers | while read node status role age version; do
          if [[ "$status" == "Ready" ]]; then
            CALICO_ON_NODE=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector spec.nodeName="$node" --no-headers | wc -l)
            if [[ "$CALICO_ON_NODE" -eq 0 ]]; then
              echo "   ❌ $node: NO Calico pod"
            else
              CALICO_STATUS=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector spec.nodeName="$node" -o jsonpath='{.items[0].status.phase}')
              echo "   ✅ $node: Calico pod ($CALICO_STATUS)"
            fi
          fi
        done
        exit 1
      fi
      
      # Verify no Calico pods are in bad states
      CALICO_PENDING=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector=status.phase=Pending --no-headers | wc -l)
      CALICO_FAILED=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector=status.phase=Failed --no-headers | wc -l)
      
      if [[ "$CALICO_PENDING" -gt 0 ]] || [[ "$CALICO_FAILED" -gt 0 ]]; then
        echo "❌ Found problematic Calico pods: $CALICO_PENDING pending, $CALICO_FAILED failed"
        kubectl -n kube-system get pods -l k8s-app=calico-node -o wide
        exit 1
      fi
      
      echo "   ✅ Calico: All $CALICO_READY node pods running and healthy"
      
      # Check EBS CSI Driver
      echo "   Checking EBS CSI controller..."
      if ! wait_for_resource "deployment" "ebs-csi-controller" "kube-system" "120" "available"; then
        echo "❌ EBS CSI controller not ready"
        exit 1
      fi
      
      # Check EBS CSI node DaemonSet
      echo "   Checking EBS CSI node DaemonSet..."
      if ! wait_for_resource "daemonset" "ebs-csi-node" "kube-system" "60" "rollout"; then
        echo "❌ EBS CSI node DaemonSet not ready"
        exit 1
      fi
      
      EBS_CONTROLLER_READY=$(kubectl -n kube-system get pods -l app=ebs-csi-controller --field-selector=status.phase=Running --no-headers | wc -l)
      EBS_NODE_READY=$(kubectl -n kube-system get pods -l app=ebs-csi-node --field-selector=status.phase=Running --no-headers | wc -l)
      echo "   ✅ EBS CSI: $EBS_CONTROLLER_READY controller pods, $EBS_NODE_READY node pods running"
      
      echo ""
      echo "🔍 Phase 3: Network connectivity test..."
      
      # Enhanced DNS and networking tests
      echo "   Testing cluster DNS resolution..."
      
      # Test 1: Basic cluster DNS (kubernetes service)
      if ! kubectl run dns-test-basic --image=busybox --rm -i --restart=Never --timeout=60s -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
        echo "❌ Basic cluster DNS resolution failed"
        echo "   Cannot resolve kubernetes.default.svc.cluster.local"
        
        # Try to diagnose DNS issues
        echo "🔍 Diagnosing DNS issues..."
        kubectl -n kube-system get pods -l k8s-app=kube-dns -o wide
        kubectl -n kube-system get svc kube-dns
        exit 1
      fi
      echo "   ✅ Basic cluster DNS working"
      
      # Test 2: CoreDNS service discovery
      if ! kubectl run dns-test-service --image=busybox --rm -i --restart=Never --timeout=60s -- nslookup kube-dns.kube-system.svc.cluster.local >/dev/null 2>&1; then
        echo "❌ Service discovery DNS failed"
        echo "   Cannot resolve kube-dns.kube-system.svc.cluster.local"
        exit 1
      fi
      echo "   ✅ Service discovery DNS working"
      
      # Test 3: External DNS (if possible)
      echo "   Testing external DNS resolution..."
      if kubectl run dns-test-external --image=busybox --rm -i --restart=Never --timeout=60s -- nslookup google.com >/dev/null 2>&1; then
        echo "   ✅ External DNS resolution working"
      else
        echo "   ⚠️ External DNS resolution failed (network policy may be blocking)"
      fi
      
      # Test 4: Pod-to-Pod communication across nodes (if we have multiple nodes)
      if [[ "$READY_NODES" -gt 1 ]]; then
        echo "   Testing pod-to-pod communication across nodes..."
        
        # Create a test pod on each node and try to communicate
        kubectl run network-test-server --image=nginx --restart=Never --port=80 --timeout=60s >/dev/null 2>&1 &
        sleep 5
        
        if kubectl run network-test-client --image=busybox --rm -i --restart=Never --timeout=60s -- wget -qO- network-test-server >/dev/null 2>&1; then
          echo "   ✅ Pod-to-pod communication working"
        else
          echo "   ⚠️ Pod-to-pod communication may have issues"
        fi
        
        # Cleanup
        kubectl delete pod network-test-server --ignore-not-found=true >/dev/null 2>&1 &
      fi
      
      echo ""
      echo "🔍 Phase 4: Final validation..."
      
      # Check for any crashlooping pods in system namespaces
      CRASH_PODS=$(kubectl get pods -n kube-system --field-selector=status.phase=Running -o json | \
        jq -r '.items[] | select(.status.containerStatuses[]?.restartCount > 5) | .metadata.name' 2>/dev/null || true)
      
      if [[ -n "$CRASH_PODS" ]]; then
        echo "   ⚠️ Found crash-looping pods: $CRASH_PODS"
      else
        echo "   ✅ No crash-looping pods detected"
      fi
      
      # Summary
      echo ""
      echo "✅ Cluster Readiness Check PASSED!"
      echo "   Nodes Ready: $READY_NODES/$TOTAL_NODES"
      echo "   CoreDNS: $COREDNS_READY pods"
      echo "   Calico: $CALICO_READY/$CALICO_TOTAL node pods"
      echo "   EBS CSI: $EBS_CONTROLLER_READY controller, $EBS_NODE_READY node pods"
      echo ""
      echo "🎉 Cluster is ready for application deployment!"
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

# STREAMLINED: Single robust ArgoCD installation
# Replaces: install_argocd (simplified), configure_argocd_repositories, check_argocd_status, argocd_direct_access
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [
    null_resource.cluster_readiness_check,  # Only depend on comprehensive readiness check
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
        kubectl -n argocd get pods
        exit 1
      fi
      
      # Wait for application controller
      if ! kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s; then
        echo "❌ ArgoCD application controller not ready"
        kubectl -n argocd get statefulset
        exit 1
      fi
      
      # Wait for server pods to be ready
      if ! kubectl -n argocd wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server --timeout=180s; then
        echo "❌ ArgoCD server pods not ready"
        kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-server
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
      
      echo "📦 Creating essential storage classes..."
      kubectl apply -f - <<'EOF' || echo "Storage class creation failed, but continuing"
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
---
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
EOF
      
      echo ""
      echo "✅ ArgoCD Installation Complete!"
      echo "📋 Access Information:"
      echo "   URL: https://localhost:8081 (requires port-forward)"
      echo "   Username: admin"
      echo "   Password: $(cat /tmp/argocd-admin-password.txt 2>/dev/null || echo 'Check /tmp/argocd-admin-password.txt')"
      echo ""
      echo "🔗 To access ArgoCD:"
      echo "   kubectl -n argocd port-forward svc/argocd-server 8081:443"
      echo ""
      echo "🎉 ArgoCD is ready for application deployment!"
    EOT
  }
}

# STREAMLINED: ArgoCD Application Creation  
# Replaces: configure_argocd_apps and create_argocd_app_simple
resource "null_resource" "configure_argocd_apps" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [
    null_resource.install_argocd,
    null_resource.deploy_secrets
  ]

  triggers = {
    argocd_install_id = null_resource.install_argocd[0].id
    secrets_ready_id = null_resource.deploy_secrets[0].id
    app_config_version = "streamlined-v3"  # Updated version to include secrets dependency
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "📱 Creating ArgoCD Application..."
      
      # Create polybot namespace
      kubectl create namespace polybot --dry-run=client -o yaml | kubectl apply -f -
      
      # Create ArgoCD Application using kubectl (simpler than CLI)
      kubectl apply -f - <<'EOF'
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
    path: k8s
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
      
      echo "✅ ArgoCD Application 'polybot' created successfully"
      
      # Verify application was created
      if kubectl -n argocd get application polybot >/dev/null 2>&1; then
        echo "✅ Application verified in ArgoCD"
      else
        echo "⚠️ Application may not be visible yet, but manifest was applied"
      fi
      
    EOT
  }
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

# CONSOLIDATED: Single robust node cleanup resource
# Replaces: cleanup_stale_nodes, remove_orphaned_nodes, emergency_cluster_cleanup
resource "null_resource" "cleanup_orphaned_nodes" {
  depends_on = [
    null_resource.cluster_readiness_check,
    terraform_data.kubectl_provider_config
  ]

  # Only run when there are actual issues - more selective triggering
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    # Use a more stable trigger that doesn't cause unnecessary runs
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
      
      # Phase 1: Identify orphaned nodes (nodes without backing EC2 instances)
      echo ""
      echo "🔍 Phase 1: Identifying orphaned nodes..."
      
      WORKER_NODES=$(kubectl get nodes --no-headers | grep -v "control-plane" | awk '{print $1}' || true)
      ORPHANED_NODES=()
      
      if [[ -z "$WORKER_NODES" ]]; then
        echo "ℹ️  No worker nodes found in cluster"
        exit 0
      fi
      
      echo "📋 Found worker nodes: $WORKER_NODES"
      
      # Get all EC2 instances from ASG (any state, not just running)
      EXISTING_INSTANCES=$(aws ec2 describe-instances \
        --region ${var.region} \
        --filters "Name=tag:aws:autoscaling:groupName,Values=guy-polybot-asg" \
        --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,PrivateIp:PrivateIpAddress}" \
        --output json 2>/dev/null)
      
      echo "📋 EC2 instances from ASG:"
      echo "$EXISTING_INSTANCES" | jq -c '.[][]' 2>/dev/null || echo "No instances found"
      
      # Check each worker node
      for NODE_NAME in $WORKER_NODES; do
        echo ""
        echo "🔍 Checking node: $NODE_NAME"
        
        # Get node status and age
        NODE_STATUS=$(kubectl get node "$NODE_NAME" --no-headers | awk '{print $2}' || echo "Unknown")
        NODE_READY=$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
        
        echo "   Status: $NODE_STATUS (Ready: $NODE_READY)"
        
        # Only consider removing NotReady nodes
        if [[ "$NODE_STATUS" == "NotReady" ]] || [[ "$NODE_READY" != "True" ]]; then
          echo "   ⚠️  Node is NotReady, checking for backing instance..."
          
          INSTANCE_FOUND=false
          
          # Method 1: Extract instance ID from node name pattern
          if [[ "$NODE_NAME" =~ worker-([a-f0-9]{17})$ ]]; then
            POTENTIAL_INSTANCE_ID="i-$${BASH_REMATCH[1]}"
            echo "     Checking extracted instance ID: $POTENTIAL_INSTANCE_ID"
            
            MATCHING_INSTANCE=$(echo "$EXISTING_INSTANCES" | jq -r --arg id "$POTENTIAL_INSTANCE_ID" \
              '.[][] | select(.InstanceId == $id) | .InstanceId' 2>/dev/null)
            
            if [[ -n "$MATCHING_INSTANCE" ]]; then
              INSTANCE_STATE=$(echo "$EXISTING_INSTANCES" | jq -r --arg id "$POTENTIAL_INSTANCE_ID" \
                '.[][] | select(.InstanceId == $id) | .State' 2>/dev/null)
              echo "     ✅ Found backing instance: $MATCHING_INSTANCE (State: $INSTANCE_STATE)"
              INSTANCE_FOUND=true
            fi
          fi
          
          # Method 2: Check by private IP if instance ID method failed
          if [[ "$INSTANCE_FOUND" == false ]]; then
            NODE_PRIVATE_IP=$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo "unknown")
            if [[ "$NODE_PRIVATE_IP" != "unknown" ]]; then
              echo "     Checking by private IP: $NODE_PRIVATE_IP"
              
              MATCHING_INSTANCE=$(echo "$EXISTING_INSTANCES" | jq -r --arg ip "$NODE_PRIVATE_IP" \
                '.[][] | select(.PrivateIp == $ip) | .InstanceId' 2>/dev/null)
              
              if [[ -n "$MATCHING_INSTANCE" ]]; then
                INSTANCE_STATE=$(echo "$EXISTING_INSTANCES" | jq -r --arg ip "$NODE_PRIVATE_IP" \
                  '.[][] | select(.PrivateIp == $ip) | .State' 2>/dev/null)
                echo "     ✅ Found backing instance by IP: $MATCHING_INSTANCE (State: $INSTANCE_STATE)"
                INSTANCE_FOUND=true
              fi
            fi
          fi
          
          # If no backing instance found, mark for removal
          if [[ "$INSTANCE_FOUND" == false ]]; then
            echo "     ❌ No backing EC2 instance found - marking for removal"
            ORPHANED_NODES+=("$NODE_NAME")
          fi
        else
          echo "   ✅ Node is healthy (Ready)"
        fi
      done
      
      # Phase 2: Clean up identified orphaned nodes
      if [[ $${#ORPHANED_NODES[@]} -gt 0 ]]; then
        echo ""
        echo "🗑️  Phase 2: Removing $${#ORPHANED_NODES[@]} orphaned nodes..."
        
        for NODE_NAME in "$${ORPHANED_NODES[@]}"; do
          echo ""
          echo "🗑️  Cleaning up orphaned node: $NODE_NAME"
          
          # Force delete terminating pods first
          echo "     Cleaning terminating pods..."
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" -o json 2>/dev/null | \
            jq -r '.items[] | select(.metadata.deletionTimestamp != null) | "\(.metadata.namespace) \(.metadata.name)"' | \
            while read -r namespace podname; do
              if [[ -n "$namespace" ]] && [[ -n "$podname" ]]; then
                echo "       Force deleting terminating pod: $namespace/$podname"
                kubectl delete pod "$podname" -n "$namespace" --force --grace-period=0 --timeout=10s || true
              fi
            done
          
          # Force delete all remaining pods on the node
          echo "     Force deleting all remaining pods..."
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" --no-headers 2>/dev/null | \
            while read -r namespace podname rest; do
              if [[ -n "$namespace" ]] && [[ -n "$podname" ]]; then
                echo "       Force deleting pod: $namespace/$podname"
                kubectl delete pod "$podname" -n "$namespace" --force --grace-period=0 --timeout=10s || true
              fi
            done
          
          
          # Remove the node from cluster
          echo "     Removing node from cluster..."
          if kubectl delete node "$NODE_NAME" --timeout=30s; then
            echo "     ✅ Successfully removed orphaned node: $NODE_NAME"
          else
            echo "     ⚠️  Standard delete failed, trying force delete..."
            kubectl delete node "$NODE_NAME" --force --grace-period=0 || true
          fi
        done
        
        echo ""
        echo "✅ Orphaned node cleanup completed! Removed $${#ORPHANED_NODES[@]} nodes."
      else
        echo ""
        echo "✅ No orphaned nodes found - all worker nodes have backing instances"
      fi
      
      # Phase 3: Clean up general problematic pods (not tied to specific nodes)
      echo ""
      echo "🧹 Phase 3: General pod cleanup..."
      
      # Clean up completed pods
      echo "   Removing completed pods..."
      kubectl get pods --all-namespaces --field-selector=status.phase=Succeeded -o name 2>/dev/null | \
        head -10 | xargs -r kubectl delete --timeout=15s 2>/dev/null || true
      
      # Clean up failed pods
      echo "   Removing failed pods..."
      kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o name 2>/dev/null | \
        head -10 | xargs -r kubectl delete --timeout=15s 2>/dev/null || true
      
      echo ""
      echo "📋 Final cluster state:"
      kubectl get nodes -o wide
      
      echo ""
      echo "✅ Consolidated node cleanup completed successfully!"
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

# Install ArgoCD applications
resource "null_resource" "install_argocd_apps" {
  count = local.skip_argocd ? 0 : 1
  triggers = {
    argocd_ready = null_resource.install_argocd[0].id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      if [ -f "${local.kubeconfig_path}" ]; then
        echo "$(date): Installing ArgoCD applications..." | tee -a ${local.debug_log}
        
        # Apply the polybot application
        KUBECONFIG="${local.kubeconfig_path}" kubectl apply -f - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: polybot
  namespace: argocd
spec:
  project: default
  source:
    repoURL: 'https://github.com/gmeltzer/PolybotService.git'
    path: k8s
    targetRevision: HEAD
  destination:
    server: 'https://kubernetes.default.svc'
    namespace: prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
EOF
        
        echo "$(date): ArgoCD applications installed successfully" | tee -a ${local.debug_log}
        echo '{"timestamp":"'$(date -Iseconds)'","component":"argocd_apps","status":"success","message":"ArgoCD applications installed"}' >> ${local.debug_log}
      else
        echo "$(date): Error: Kubeconfig not found at ${local.kubeconfig_path}" | tee -a ${local.debug_log}
        echo '{"timestamp":"'$(date -Iseconds)'","component":"argocd_apps","status":"error","message":"Kubeconfig not found"}' >> ${local.debug_log}
      fi
    EOT
  }
  depends_on = [null_resource.install_argocd]
}

# Process and deploy secrets before ArgoCD applications
resource "null_resource" "deploy_secrets" {
  count = local.skip_argocd ? 0 : 1

  depends_on = [
    null_resource.install_argocd,
    null_resource.cluster_readiness_check,
    aws_s3_bucket.polybot_storage,
    aws_sqs_queue.polybot_queue
  ]

  triggers = {
    argocd_install_id = null_resource.install_argocd[0].id
    # Trigger when generated resources change
    secrets_hash = md5(join("", [
      local.generated_secrets.telegram_token,
      local.generated_secrets.sqs_queue_url,
      local.generated_secrets.s3_bucket_name,
      local.generated_secrets.telegram_app_url,
      local.generated_secrets.mongo_uri,
      local.generated_secrets.polybot_url
    ]))
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔐 Processing and deploying secrets..."
      
      # Check if kubectl can connect
      if ! kubectl get nodes >/dev/null 2>&1; then
        echo "❌ Cannot connect to cluster"
        exit 1
      fi
      
      # Create prod namespace
      kubectl create namespace prod --dry-run=client -o yaml | kubectl apply -f -
      
      # Process polybot-secrets with actual values
      echo "📝 Creating polybot-secrets..."
      kubectl apply -f - <<'POLYBOT_EOF'
apiVersion: v1
kind: Secret
metadata:
  name: polybot-secrets
  namespace: prod
type: Opaque
stringData:
  telegram_token: "${local.generated_secrets.telegram_token}"
  sqs_queue_url: "${local.generated_secrets.sqs_queue_url}"
  s3_bucket_name: "${local.generated_secrets.s3_bucket_name}"
  telegram_app_url: "${local.generated_secrets.telegram_app_url}"
  aws_access_key_id: "${local.generated_secrets.aws_access_key_id}"
  aws_secret_access_key: "${local.generated_secrets.aws_secret_access_key}"
  mongo_collection: "${local.generated_secrets.mongo_collection}"
  mongo_db: "${local.generated_secrets.mongo_db}"
  mongo_uri: "${local.generated_secrets.mongo_uri}"
  polybot_url: "${local.generated_secrets.polybot_url}"
POLYBOT_EOF
      
      # Deploy TLS secret
      echo "📝 Creating polybot-tls secret..."
      kubectl apply -f ../k8s/shared/polybot-tls-secret.yaml
      
      # Deploy CA secret  
      echo "📝 Creating polybot-ca secret..."
      kubectl apply -f ../k8s/shared/polybot-ca-secret.yaml
      
      # Process docker registry secret with actual values
      echo "📝 Creating docker-registry-credentials..."
      DOCKER_AUTH=$(echo -n "${local.generated_secrets.docker_username}:${local.generated_secrets.docker_password}" | base64 -w 0)
      kubectl apply -f - <<DOCKER_EOF
apiVersion: v1
kind: Secret
metadata:
  name: docker-registry-credentials
  namespace: prod
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {
      "auths": {
        "https://index.docker.io/v1/": {
          "username": "${local.generated_secrets.docker_username}",
          "password": "${local.generated_secrets.docker_password}",
          "auth": "$DOCKER_AUTH"
        }
      }
    }
DOCKER_EOF
      
      echo "✅ All secrets deployed successfully!"
      
      # Verify secrets exist
      echo "🔍 Verifying secrets..."
      kubectl get secrets -n prod | grep -E "(polybot-secrets|polybot-tls|polybot-ca|docker-registry-credentials)" || {
        echo "❌ Some secrets are missing!"
        exit 1
      }
      
      echo "✅ Secret verification complete!"
    EOT
  }
}

# =============================================================================
# NODE DIAGNOSTICS AND MONITORING RESOURCES
# =============================================================================

# Diagnostic resource for NotReady worker nodes
# This creates a comprehensive diagnostic report for troubleshooting node issues
resource "null_resource" "diagnose_notready_nodes" {
  count = 0  # Set to 1 to enable diagnostics when needed

  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔍 Diagnosing NotReady Worker Nodes..."
      echo "====================================="
      
      # Create diagnostics directory
      mkdir -p logs/node-diagnostics
      
      # Get current cluster state
      echo "📋 Current cluster state:"
      kubectl get nodes -o wide | tee logs/node-diagnostics/cluster-nodes.txt
      
      # Identify NotReady nodes
      NOTREADY_NODES=$(kubectl get nodes --no-headers | grep "NotReady" | awk '{print $1}' || true)
      
      if [[ -z "$NOTREADY_NODES" ]]; then
        echo "✅ No NotReady nodes found!"
        exit 0
      fi
      
      echo ""
      echo "🚨 Found NotReady nodes: $NOTREADY_NODES"
      echo ""
      
      # Diagnose each NotReady node
      for NODE in $NOTREADY_NODES; do
        echo "🔍 Diagnosing node: $NODE"
        echo "================================="
        
        # Get node details
        echo "Node description:" | tee logs/node-diagnostics/$NODE-describe.txt
        kubectl describe node "$NODE" | tee -a logs/node-diagnostics/$NODE-describe.txt
        
        # Get node conditions
        echo "Node conditions:" | tee logs/node-diagnostics/$NODE-conditions.txt
        kubectl get node "$NODE" -o jsonpath='{.status.conditions[*]}' | jq '.' | tee -a logs/node-diagnostics/$NODE-conditions.txt
        
        # Get pods on this node
        echo "Pods on $NODE:" | tee logs/node-diagnostics/$NODE-pods.txt
        kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE" -o wide | tee -a logs/node-diagnostics/$NODE-pods.txt
        
        # Check Calico pod specifically
        echo "Calico pod on $NODE:" | tee logs/node-diagnostics/$NODE-calico.txt
        kubectl get pods -n kube-system -l k8s-app=calico-node --field-selector spec.nodeName="$NODE" -o wide | tee -a logs/node-diagnostics/$NODE-calico.txt
        
        # Get private IP for SSH diagnostics
        PRIVATE_IP=$(kubectl get node "$NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
        echo "Node private IP: $PRIVATE_IP"
        
        # Try to get EC2 instance ID from node name
        if [[ "$NODE" =~ worker-([a-f0-9]{17})$ ]]; then
          INSTANCE_ID="i-$${BASH_REMATCH[1]}"
          echo "Extracted instance ID: $INSTANCE_ID"
          
          # Get instance details
          echo "EC2 instance details:" | tee logs/node-diagnostics/$NODE-ec2.txt
          aws ec2 describe-instances --region ${var.region} --instance-ids "$INSTANCE_ID" --output json | tee -a logs/node-diagnostics/$NODE-ec2.txt
          
          # Get instance state
          INSTANCE_STATE=$(aws ec2 describe-instances --region ${var.region} --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name' --output text)
          echo "EC2 instance state: $INSTANCE_STATE"
          
          if [[ "$INSTANCE_STATE" == "running" ]]; then
            echo "✅ EC2 instance is running - issue is likely with kubelet/CRI-O"
            
            # Generate SSH diagnostic commands
            cat > logs/node-diagnostics/$NODE-ssh-commands.sh << SSH_EOF
#!/bin/bash
# SSH diagnostic commands for $NODE ($INSTANCE_ID)
# Run these commands manually: ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@PUBLIC_IP

echo "=== Kubelet Status ==="
sudo systemctl status kubelet

echo "=== Kubelet Logs (last 50 lines) ==="
sudo journalctl -u kubelet -n 50 --no-pager

echo "=== CRI-O Status ==="
sudo systemctl status crio

echo "=== CRI-O Logs (last 50 lines) ==="
sudo journalctl -u crio -n 50 --no-pager

echo "=== Container Runtime Info ==="
sudo crictl info

echo "=== Node Network Configuration ==="
ip addr show
ip route show

echo "=== DNS Resolution Test ==="
nslookup kubernetes.default.svc.cluster.local

echo "=== CNI Configuration ==="
ls -la /etc/cni/net.d/
cat /etc/cni/net.d/* 2>/dev/null || echo "No CNI config found"

echo "=== Kubelet Config ==="
sudo cat /var/lib/kubelet/config.yaml

echo "=== Node Join Status ==="
sudo cat /var/log/k8s-worker-init.log 2>/dev/null || echo "No worker init log found"

echo "=== Disk Usage ==="
df -h

echo "=== Memory Usage ==="
free -h

echo "=== System Load ==="
uptime

echo "=== Check if node can reach control plane ==="
curl -k https://${module.k8s-cluster.control_plane_public_ip}:6443/healthz || echo "Cannot reach control plane"
SSH_EOF
            
            chmod +x logs/node-diagnostics/$NODE-ssh-commands.sh
            echo "📝 Generated SSH diagnostic script: logs/node-diagnostics/$NODE-ssh-commands.sh"
            
          else
            echo "❌ EC2 instance is not running (state: $INSTANCE_STATE) - this node should be removed"
          fi
        else
          echo "⚠️ Could not extract instance ID from node name: $NODE"
        fi
        
        echo ""
      done
      
      # Generate summary report
      cat > logs/node-diagnostics/SUMMARY.md << SUMMARY_EOF
# NotReady Nodes Diagnostic Summary

## NotReady Nodes Found:
$NOTREADY_NODES

## Next Steps:

1. **For each NotReady node, check the generated files:**
   - \`\$NODE-describe.txt\` - Full node description
   - \`\$NODE-conditions.txt\` - Node status conditions  
   - \`\$NODE-pods.txt\` - Pods scheduled on the node
   - \`\$NODE-calico.txt\` - Calico pod status
   - \`\$NODE-ec2.txt\` - EC2 instance details
   - \`\$NODE-ssh-commands.sh\` - SSH diagnostic script

2. **Run SSH diagnostics on problematic nodes:**
   \`\`\`bash
   # Get the public IP from EC2 console or:
   aws ec2 describe-instances --region ${var.region} --instance-ids INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text
   
   # Then SSH and run:
   ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@PUBLIC_IP
   # Run the commands from the \$NODE-ssh-commands.sh file
   \`\`\`

3. **Common issues to check:**
   - Kubelet not running or failing to start
   - CRI-O not running or misconfigured
   - Network connectivity issues to control plane
   - CNI (Calico) configuration problems
   - Disk space or memory issues
   - Join token expired or invalid

## Generated: $(date)
SUMMARY_EOF
      
      echo ""
      echo "✅ Diagnostic complete! Check logs/node-diagnostics/ for detailed reports"
      echo "📋 Summary: logs/node-diagnostics/SUMMARY.md"
      echo ""
    EOT
  }

  depends_on = [
    module.k8s-cluster,
    terraform_data.kubectl_provider_config
  ]
}

# Node Health Monitoring and Remediation
# This resource monitors worker node health and can remediate issues
resource "null_resource" "node_health_monitor" {
  count = 0  # Set to 1 to enable monitoring

  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
    check_interval = timestamp()  # Run periodically
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      set -e
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "🔍 Node Health Monitoring Check..."
      echo "================================="
      
      # Create monitoring logs directory
      mkdir -p logs/node-health
      
      # Check if kubectl can connect
      if ! kubectl get nodes &>/dev/null; then
        echo "❌ Cannot connect to cluster"
        exit 1
      fi
      
      # Get current time for logging
      TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
      
      # Check all nodes
      echo "📋 Current node status:"
      kubectl get nodes -o wide | tee logs/node-health/nodes-$$(date +%Y%m%d-%H%M%S).txt
      
      # Identify problematic nodes
      NOTREADY_NODES=$(kubectl get nodes --no-headers | grep "NotReady" | awk '{print $1}' || true)
      READY_NODES=$(kubectl get nodes --no-headers | grep " Ready " | awk '{print $1}' || true)
      
      # Log status
      cat > logs/node-health/status-$$(date +%Y%m%d-%H%M%S).txt << STATUS_EOF
Timestamp: $TIMESTAMP
Ready Nodes: $(echo "$READY_NODES" | wc -w)
NotReady Nodes: $(echo "$NOTREADY_NODES" | wc -w)

Ready Nodes List:
$READY_NODES

NotReady Nodes List:
$NOTREADY_NODES
STATUS_EOF
      
      if [[ -z "$NOTREADY_NODES" ]]; then
        echo "✅ All nodes are healthy!"
        
        # Check for any nodes that have been NotReady recently
        RECENTLY_READY=$(kubectl get nodes -o json | jq -r '.items[] | select(.status.conditions[] | select(.type=="Ready" and .status=="True" and (.lastTransitionTime | fromdateiso8601) > (now - 3600))) | .metadata.name' 2>/dev/null || true)
        
        if [[ -n "$RECENTLY_READY" ]]; then
          echo "ℹ️ Nodes that became Ready in the last hour:"
          echo "$RECENTLY_READY"
        fi
        
        exit 0
      fi
      
      echo ""
      echo "🚨 Found unhealthy nodes!"
      echo "========================"
      
      # Analyze each NotReady node
      for NODE in $NOTREADY_NODES; do
        echo ""
        echo "🔍 Analyzing node: $NODE"
        echo "----------------------------"
        
        # Get node conditions
        NODE_CONDITIONS=$(kubectl get node "$NODE" -o json | jq -r '.status.conditions[] | select(.type=="Ready") | .message' 2>/dev/null || echo "Unknown")
        echo "Node condition message: $NODE_CONDITIONS"
        
        # Check how long it's been NotReady
        LAST_TRANSITION=$(kubectl get node "$NODE" -o json | jq -r '.status.conditions[] | select(.type=="Ready") | .lastTransitionTime' 2>/dev/null || echo "Unknown")
        echo "Last transition time: $LAST_TRANSITION"
        
        # Get EC2 instance details
        if [[ "$NODE" =~ worker-([a-f0-9]{17})$ ]]; then
          INSTANCE_ID="i-$${BASH_REMATCH[1]}"
          echo "Instance ID: $INSTANCE_ID"
          
          # Check EC2 instance state
          INSTANCE_STATE=$(aws ec2 describe-instances --region ${var.region} --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo "unknown")
          echo "EC2 instance state: $INSTANCE_STATE"
          
          case "$INSTANCE_STATE" in
            "running")
              echo "   ✅ EC2 instance is running - kubelet/network issue likely"
              
              # Check if we can get logs from the instance
              PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || echo "none")
              
              if [[ "$PUBLIC_IP" != "none" && "$PUBLIC_IP" != "null" ]]; then
                echo "   Instance public IP: $PUBLIC_IP"
                
                # Create remediation script
                cat > logs/node-health/remediate-$NODE.sh << REMEDIATE_EOF
#!/bin/bash
# Remediation script for $NODE ($INSTANCE_ID)
# Public IP: $PUBLIC_IP

echo "🔧 Attempting to remediate node $NODE..."

# SSH and try to restart services
if ssh -i ${module.k8s-cluster.ssh_key_name}.pem -o ConnectTimeout=10 -o StrictHostKeyChecking=no ubuntu@$PUBLIC_IP << 'SSH_COMMANDS'
echo "=== Checking kubelet status ==="
sudo systemctl status kubelet

echo "=== Checking CRI-O status ==="
sudo systemctl status crio

echo "=== Recent kubelet logs ==="
sudo journalctl -u kubelet -n 20 --no-pager

echo "=== Restarting kubelet ==="
sudo systemctl restart kubelet

echo "=== Waiting for kubelet to start ==="
sleep 10
sudo systemctl status kubelet

echo "=== Checking if node is now Ready ==="
sudo kubectl --kubeconfig=/etc/kubernetes/kubelet.conf get nodes $NODE
SSH_COMMANDS
then
  echo "✅ Successfully connected and attempted remediation"
  echo "⏳ Wait 2-3 minutes and check if node becomes Ready"
else
  echo "❌ Failed to connect via SSH - instance may need replacement"
  echo "💡 Consider: aws ec2 terminate-instances --instance-ids $INSTANCE_ID"
  echo "💡 ASG will automatically launch a replacement"
fi
REMEDIATE_EOF
                
                chmod +x logs/node-health/remediate-$NODE.sh
                echo "   📝 Created remediation script: logs/node-health/remediate-$NODE.sh"
                
              else
                echo "   ❌ No public IP available for SSH access"
              fi
              ;;
              
            "stopped"|"stopping"|"terminated"|"terminating")
              echo "   ❌ EC2 instance is $INSTANCE_STATE - should be removed from cluster"
              
              # Create cleanup script
              cat > logs/node-health/cleanup-$NODE.sh << CLEANUP_EOF
#!/bin/bash
# Cleanup script for dead node $NODE ($INSTANCE_ID)

echo "🧹 Cleaning up dead node $NODE..."

# Remove the node from Kubernetes
kubectl delete node "$NODE" --ignore-not-found=true

echo "✅ Node $NODE removed from cluster"
echo "💡 ASG should automatically launch a replacement instance"
CLEANUP_EOF
              
              chmod +x logs/node-health/cleanup-$NODE.sh
              echo "   📝 Created cleanup script: logs/node-health/cleanup-$NODE.sh"
              ;;
              
            *)
              echo "   ⚠️ Instance in unknown state: $INSTANCE_STATE"
              ;;
          esac
          
        else
          echo "   ⚠️ Could not extract instance ID from node name"
        fi
        
        # Check pods stuck on this node
        STUCK_PODS=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE" --no-headers | wc -l)
        if [[ "$STUCK_PODS" -gt 0 ]]; then
          echo "   ⚠️ $STUCK_PODS pods are stuck on this NotReady node"
          kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE" -o wide | head -10
        fi
      done
      
      # Generate summary report
      cat > logs/node-health/SUMMARY-$$(date +%Y%m%d-%H%M%S).md << SUMMARY_EOF
# Node Health Check Summary

**Timestamp:** $TIMESTAMP
**Ready Nodes:** $(echo "$READY_NODES" | wc -w)
**NotReady Nodes:** $(echo "$NOTREADY_NODES" | wc -w)

## NotReady Nodes:
$NOTREADY_NODES

## Recommended Actions:

1. **Review generated remediation scripts** in logs/node-health/
2. **For running instances with kubelet issues:** Run remediate-\$NODE.sh
3. **For dead instances:** Run cleanup-\$NODE.sh 
4. **Monitor cluster:** Wait 5-10 minutes after remediation

## Auto-remediation Options:

To enable automatic remediation, you can:
- Set count = 1 for node_health_monitor in main.tf
- Enable auto-cleanup of dead nodes
- Enable auto-restart of problematic services

## Monitoring Commands:

\`\`\`bash
# Watch nodes continuously
watch kubectl get nodes

# Check specific node details
kubectl describe node NODE_NAME

# Check pods on problematic nodes  
kubectl get pods --all-namespaces --field-selector spec.nodeName=NODE_NAME
\`\`\`

## Next Health Check:
Run: terraform apply -target=null_resource.node_health_monitor
SUMMARY_EOF
      
      echo ""
      echo "📋 Health check summary: logs/node-health/SUMMARY-$$(date +%Y%m%d-%H%M%S).md"
      echo "🔧 Remediation scripts created in logs/node-health/"
      echo ""
      
      # Return exit code based on health
      if [[ -n "$NOTREADY_NODES" ]]; then
        echo "❌ Cluster has unhealthy nodes - manual intervention may be required"
        exit 1
      else
        echo "✅ All nodes are healthy"
        exit 0
      fi
    EOT
  }

  depends_on = [
    module.k8s-cluster,
    terraform_data.kubectl_provider_config
  ]
}
