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
      
      echo "   Ready nodes: $READY_NODES/$TOTAL_NODES"
      
      if [[ "$READY_NODES" -eq 0 ]]; then
        echo "❌ No nodes are Ready"
        exit 1
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
      
      # Verify Calico pods distribution
      CALICO_READY=$(kubectl -n kube-system get pods -l k8s-app=calico-node --field-selector=status.phase=Running --no-headers | wc -l)
      echo "   ✅ Calico: $CALICO_READY node pods running"
      
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
      
      # Test DNS resolution
      echo "   Testing DNS resolution..."
      if kubectl run dns-test --image=busybox --rm -i --restart=Never --timeout=60s -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
        echo "   ✅ DNS resolution working"
      else
        echo "   ⚠️ DNS resolution test failed, but continuing..."
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
      echo "   Calico: $CALICO_READY node pods"
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
    null_resource.install_argocd
  ]
  
  triggers = {
    argocd_install_id = null_resource.install_argocd[0].id
    app_config_version = "streamlined-v1"
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
