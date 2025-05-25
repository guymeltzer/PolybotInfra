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
  region                        = var.region
  cluster_name                 = "guy-cluster"  # Fixed cluster name
  vpc_id                       = var.vpc_id
  subnet_ids                   = var.subnet_ids
  route53_zone_id              = var.route53_zone_id
  key_name                     = var.key_name
  control_plane_ami            = var.control_plane_ami
  worker_ami                   = var.worker_ami
  control_plane_instance_type  = var.control_plane_instance_type
  worker_instance_type         = var.instance_type
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

# Install ArgoCD only if not already installed
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1
  
  # Remove dependencies that create circular references
  # depends_on = [
  #   null_resource.create_namespaces,
  #   null_resource.providers_ready,
  #   null_resource.check_argocd_status,
  #   null_resource.install_ebs_csi_driver
  # ]
  
  # Only run when needed based on whether ArgoCD is already installed
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    ebs_driver_id = null_resource.install_ebs_csi_driver.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Creating Kubernetes storage classes..."
      
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Check if kubectl can connect to the cluster
      if ! kubectl get nodes &>/dev/null; then
        echo "Cannot connect to Kubernetes cluster, skipping storage class creation"
        exit 0
      fi
      
      # Wait for the EBS CSI driver to be ready
      echo "Waiting for EBS CSI driver pods to be ready..."
      kubectl -n kube-system wait --for=condition=ready pod -l app=ebs-csi-controller --timeout=120s || {
        echo "Warning: EBS CSI driver pods not ready within timeout, but continuing anyway"
      }
      
      # Create general purpose SSD storage class
      echo "Creating gp2 storage class..."
      kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp2
  encrypted: "true"
allowVolumeExpansion: true
EOF
      
      # Create MongoDB storage class
      echo "Creating MongoDB storage class..."
      kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: mongodb-sc
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp2
  encrypted: "true"
allowVolumeExpansion: true
EOF
      
      echo "Storage classes created successfully"
    EOT
  }
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
      KUBECONFIG="${local.kubeconfig_path}" argocd app create polybot \
        --repo https://github.com/your-org/polybot-repo.git \
        --path manifests \
        --dest-server https://kubernetes.default.svc \
        --dest-namespace polybot
      KUBECONFIG="${local.kubeconfig_path}" argocd app sync polybot
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
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      KUBECONFIG="${local.kubeconfig_path}" kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
    EOT
  }
  depends_on = [
    null_resource.wait_for_kubernetes,
    module.k8s-cluster
  ]
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
      KUBECONFIG="${local.kubeconfig_path}" argocd repo add https://github.com/your-org/polybot-repo.git --name polybot-repo
    EOT
  }
  depends_on = [
    null_resource.install_argocd,
    null_resource.argocd_password_retriever,
    module.k8s-cluster
  ]
}

# Add this resource after the null_resource.fix_argocd_connectivity resource
resource "null_resource" "cleanup_worker_nodes" {
  # Skip this resource since it's duplicated in the kubernetes_resources module
  count = 0  # Set to 0 to disable as we're using the module version instead

  # Remove dependency on fix_argocd_connectivity
  depends_on = [null_resource.install_ebs_csi_driver]

  provisioner "local-exec" {
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="./kubeconfig.yaml"
      
      echo "Cleaning up evicted pods..."
      kubectl get pods --all-namespaces | grep Evicted | awk '{print $2 " --namespace=" $1}' | xargs -L1 kubectl delete pod || true
      
      echo "Setting up node disk cleanup job..."
      cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: node-cleanup
  namespace: kube-system
spec:
  schedule: "0 */6 * * *"  # Run every 6 hours
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          tolerations:
          - key: node-role.kubernetes.io/master
            effect: NoSchedule
          - key: node-role.kubernetes.io/control-plane
            effect: NoSchedule
          containers:
          - name: cleanup
            image: ubuntu:20.04
            resources:
              requests:
                memory: "128Mi"
                cpu: "100m"
              limits:
                memory: "256Mi"
                cpu: "200m"
            command:
            - /bin/sh
            - -c
            - |
              apt-get update && apt-get install -y docker.io
              echo "Cleaning up Docker system..."
              docker system prune -af
              echo "Clearing logs..."
              find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
              echo "Clearing journal logs..."
              journalctl --vacuum-time=1d
              echo "Clearing temp files..."
              rm -rf /tmp/*
              echo "Node cleanup completed"
            securityContext:
              privileged: true
            volumeMounts:
            - name: var-log
              mountPath: /var/log
            - name: var-lib-docker
              mountPath: /var/lib/docker
            - name: run
              mountPath: /run
            - name: tmp 
              mountPath: /tmp
          volumes:
          - name: var-log
            hostPath:
              path: /var/log
          - name: var-lib-docker
            hostPath:
              path: /var/lib/docker
          - name: run
            hostPath:
              path: /run
          - name: tmp
            hostPath:
              path: /tmp
          restartPolicy: OnFailure
          hostNetwork: true
          hostPID: true
EOF
      
      # Execute a disk cleanup job immediately - fix find command syntax
      echo "Running immediate disk cleanup on worker nodes..."
      cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: disk-cleanup-now
  namespace: kube-system
spec:
  ttlSecondsAfterFinished: 100
  activeDeadlineSeconds: 300  # Add 5-minute timeout to prevent job from hanging
  template:
    spec:
      tolerations:
      - operator: Exists
      containers:
      - name: cleanup
        image: ubuntu:20.04
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        command:
        - /bin/sh
        - -c
        - |
          apt-get update && apt-get install -y docker.io
          echo "Emergency cleanup - freeing disk space..."
          docker system prune -af
          find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
          find /var/log -type f -size +10M -delete
          journalctl --vacuum-time=1d
          rm -rf /tmp/*
          echo "Emergency cleanup completed"
        securityContext:
          privileged: true
        volumeMounts:
        - name: var-log
          mountPath: /var/log
        - name: var-lib-docker
          mountPath: /var/lib/docker
        - name: run
          mountPath: /run
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: var-log
        hostPath:
          path: /var/log
      - name: var-lib-docker
        hostPath:
          path: /var/lib/docker
      - name: run
        hostPath:
          path: /run
      - name: tmp
        hostPath:
          path: /tmp
      restartPolicy: Never
      hostNetwork: true
      hostPID: true
EOF
      
      # Increase timeout for cleanup job
      echo "Waiting for emergency disk cleanup to complete (max 3 minutes)..."
      kubectl -n kube-system wait --for=condition=complete job/disk-cleanup-now --timeout=180s || true
      
      # Force continue even if job hasn't completed
      echo "Continuing deployment whether cleanup is done or not..."
      kubectl get nodes
      
      echo "Cleanup job created successfully."
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
      KUBECONFIG="${local.kubeconfig_path}" kubectl apply -f ${path.module}/manifests/mongodb-deployment.yaml
    EOT
  }
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.install_ebs_csi_driver,
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
    terraform_data.kubectl_provider_config
  ]
  
  # Trigger reinstall when the role check is run
  triggers = {
    ebs_role_check = null_resource.check_ebs_role.id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Installing AWS EBS CSI Driver..."
      
      # Use kubectl directly since it's already set up
      export KUBECONFIG=${local.kubeconfig_path}
      
      # Create required namespace
      kubectl create namespace kube-system --dry-run=client -o yaml | kubectl apply -f -
      
      # Install the EBS CSI driver using the official YAML
      kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.19"
      
      echo "Waiting for EBS CSI driver pods to start..."
      kubectl -n kube-system wait --for=condition=ready pod -l app=ebs-csi-controller --timeout=120s || true
      
      echo "EBS CSI Driver installation complete"
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

