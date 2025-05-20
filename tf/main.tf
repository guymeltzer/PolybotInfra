provider "aws" {
  region = var.region
}

# Define a local provider for first-time setup
provider "local" {}

# Create a bootstrap kubeconfig file for Kubernetes provider initialization
resource "local_file" "bootstrap_kubeconfig" {
  count    = fileexists("${path.module}/kubeconfig.yml") ? 0 : 1
  filename = "${path.module}/kubeconfig.yml"
  content  = <<-EOT
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://placeholder:6443
    insecure-skip-tls-verify: true
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
    client-certificate-data: cGxhY2Vob2xkZXI=
    client-key-data: cGxhY2Vob2xkZXI=
EOT

  # Only create this file if it doesn't already exist
  lifecycle {
    prevent_destroy = false
  }
}

# Configure the Kubernetes provider with proper authentication
provider "kubernetes" {
  config_path    = "${path.module}/kubeconfig.yml"
  config_context = "kubernetes-admin@kubernetes"  # This is the default context name with kubeadm
  insecure       = true  # Allow connections to the API server without verifying the TLS certificate
}

# Configure the Helm provider with proper authentication
provider "helm" {
  kubernetes {
    config_path    = "${path.module}/kubeconfig.yml"
    config_context = "kubernetes-admin@kubernetes"
    insecure       = true
  }
}

# Configure the kubectl provider with proper authentication
provider "kubectl" {
  config_path      = "${path.module}/kubeconfig.yml"
  config_context   = "kubernetes-admin@kubernetes"
  load_config_file = true
  insecure         = true
}

# Create Kubernetes namespaces for dev and prod
resource "kubernetes_namespace" "dev" {
  metadata {
    name = "dev"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "kubernetes_namespace" "prod" {
  metadata {
    name = "prod"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  
  lifecycle {
    create_before_destroy = true
  }
}

module "k8s-cluster" {
  source                      = "./modules/k8s-cluster"
  region                      = var.region
  cluster_name                = "polybot-cluster"
  vpc_id                      = var.vpc_id
  subnet_ids                  = var.subnet_ids
  control_plane_instance_type = "t3.medium"
  worker_instance_type        = "t3.medium"
  worker_count                = 2
  route53_zone_id             = var.route53_zone_id
  key_name                    = var.key_name
  control_plane_ami           = var.control_plane_ami
  worker_ami                  = var.worker_ami

  addons = [
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/storage-class.yaml",
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/autoscaler.yaml"
  ]
}

# Wait for Kubernetes API to be fully available
resource "null_resource" "wait_for_kubernetes" {
  depends_on = [module.k8s-cluster, local_file.bootstrap_kubeconfig]
  
  triggers = {
    # Use formatdate instead of raw timestamp to avoid changing on every apply
    timestamp = formatdate("YYYY-MM-DDThh:mm:ssZ", timestamp())
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      # Wait for Kubernetes API to be available
      echo "Waiting for Kubernetes API to be available..."
      export AWS_REGION=us-east-1
      export AWS_DEFAULT_REGION=us-east-1
      
      # Find the control plane instance by tag
      echo "Finding control plane instance by tag..."
      INSTANCE_ID=$(aws ec2 describe-instances --region us-east-1 --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text || echo "")
      
      if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "None" ]; then
        echo "ERROR: Could not find control plane instance with tag 'Name=k8s-control-plane'"
        exit 1
      fi
      
      echo "Found control plane instance: $INSTANCE_ID"
      
      # Get the instance's public IP address
      PUBLIC_IP=$(aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
      PRIVATE_IP=$(aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)
      
      if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
        echo "No public IP found, will use private IP: $PRIVATE_IP"
        CP_IP=$PRIVATE_IP
        IP_TYPE="private"
      else
        echo "Using public IP: $PUBLIC_IP"
        CP_IP=$PUBLIC_IP
        IP_TYPE="public"
      fi
      
      echo "Control plane IP: $CP_IP (type: $IP_TYPE)"
      
      # First verify that the server is actually running
      echo "Checking basic connectivity to control plane..."
      attempt=0
      max_attempts=15
      
      while true; do
        if nc -z -w5 $CP_IP 22 2>/dev/null; then
          echo "SSH port is open, instance appears to be running"
          break
        fi
        
        attempt=$((attempt+1))
        if [ $attempt -ge $max_attempts ]; then
          echo "Timed out waiting for instance to be accessible"
          echo "This suggests a fundamental network or security group issue"
          exit 1
        fi
        echo "Attempt $attempt/$max_attempts: TCP port 22 not available yet, waiting..."
        sleep 15
      done
      
      # Wait for kubernetes initialization with a more adaptive approach
      echo "Instance is running. Waiting for Kubernetes initialization..."
      INIT_WAIT=120
      echo "Initial wait: $INIT_WAIT seconds"
      sleep $INIT_WAIT
      
      # Check if kubelet is running before proceeding
      echo "Checking if kubelet is running on control plane..."
      KUBELET_CHECK=$(aws ssm send-command \
        --instance-ids $INSTANCE_ID \
        --document-name "AWS-RunShellScript" \
        --parameters commands="systemctl status kubelet" \
        --output text --query "CommandInvocations[].CommandPlugins[].Output" || echo "Failed")
      
      if echo "$KUBELET_CHECK" | grep -q "active (running)"; then
        echo "Kubelet is running. Proceeding with API check..."
      else
        echo "Kubelet not yet running, waiting an additional 60 seconds..."
        sleep 60
      fi
      
      # Try to get logs and debug info via SSM
      function get_debug_info {
        echo "=========== GATHERING DEBUG INFO ==========="
        echo "Attempting to retrieve cluster state from server..."
        
        if [ -z "$INSTANCE_ID" ]; then
          echo "No instance ID available for logs."
          return
        fi
        
        # Get kubelet status
        echo "Checking kubelet status via AWS SSM..."
        aws ssm send-command \
          --instance-ids $INSTANCE_ID \
          --document-name "AWS-RunShellScript" \
          --parameters commands="systemctl status kubelet" \
          --output text --query "CommandInvocations[].CommandPlugins[].Output" || echo "Failed to retrieve kubelet status"
        
        # Get kubelet logs
        echo "Checking kubelet logs via AWS SSM..."
        aws ssm send-command \
          --instance-ids $INSTANCE_ID \
          --document-name "AWS-RunShellScript" \
          --parameters commands="journalctl -xeu kubelet | tail -n 50" \
          --output text --query "CommandInvocations[].CommandPlugins[].Output" || echo "Failed to retrieve kubelet logs"
        
        # Check API server pods
        echo "Checking API server pods via AWS SSM..."
        aws ssm send-command \
          --instance-ids $INSTANCE_ID \
          --document-name "AWS-RunShellScript" \
          --parameters commands="kubectl get pods -n kube-system -l component=kube-apiserver -o wide" \
          --output text --query "CommandInvocations[].CommandPlugins[].Output" || echo "Failed to retrieve API server pod status"
        
        # Check if port 6443 is listening
        echo "Checking if port 6443 is listening via AWS SSM..."
        aws ssm send-command \
          --instance-ids $INSTANCE_ID \
          --document-name "AWS-RunShellScript" \
          --parameters commands="netstat -tulpn | grep 6443" \
          --output text --query "CommandInvocations[].CommandPlugins[].Output" || echo "Failed to check listening ports"
        
        echo "=========== END DEBUG INFO ==========="
      }
      
      # Check for Kubernetes API
      echo "Now checking for Kubernetes API at https://$CP_IP:6443..."
      
      attempt=0
      max_attempts=30
      
      # Keep trying until we get a response or timeout
      while true; do
        # First check if port 6443 is open
        if nc -z -w5 $CP_IP 6443 2>/dev/null; then
          echo "Port 6443 is open, testing API server..."
          if curl -k --connect-timeout 10 --max-time 15 https://$CP_IP:6443/healthz 2>/dev/null | grep -q ok; then
            echo "Kubernetes API is available!"
            break
          else
            echo "Port 6443 is open but API not responding correctly."
            curl -k -v https://$CP_IP:6443/healthz 2>&1 | head -20
          fi
        else
          echo "Port 6443 is not yet open."
          
          # Check if the instance is definitely up (via port 22)
          if ! nc -z -w5 $CP_IP 22 2>/dev/null; then
            echo "WARNING: Instance is no longer accessible via SSH. It may have rebooted."
          fi
        fi
        
        attempt=$((attempt+1))
        if [ $attempt -ge $max_attempts ]; then
          echo "Timed out waiting for Kubernetes API"
          echo "Debug info:"
          echo "- Control plane instance ID: $INSTANCE_ID"
          echo "- Control plane IP: $CP_IP (type: $IP_TYPE)"
          echo "- Attempting to connect to port 6443 to verify it's open..."
          nc -z -v $CP_IP 6443 || echo "Port 6443 appears to be closed"
          
          # Gather debug info
          get_debug_info
          
          echo "SOLUTION: You may need to manually check the control plane instance."
          echo "Try running: aws ssm start-session --target $INSTANCE_ID --region $AWS_REGION"
          echo "Or run: ssh ubuntu@$CP_IP"
          exit 1
        fi
        
        echo "Attempt $attempt/$max_attempts: Kubernetes API not ready yet, waiting..."
        sleep 20
        
        # Every 5 attempts, get more debug info
        if [ $((attempt % 5)) -eq 0 ]; then
          get_debug_info
        fi
      done
      
      # Retrieve the proper kubeconfig file from the control plane node
      echo "Retrieving kubeconfig file from control plane..."
      CMD_ID=$(aws ssm send-command \
        --instance-ids $INSTANCE_ID \
        --document-name "AWS-RunShellScript" \
        --parameters commands="cat /etc/kubernetes/admin.conf" \
        --output text --query "CommandId")
      
      echo "Waiting for kubeconfig to be retrieved (Command ID: $CMD_ID)..."
      sleep 5
      
      # Wait for command to complete and get the output
      RESPONSE=""
      MAX_WAIT=10
      for i in $(seq 1 $MAX_WAIT); do
        echo "Fetching kubeconfig, attempt $i of $MAX_WAIT..."
        CMD_STATUS=$(aws ssm get-command-invocation \
          --command-id "$CMD_ID" \
          --instance-id "$INSTANCE_ID" \
          --query "Status" \
          --output text)
          
        if [[ "$CMD_STATUS" == "Success" ]]; then
          RESPONSE=$(aws ssm get-command-invocation \
            --command-id "$CMD_ID" \
            --instance-id "$INSTANCE_ID" \
            --query "StandardOutputContent" \
            --output text)
          break
        elif [[ "$CMD_STATUS" == "Failed" || "$CMD_STATUS" == "Cancelled" || "$CMD_STATUS" == "TimedOut" ]]; then
          echo "Command failed with status: $CMD_STATUS"
          aws ssm get-command-invocation \
            --command-id "$CMD_ID" \
            --instance-id "$INSTANCE_ID" \
            --query "StandardErrorContent" \
            --output text
          break
        fi
        
        if [ $i -eq $MAX_WAIT ]; then
          echo "Timed out waiting for kubeconfig retrieval"
        fi
        
        sleep 5
      done
      
      if [ -z "$RESPONSE" ]; then
        echo "ERROR: Failed to retrieve kubeconfig from control plane"
        exit 1
      fi
      
      # Save the retrieved kubeconfig to a local file
      echo "$RESPONSE" > kubeconfig.yml.tmp
      
      # Process kubeconfig to ensure correct formatting
      cat kubeconfig.yml.tmp | sed 's/\\n/\n/g' | sed 's/\\t/\t/g' > kubeconfig.yml
      rm kubeconfig.yml.tmp
      
      # Update the server address in the kubeconfig
      sed -i.bak "s|server: https://[^:]*:|server: https://$CP_IP:|" kubeconfig.yml
      
      # Ensure proper YAML format
      echo "Verifying kubeconfig format..."
      if command -v python3 &> /dev/null; then
        python3 -c "import yaml; yaml.safe_load(open('kubeconfig.yml')); print('Kubeconfig format is valid')" || {
          echo "WARNING: kubeconfig has format issues, attempting to fix..."
          # Try to fix common escaping issues
          cat kubeconfig.yml | python3 -c "import sys, yaml; print(yaml.dump(yaml.safe_load(sys.stdin)))" > kubeconfig.yml.fixed
          if [ $? -eq 0 ]; then
            mv kubeconfig.yml.fixed kubeconfig.yml
            echo "Fixed kubeconfig format"
          else
            echo "Could not fix kubeconfig format automatically"
          fi
        }
      fi
      
      # Double check the file exists and has content
      if [ ! -s kubeconfig.yml ]; then
        echo "ERROR: kubeconfig.yml is empty or doesn't exist"
        exit 1
      fi
      
      # Verify file has apiVersion field
      if ! grep -q "apiVersion:" kubeconfig.yml; then
        echo "ERROR: kubeconfig.yml is missing apiVersion field"
        echo "Content of the file:"
        cat kubeconfig.yml
        exit 1
      fi
      
      echo "Created kubeconfig file at $(pwd)/kubeconfig.yml"
      echo "export KUBECONFIG=$(pwd)/kubeconfig.yml" > k8s-env.sh
      echo "Kubernetes is ready! You can now use kubectl with the created kubeconfig."
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes]
  
  # This ensures we rebuild when kubeconfig changes, not on every apply
  triggers_replace = {
    kubeconfig_exists = fileexists("${path.module}/kubeconfig.yml") ? "true" : "false"
    # Add a checksum of the kubeconfig file to track content changes
    kubeconfig_hash = fileexists("${path.module}/kubeconfig.yml") ? filesha256("${path.module}/kubeconfig.yml") : "none"
  }

  # Force provision step to ensure consistency between kubeconfig and the API server
  provisioner "local-exec" {
    command = <<-EOT
      # Get the control plane's current IP
      INSTANCE_ID=$(aws ec2 describe-instances --region us-east-1 --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
      PUBLIC_IP=$(aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
      
      echo "Control plane public IP: $PUBLIC_IP"
      
      # Make sure the kubeconfig file exists
      if [ ! -f "${path.module}/kubeconfig.yml" ]; then
        echo "ERROR: kubeconfig.yml not found!"
        exit 1
      fi
      
      # Validate the kubeconfig format
      if command -v python3 &> /dev/null; then
        echo "Validating kubeconfig format with Python..."
        python3 -c "import yaml; config = yaml.safe_load(open('${path.module}/kubeconfig.yml')); print('✅ Valid kubeconfig with version:', config.get('apiVersion'))" || {
          echo "⚠️ Kubeconfig validation failed, attempting to fix..."
          # Simple attempt to fix common issues
          cat "${path.module}/kubeconfig.yml" | tr -d '\r' > "${path.module}/kubeconfig.fixed.yml"
          mv "${path.module}/kubeconfig.fixed.yml" "${path.module}/kubeconfig.yml"
          python3 -c "import yaml; yaml.safe_load(open('${path.module}/kubeconfig.yml')); print('✅ Fixed kubeconfig format')" || {
            echo "❌ Could not fix kubeconfig format automatically"
            echo "------- Current content of kubeconfig.yml -------"
            cat "${path.module}/kubeconfig.yml" | head -20
            echo "-----------------------------------------------"
            exit 1
          }
        }
      else
        echo "Warning: Python not available for YAML validation"
        # Simple validation with grep
        grep -q "apiVersion:" "${path.module}/kubeconfig.yml" || {
          echo "ERROR: kubeconfig doesn't contain apiVersion field"
          exit 1
        }
      fi
      
      # Update kubeconfig with current IP
      if [ -f "${path.module}/kubeconfig.yml" ]; then
        sed -i.bak "s|server: https://[^:]*:|server: https://$PUBLIC_IP:|g" "${path.module}/kubeconfig.yml"
        echo "Updated kubeconfig to use IP: $PUBLIC_IP"
      fi
      
      # Verify we can connect using the kubeconfig
      if command -v kubectl &> /dev/null; then
        echo "Testing kubectl connectivity with the kubeconfig..."
        KUBECONFIG="${path.module}/kubeconfig.yml" kubectl cluster-info || {
          echo "Warning: Could not connect to the cluster with kubectl"
        }
      else
        echo "Warning: kubectl not available for connectivity testing"
      fi
    EOT
  }
}

# Install EBS CSI Driver for persistent storage
resource "helm_release" "aws_ebs_csi_driver" {
  count      = fileexists("${path.module}/kubeconfig.yml") ? 1 : 0
  name       = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  namespace  = "kube-system"
  version    = "2.23.0"  # Use a specific stable version

  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.k8s-cluster.control_plane_iam_role_arn
  }

  values = [<<EOF
storageClasses:
  - name: ebs-sc
    annotations:
      storageclass.kubernetes.io/is-default-class: "true"
    volumeBindingMode: WaitForFirstConsumer
    parameters:
      csi.storage.k8s.io/fstype: xfs
      type: gp2
      encrypted: "true"
EOF
  ]

  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
  timeout    = 600
}

# ArgoCD deployment
module "argocd" {
  count          = fileexists("${path.module}/kubeconfig.yml") ? 1 : 0
  source         = "./modules/argocd"
  git_repo_url   = var.git_repo_url
  
  providers = {
    kubernetes = kubernetes
    helm       = helm
    kubectl    = kubectl
  }
  
  depends_on     = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
}

# Development environment resources
module "polybot_dev" {
  source          = "./modules/polybot"
  region          = var.region
  route53_zone_id = var.route53_zone_id
  alb_dns_name    = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id     = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment     = "dev"
  telegram_token  = var.telegram_token_dev
  aws_access_key_id = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username = var.docker_username
  docker_password = var.docker_password
}

# Production environment resources
module "polybot_prod" {
  source          = "./modules/polybot"
  region          = var.region
  route53_zone_id = var.route53_zone_id
  alb_dns_name    = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id     = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment     = "prod"
  telegram_token  = var.telegram_token_prod
  aws_access_key_id = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username = var.docker_username
  docker_password = var.docker_password
}
