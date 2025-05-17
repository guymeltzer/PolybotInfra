provider "aws" {
  region = var.region
}

# Define a local provider for first-time setup
provider "local" {}

# Configure the Kubernetes provider with safe defaults
provider "kubernetes" {
  # These values are placeholders that will be ignored during initial apply
  # The actual connection will happen in subsequent applies after the cluster is ready
  host = "https://127.0.0.1:6443"  # Placeholder
  client_certificate = ""
  client_key = ""
  cluster_ca_certificate = ""
  
  # Skip validation during initial apply
  insecure = true
  ignore_annotations = [".*"]
  ignore_labels = [".*"]
}

# Configure the Helm provider with safe defaults
provider "helm" {
  kubernetes {
    # These values are placeholders that will be ignored during initial apply
    host = "https://127.0.0.1:6443"  # Placeholder
    client_certificate = ""
    client_key = ""
    cluster_ca_certificate = ""
    
    # Skip validation during initial apply
    insecure = true
  }
}

# Configure the kubectl provider with safe defaults
provider "kubectl" {
  # These values are placeholders that will be ignored during initial apply
  host = "https://127.0.0.1:6443"  # Placeholder
  client_certificate = ""
  client_key = ""
  cluster_ca_certificate = ""
  
  # Skip validation during initial apply
  load_config_file = false
  insecure = true
}

# Create Kubernetes namespaces for dev and prod
resource "kubernetes_namespace" "dev" {
  metadata {
    name = "dev"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
}

resource "kubernetes_namespace" "prod" {
  metadata {
    name = "prod"
  }
  depends_on = [module.k8s-cluster, null_resource.wait_for_kubernetes, terraform_data.kubectl_provider_config]
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
  depends_on = [module.k8s-cluster]
  
  triggers = {
    # Use timestamp to always run this
    timestamp = timestamp()
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
      INSTANCE_ID=$(aws ec2 describe-instances --region us-east-1 --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
      
      if [ "$INSTANCE_ID" = "None" ] || [ -z "$INSTANCE_ID" ]; then
        echo "ERROR: Could not find control plane instance with tag 'Name=k8s-control-plane'"
        exit 1
      fi
      
      echo "Found control plane instance: $INSTANCE_ID"
      
      # Get the instance's public IP address
      PUBLIC_IP=$(aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
      PRIVATE_IP=$(aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)
      
      if [ "$PUBLIC_IP" = "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo "No public IP found, will use private IP: $PRIVATE_IP"
        CP_IP=$PRIVATE_IP
        IP_TYPE="private"
      else
        echo "Using public IP: $PUBLIC_IP"
        CP_IP=$PUBLIC_IP
        IP_TYPE="public"
      fi
      
      echo "Control plane IP: $CP_IP (type: $IP_TYPE)"
      
      # Check instance console output for errors first
      echo "Getting console output for troubleshooting..."
      aws ec2 get-console-output --region us-east-1 --instance-id $INSTANCE_ID --output text || echo "Failed to get console output"
      
      # Wait for SSH to be available first (proving network connectivity)
      echo "Checking SSH connectivity to control plane..."
      attempt=0
      max_attempts=10
      SSH_READY=0
      
      while [ $attempt -lt $max_attempts ] && [ $SSH_READY -eq 0 ]; do
        if nc -z -w5 $CP_IP 22 2>/dev/null; then
          SSH_READY=1
          echo "SSH connectivity confirmed."
        else
          attempt=$((attempt+1))
          if [ $attempt -ge $max_attempts ]; then
            echo "Timed out waiting for SSH connectivity to control plane"
            echo "This suggests a fundamental network or security group issue"
            exit 1
          fi
          echo "Attempt $attempt/$max_attempts: SSH not available yet, waiting..."
          sleep 15
        fi
      done
      
      # Try to get kubeadm init logs via SSM to see what's happening
      echo "Checking kubeadm logs via SSM..."
      aws ssm send-command --region us-east-1 --instance-ids $INSTANCE_ID --document-name "AWS-RunShellScript" \
        --parameters commands="cat /var/log/k8s-control-plane-init.log | tail -n 50" --output text
      
      echo "Checking kubelet status..."
      aws ssm send-command --region us-east-1 --instance-ids $INSTANCE_ID --document-name "AWS-RunShellScript" \
        --parameters commands="systemctl status kubelet" --output text
      
      # Wait longer before checking for Kubernetes API - it takes time to initialize
      echo "Waiting 3 minutes for Kubernetes initialization..."
      sleep 180
      
      # Now check for Kubernetes API
      echo "Now checking for Kubernetes API at https://$CP_IP:6443..."
      
      attempt=0
      max_attempts=30
      API_READY=0
      
      while [ $attempt -lt $max_attempts ] && [ $API_READY -eq 0 ]; do
        if curl -k --connect-timeout 5 --max-time 10 https://$CP_IP:6443/healthz 2>/dev/null | grep -q ok; then
          API_READY=1
          echo "Kubernetes API is available!"
        else
          attempt=$((attempt+1))
          if [ $attempt -ge $max_attempts ]; then
            echo "Timed out waiting for Kubernetes API"
            echo "Debug info:"
            echo "- Control plane instance ID: $INSTANCE_ID"
            echo "- Control plane IP: $CP_IP (type: $IP_TYPE)"
            
            # Try to get logs from the kubelet service
            echo "Checking for errors in Kubernetes initialization..."
            aws ssm send-command --region us-east-1 --instance-ids $INSTANCE_ID --document-name "AWS-RunShellScript" \
              --parameters commands="systemctl status kubelet || journalctl -xeu kubelet" --output text
            
            # Check kubeadm logs
            echo "Checking kubeadm logs..."
            aws ssm send-command --region us-east-1 --instance-ids $INSTANCE_ID --document-name "AWS-RunShellScript" \
              --parameters commands="cat /var/log/cloud-init-output.log | tail -n 100" --output text
            
            exit 1
          fi
          echo "Attempt $attempt/$max_attempts: Kubernetes API not ready yet, waiting..."
          sleep 20
        fi
      done
      
      # Create kubeconfig file for subsequent operations
      cat > kubeconfig.yml <<EOF
apiVersion: v1
kind: Config
clusters:
- name: default-cluster
  cluster:
    server: https://$CP_IP:6443
    insecure-skip-tls-verify: true
users:
- name: default-user
  user: {}
contexts:
- name: default-context
  context:
    cluster: default-cluster
    user: default-user
current-context: default-context
EOF
      
      echo "Created kubeconfig file at $(pwd)/kubeconfig.yml"
      echo "export KUBECONFIG=$(pwd)/kubeconfig.yml" > k8s-env.sh
      echo "Kubernetes is ready! You can now use kubectl with the created kubeconfig."
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes]
  
  # This ensures we rebuild when anything related to the API changes
  triggers_replace = {
    timestamp = timestamp()
  }
}

# Install EBS CSI Driver for persistent storage
resource "helm_release" "aws_ebs_csi_driver" {
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
  alb_dns_name    = module.k8s-cluster.alb_dns_name
  alb_zone_id     = module.k8s-cluster.alb_zone_id
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
  alb_dns_name    = module.k8s-cluster.alb_dns_name
  alb_zone_id     = module.k8s-cluster.alb_zone_id
  environment     = "prod"
  telegram_token  = var.telegram_token_prod
  aws_access_key_id = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username = var.docker_username
  docker_password = var.docker_password
}
