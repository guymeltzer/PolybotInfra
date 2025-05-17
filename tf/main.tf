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
    # Also track the control plane ID
    control_plane_id = module.k8s-cluster.control_plane_instance.id
  }
  
  provisioner "local-exec" {
    command = <<EOT
      # Wait for Kubernetes API to be available
      echo "Waiting for Kubernetes API to be available..."
      export AWS_REGION=us-east-1
      export AWS_DEFAULT_REGION=us-east-1
      
      # Use the direct instance ID from Terraform output
      INSTANCE_ID="${module.k8s-cluster.control_plane_instance.id}"
      echo "Using control plane instance ID directly from Terraform: $INSTANCE_ID"
      
      # Wait for the instance to be in running state
      echo "Waiting for instance to be in running state..."
      aws ec2 wait instance-running --region us-east-1 --instance-ids $INSTANCE_ID
      
      # Get the public IP of the control plane
      CP_IP=$(aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
      echo "Control plane IP: $CP_IP"
      
      if [ -z "$CP_IP" ]; then
        echo "ERROR: Failed to get public IP for instance $INSTANCE_ID"
        echo "Instance details:"
        aws ec2 describe-instances --region us-east-1 --instance-ids $INSTANCE_ID --output json
        exit 1
      fi
      
      echo "Waiting for Kubernetes API at https://$CP_IP:6443 to become available..."
      
      attempt=0
      max_attempts=45
      until curl -k https://$CP_IP:6443/healthz -v 2>/dev/null | grep -q ok; do
        attempt=$((attempt+1))
        if [ $attempt -ge $max_attempts ]; then
          echo "Timed out waiting for Kubernetes API"
          echo "Debug info:"
          echo "- Control plane instance status: $(aws ec2 describe-instance-status --region us-east-1 --instance-ids $INSTANCE_ID --output json)"
          echo "- Control plane public IP: $CP_IP"
          echo "- EC2 console output: $(aws ec2 get-console-output --region us-east-1 --instance-id $INSTANCE_ID --output text || echo 'Failed to get console output')"
          echo "- Trying to ping control plane: $(ping -c 3 $CP_IP || echo 'Ping failed')"
          exit 1
        fi
        echo "Attempt $attempt/$max_attempts: Kubernetes API not ready yet, waiting..."
        sleep 20
      done
      echo "Kubernetes API is available!"
      
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
      echo "Created kubeconfig file"
      
      # Export KUBECONFIG to make it easier to debug
      echo "export KUBECONFIG=$(pwd)/kubeconfig.yml" > k8s-env.sh
      echo "Kubernetes environment file created at k8s-env.sh"
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes]
  
  # This ensures we rebuild when anything related to the API changes
  triggers_replace = {
    timestamp = timestamp()
    control_plane_id = module.k8s-cluster.control_plane_instance.id
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
