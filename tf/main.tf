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
  
  provisioner "local-exec" {
    command = <<EOT
      # Wait for Kubernetes API to be available
      echo "Waiting for Kubernetes API to be available..."
      echo "Control plane IP: ${module.k8s-cluster.control_plane_public_ip}"
      attempt=0
      max_attempts=45
      until curl -k https://${module.k8s-cluster.control_plane_public_ip}:6443/healthz -v 2>/dev/null | grep -q ok; do
        attempt=$((attempt+1))
        if [ $attempt -ge $max_attempts ]; then
          echo "Timed out waiting for Kubernetes API"
          echo "Debug info:"
          echo "- Control plane instance ID: $(aws ec2 describe-instances --filters "Name=tag:Name,Values=k8s-control-plane" --query "Reservations[].Instances[].InstanceId" --output text)"
          echo "- Control plane public IP: ${module.k8s-cluster.control_plane_public_ip}"
          echo "- Trying to ping control plane: $(ping -c 3 ${module.k8s-cluster.control_plane_public_ip} || echo 'Ping failed')"
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
    server: https://${module.k8s-cluster.control_plane_public_ip}:6443
    insecure-skip-tls-verify: true
users:
- name: default-user
  user:
    client-certificate-data: ${module.k8s-cluster.client_certificate_data}
    client-key-data: ${module.k8s-cluster.client_key_data}
contexts:
- name: default-context
  context:
    cluster: default-cluster
    user: default-user
current-context: default-context
EOF
      echo "Created kubeconfig file"
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  depends_on = [null_resource.wait_for_kubernetes]
  
  # These trigger changes when the control plane is recreated or credentials change
  triggers_replace = {
    control_plane_ip = module.k8s-cluster.control_plane_public_ip
    client_cert_hash = sha256(module.k8s-cluster.client_certificate_data != "" ? module.k8s-cluster.client_certificate_data : "empty")
    client_key_hash = sha256(module.k8s-cluster.client_key_data != "" ? module.k8s-cluster.client_key_data : "empty")
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
