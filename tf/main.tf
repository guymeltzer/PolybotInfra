provider "aws" {
  region = var.region
}

# Create a data source to fetch the cluster details
data "aws_instance" "control_plane" {
  depends_on = [module.k8s-cluster]
  filter {
    name   = "tag:Name"
    values = ["guy-control-plane"]
  }
}

# Define a local provider for first-time setup
provider "local" {}

# Configure the Kubernetes provider
provider "kubernetes" {
  host                   = "https://${data.aws_instance.control_plane.public_ip}:6443"
  cluster_ca_certificate = module.k8s-cluster.cluster_ca_certificate
  
  # Use client certificate authentication instead of EKS token
  client_certificate     = module.k8s-cluster.client_certificate
  client_key             = module.k8s-cluster.client_key
  
  # Increase timeout for cluster to become available
  ignore_annotations     = [".*"]
  ignore_labels          = [".*"]
  insecure               = false
}

# Configure the Helm provider
provider "helm" {
  kubernetes {
    host                   = "https://${data.aws_instance.control_plane.public_ip}:6443"
    cluster_ca_certificate = module.k8s-cluster.cluster_ca_certificate
    
    # Use client certificate authentication instead of EKS token
    client_certificate     = module.k8s-cluster.client_certificate
    client_key             = module.k8s-cluster.client_key
  }
}

# Configure the kubectl provider
provider "kubectl" {
  host                   = "https://${data.aws_instance.control_plane.public_ip}:6443"
  cluster_ca_certificate = module.k8s-cluster.cluster_ca_certificate
  load_config_file       = false
  
  # Use client certificate authentication instead of EKS token
  client_certificate     = module.k8s-cluster.client_certificate
  client_key             = module.k8s-cluster.client_key
}

# Create Kubernetes namespaces for dev and prod
resource "kubernetes_namespace" "dev" {
  metadata {
    name = "dev"
  }
  depends_on = [module.k8s-cluster]
}

resource "kubernetes_namespace" "prod" {
  metadata {
    name = "prod"
  }
  depends_on = [module.k8s-cluster]
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

  depends_on = [module.k8s-cluster]
}

# ArgoCD deployment
module "argocd" {
  source         = "./modules/argocd"
  git_repo_url   = var.git_repo_url
  depends_on     = [module.k8s-cluster]
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
}
