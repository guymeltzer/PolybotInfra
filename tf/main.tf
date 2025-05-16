provider "aws" {
  region = var.region
}

module "k8s-cluster" {
  source         = "./modules/k8s-cluster"
  region         = var.region
  cluster_name   = "polybot-cluster"
  vpc_id         = var.vpc_id
  subnet_ids     = var.subnet_ids
  subnet_ids     = var.public_subnet_ids
  control_plane_instance_type = "t3.medium"
  worker_instance_type        = "t3.medium"
  worker_count                = 2

  addons = [
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/storage-class.yaml",
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/autoscaler.yaml"
  ]
