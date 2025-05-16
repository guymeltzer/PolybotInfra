output "kubernetes_api_server_endpoint" {
  description = "Endpoint for Kubernetes API server"
  value       = module.k8s-cluster.control_plane_public_ip
}

# Development Environment Outputs
output "polybot_dev_s3_bucket" {
  description = "Polybot Dev S3 bucket name"
  value       = module.polybot_dev.s3_bucket_name
}

output "polybot_dev_sqs_queue_url" {
  description = "Polybot Dev SQS queue URL"
  value       = module.polybot_dev.sqs_queue_url
}

output "polybot_dev_url" {
  description = "Polybot Dev URL"
  value       = "https://guy-polybot-dev.devops-int-college.com"
}

# Production Environment Outputs
output "polybot_prod_s3_bucket" {
  description = "Polybot Prod S3 bucket name"
  value       = module.polybot_prod.s3_bucket_name
}

output "polybot_prod_sqs_queue_url" {
  description = "Polybot Prod SQS queue URL"
  value       = module.polybot_prod.sqs_queue_url
}

output "polybot_prod_url" {
  description = "Polybot Prod URL"
  value       = "https://guy-polybot-prod.devops-int-college.com"
}

output "polybot_alb_dns" {
  description = "Polybot ALB DNS name"
  value       = module.k8s-cluster.alb_dns_name
}

output "vpc_id" {
  description = "VPC ID created for the Kubernetes cluster"
  value       = module.k8s-cluster.vpc_id
}

output "subnet_ids" {
  description = "Subnet IDs created for the Kubernetes cluster"
  value       = module.k8s-cluster.subnet_ids
}

output "argocd_url" {
  description = "URL of the ArgoCD server"
  value       = module.argocd.argocd_url
}

output "argocd_applications" {
  description = "ArgoCD applications deployed"
  value       = module.argocd.applications
}
