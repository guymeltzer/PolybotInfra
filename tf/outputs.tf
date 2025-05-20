output "kubernetes_api_endpoint" {
  description = "Kubernetes API endpoint"
  value       = "https://${module.k8s-cluster.control_plane_public_ip}:6443"
}

output "control_plane_public_ip" {
  description = "Control plane public IP address"
  value       = module.k8s-cluster.control_plane_public_ip
}

output "control_plane_private_ip" {
  description = "Control plane private IP address"
  value       = module.k8s-cluster.control_plane_private_ip
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.k8s-cluster.vpc_id
}

output "load_balancer_address" {
  description = "DNS name of the application load balancer"
  value       = module.k8s-cluster.alb_dns_name
}

output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "ssh ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=$(pwd)/kubeconfig.yaml"
}

output "polybot_dev_url" {
  description = "URL for accessing Polybot dev environment"
  value       = "https://dev-polybot.${terraform.workspace}.devops-int-college.com"
}

output "polybot_prod_url" {
  description = "URL for accessing Polybot production environment"
  value       = "https://polybot.${terraform.workspace}.devops-int-college.com"
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

output "polybot_dev_domain" {
  description = "Polybot Dev domain name"
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

output "polybot_prod_domain" {
  description = "Polybot Prod domain name"
  value       = "https://guy-polybot-prod.devops-int-college.com"
}

output "polybot_alb_dns" {
  description = "Polybot ALB DNS name"
  value       = module.k8s-cluster.alb_dns_name
}

output "subnet_ids" {
  description = "Subnet IDs created for the Kubernetes cluster"
  value       = module.k8s-cluster.public_subnet_ids
}

output "argocd_url" {
  description = "URL of the ArgoCD server"
  value       = module.argocd.argocd_url
}

output "argocd_applications" {
  description = "ArgoCD applications deployed"
  value       = module.argocd.applications
  sensitive   = true
}
