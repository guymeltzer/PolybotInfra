output "kubernetes_api_endpoint" {
  description = "Kubernetes API endpoint"
  value       = module.k8s-cluster.kubernetes_api_endpoint
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
  value       = module.polybot_dev.domain_name
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
  value       = module.polybot_prod.domain_name
}

output "polybot_alb_dns" {
  description = "Polybot ALB DNS name"
  value       = module.k8s-cluster.alb_dns_name
}

output "subnet_ids" {
  description = "Subnet IDs created for the Kubernetes cluster"
  value       = module.k8s-cluster.public_subnet_ids
}

# Conditional outputs for ArgoCD, using try() to handle potential errors
output "argocd_url" {
  description = "URL of the ArgoCD server"
  value       = try(module.argocd.argocd_server_service_url, "argocd-not-available")
}

output "argocd_applications" {
  description = "ArgoCD applications deployed"
  value       = try(module.argocd.argocd_applications, null)
  sensitive   = true
}

output "ssh_key_name" {
  value       = module.k8s-cluster.ssh_key_name
  description = "SSH key name used for the instances"
}

output "ssh_private_key_path" {
  value = module.k8s-cluster.ssh_private_key_path
}

output "ssh_command_control_plane" {
  value = module.k8s-cluster.ssh_command_control_plane
}

output "ssh_command_worker_nodes" {
  value = module.k8s-cluster.ssh_command_worker_nodes
}

output "worker_logs_command" {
  value = module.k8s-cluster.worker_logs_command
}

output "worker_node_info" {
  value = module.k8s-cluster.worker_node_info
}

output "init_logs_commands" {
  description = "Commands to view initialization logs on control plane and worker nodes"
  value       = module.k8s-cluster.init_logs_commands
}