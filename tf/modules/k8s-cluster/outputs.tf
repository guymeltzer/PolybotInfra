output "vpc_id" {
  description = "ID of the VPC created for the cluster"
  value       = module.vpc.vpc_id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets created for the cluster"
  value       = module.vpc.public_subnets
}

output "private_subnet_ids" {
  description = "IDs of the private subnets created for the cluster"
  value       = module.vpc.private_subnets
}

output "control_plane_public_ip" {
  description = "The public IP address of the Kubernetes control plane"
  value       = aws_instance.control_plane.public_ip
}

output "control_plane_private_ip" {
  description = "Private IP of the control plane node"
  value       = aws_instance.control_plane.private_ip
}

output "kubeconfig_path" {
  description = "Path to the kubeconfig file"
  value       = "/root/.kube/config"
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.polybot_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.polybot_alb.zone_id
}

output "cluster_ca_certificate" {
  description = "Base64 encoded public certificate authority data for the cluster"
  value       = fileexists("${path.module}/certs/ca.crt") ? base64encode(file("${path.module}/certs/ca.crt")) : ""
  sensitive   = true
}

output "client_certificate" {
  description = "Base64 encoded client certificate for authentication"
  value       = fileexists("${path.module}/certs/client.crt") ? base64encode(file("${path.module}/certs/client.crt")) : ""
  sensitive   = true
}

output "client_key" {
  description = "Base64 encoded client key for authentication"
  value       = fileexists("${path.module}/certs/client.key") ? base64encode(file("${path.module}/certs/client.key")) : ""
  sensitive   = true
}

output "client_certificate_data" {
  description = "Base64 encoded client certificate for authentication (for kubeconfig)"
  value       = fileexists("${path.module}/certs/client.crt") ? base64encode(file("${path.module}/certs/client.crt")) : ""
}

output "client_key_data" {
  description = "Base64 encoded client key for authentication (for kubeconfig)"
  value       = fileexists("${path.module}/certs/client.key") ? base64encode(file("${path.module}/certs/client.key")) : ""
}

output "control_plane_instance" {
  description = "Control plane EC2 instance resource"
  value       = aws_instance.control_plane
}

output "control_plane_iam_role_arn" {
  description = "ARN of the IAM role for the control plane node"
  value       = aws_iam_role.control_plane_role.arn
}

output "control_plane_instance_id" {
  description = "The instance ID of the Kubernetes control plane"
  value       = aws_instance.control_plane.id
}