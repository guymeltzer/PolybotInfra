# REORGANIZED OUTPUTS - Structured into logical sections

# ------------------------------------------------------------------------
# Section 1: Kubernetes Infrastructure
# ------------------------------------------------------------------------

output "kubernetes_api_endpoint" {
  description = "Kubernetes API endpoint"
  value       = module.k8s-cluster.kubernetes_api_endpoint
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.k8s-cluster.vpc_id
}

output "load_balancer_address" {
  description = "DNS name of the application load balancer"
  value       = module.k8s-cluster.alb_dns_name
}

output "subnet_ids" {
  description = "Subnet IDs created for the Kubernetes cluster"
  value       = module.k8s-cluster.public_subnet_ids
}

# ------------------------------------------------------------------------
# Section 2: Control Plane Node Details
# ------------------------------------------------------------------------

output "control_plane_details" {
  description = "Details of the control plane node"
  value = {
    instance_id = module.k8s-cluster.control_plane_instance_id
    public_ip   = module.k8s-cluster.control_plane_public_ip
    private_ip  = module.k8s-cluster.control_plane_private_ip
    ssh_command = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}"
  }
}

# ------------------------------------------------------------------------
# Section 3: Worker Node Details
# ------------------------------------------------------------------------

output "worker_nodes_overview" {
  description = "Overview of worker nodes"
  value = <<-EOT
    Worker Node Auto Scaling Group: ${module.k8s-cluster.worker_asg_name}
    Worker Count: 2
    Get detailed worker info with: 
    aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=guy-worker-node*" --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}" --output table
  EOT
}

output "worker_node_ssh_command" {
  description = "SSH command template for worker nodes"
  value       = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@WORKER_PUBLIC_IP (replace WORKER_PUBLIC_IP with the IP from the worker nodes list)"
}

# Dynamically get worker node details (attempts to get them if available)
resource "null_resource" "worker_node_details" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    command = "aws ec2 describe-instances --region ${var.region} --filters \"Name=tag:Name,Values=guy-worker-node*\" --query \"Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,PublicIP:PublicIpAddress}\" --output json > /tmp/worker_nodes.json || echo '[]' > /tmp/worker_nodes.json"
  }
}

output "worker_nodes" {
  description = "Worker node details"
  value = fileexists("/tmp/worker_nodes.json") ? jsondecode(file("/tmp/worker_nodes.json")) : []
}

# ------------------------------------------------------------------------
# Section 4: Kubernetes Access Commands
# ------------------------------------------------------------------------

output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=$$(pwd)/kubeconfig.yaml"
}

output "init_logs_commands" {
  description = "Commands to view initialization logs on control plane and worker nodes"
  value       = module.k8s-cluster.init_logs_commands
}

# ------------------------------------------------------------------------
# Section 5: ArgoCD Information
# ------------------------------------------------------------------------

output "argocd_url" {
  description = "URL of the ArgoCD server (port forwarded)"
  value       = "https://localhost:8080 (Run ./argocd-access.sh start to start port forwarding)"
}

output "argocd_admin_credentials" {
  description = "ArgoCD admin credentials"
  value = <<-EOT
    Username: admin
    Password: Run ./argocd-access.sh password to retrieve
  EOT
}

output "argocd_access_script" {
  description = "ArgoCD access script usage"
  value = <<-EOT
    ✅ ArgoCD Access Helper Script
    
    To access ArgoCD UI:
    1. Run: ./argocd-access.sh start
    2. Open: https://localhost:8080
    3. Username: admin
    4. Password: Will be displayed by the script
    
    To stop port forwarding:
    Run: ./argocd-access.sh stop
    
    To just get the password:
    Run: ./argocd-access.sh password
  EOT
}

# ------------------------------------------------------------------------
# Section 6: Polybot Application URLs
# ------------------------------------------------------------------------

output "polybot_dev_url" {
  description = "URL for accessing Polybot dev environment"
  value       = "https://dev-polybot.${terraform.workspace}.devops-int-college.com"
}

output "polybot_prod_url" {
  description = "URL for accessing Polybot production environment"
  value       = "https://polybot.${terraform.workspace}.devops-int-college.com"
}

output "polybot_alb_dns" {
  description = "Polybot ALB DNS name"
  value       = module.k8s-cluster.alb_dns_name
}

# ------------------------------------------------------------------------
# Section 7: Polybot AWS Resources
# ------------------------------------------------------------------------

# Development Environment Outputs
output "polybot_dev_resources" {
  description = "Development environment resources"
  value = {
    s3_bucket   = module.polybot_dev.s3_bucket_name
    sqs_queue   = module.polybot_dev.sqs_queue_url
    domain_name = module.polybot_dev.domain_name
  }
}

# Production Environment Outputs
output "polybot_prod_resources" {
  description = "Production environment resources"
  value = {
    s3_bucket   = module.polybot_prod.s3_bucket_name
    sqs_queue   = module.polybot_prod.sqs_queue_url
    domain_name = module.polybot_prod.domain_name
  }
}

# ------------------------------------------------------------------------
# Section 8: SSH Access Details
# ------------------------------------------------------------------------

output "ssh_key_name" {
  value       = module.k8s-cluster.ssh_key_name
  description = "SSH key name used for the instances"
}

output "ssh_private_key_path" {
  value = module.k8s-cluster.ssh_private_key_path
}

output "ssh_command_control_plane" {
  value = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}"
}

# ------------------------------------------------------------------------
# Section 9: Troubleshooting Commands
# ------------------------------------------------------------------------

output "worker_logs_command" {
  value = module.k8s-cluster.worker_logs_command
}

output "worker_node_info" {
  value = module.k8s-cluster.worker_node_info
}