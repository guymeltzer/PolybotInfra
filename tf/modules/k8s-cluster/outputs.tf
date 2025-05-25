# =============================================================================
# K8S-CLUSTER MODULE ENHANCED OUTPUTS - Visual User Experience
# =============================================================================
# #UX - Enhanced module outputs with colorful formatting and emojis
# #OUTPUT - Detailed resource information with visual clarity

# =============================================================================
# 🏗️ INFRASTRUCTURE OUTPUTS
# =============================================================================

#OUTPUT - VPC and networking details
output "vpc_id" {
  description = "ID of the VPC created for the cluster" #OUTPUT
  value       = module.vpc.vpc_id
}

#OUTPUT - Subnet information
output "public_subnet_ids" {
  description = "IDs of the public subnets created for the cluster" #OUTPUT
  value       = module.vpc.public_subnets
}

output "private_subnet_ids" {
  description = "IDs of the private subnets created for the cluster" #OUTPUT
  value       = module.vpc.private_subnets
}

# =============================================================================
# 🖥️ CONTROL PLANE OUTPUTS
# =============================================================================

#OUTPUT - Control plane network details
output "control_plane_public_ip" {
  description = "The public IP address of the Kubernetes control plane" #OUTPUT
  value       = aws_instance.control_plane.public_ip
}

output "control_plane_private_ip" {
  description = "Private IP of the control plane node" #OUTPUT
  value       = aws_instance.control_plane.private_ip
}

output "control_plane_instance_id" {
  description = "The instance ID of the Kubernetes control plane" #OUTPUT
  value       = aws_instance.control_plane.id
}

#OUTPUT - Enhanced control plane information with visual formatting
output "control_plane_info" {
  description = "Enhanced control plane information with visual formatting" #UX
  value = <<EOT
\033[1;36m📡 Control Plane Details\033[0m
\033[1;36m========================\033[0m
Instance ID:   \033[1;33m${aws_instance.control_plane.id}\033[0m
Public IP:     \033[1;33m${aws_instance.control_plane.public_ip}\033[0m
Private IP:    \033[1;33m${aws_instance.control_plane.private_ip}\033[0m
SSH Command:   \033[1;35mssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip}\033[0m
EOT
}

# =============================================================================
# 🛡️ KUBERNETES ACCESS OUTPUTS  
# =============================================================================

#OUTPUT - Kubernetes API access details
output "kubernetes_api_endpoint" {
  description = "Kubernetes API server endpoint" #OUTPUT
  value = "https://${aws_instance.control_plane.public_ip}:6443"
}

output "kubeconfig_path_control_plane" {
  description = "Path to the kubeconfig file on the control plane node" #OUTPUT
  value       = "/root/.kube/config"
}

output "kubeconfig_filename" {
  description = "Local kubeconfig file path" #OUTPUT
  value       = "${path.module}/../../kubeconfig.yaml"
}

#OUTPUT - Enhanced Kubernetes access information with visual formatting
output "kubernetes_access" {
  description = "Enhanced Kubernetes API access details with visual formatting" #UX
  value = <<EOT
\033[1;36m🛡️ Kubernetes Access\033[0m
\033[1;36m====================\033[0m
API Endpoint: \033[1;34mhttps://${aws_instance.control_plane.public_ip}:6443\033[0m
Kubeconfig:   \033[1;33m${path.module}/../../kubeconfig.yaml\033[0m

\033[1;32m✅ Quick start commands:\033[0m
  export KUBECONFIG=${path.module}/../../kubeconfig.yaml
  kubectl get nodes
  kubectl cluster-info
EOT
}

# =============================================================================
# 🔐 CERTIFICATE OUTPUTS (Secure)
# =============================================================================

output "cluster_ca_certificate" {
  description = "Base64 encoded public certificate authority data for the cluster" #OUTPUT
  value       = fileexists("${path.module}/certs/ca.crt") ? base64encode(file("${path.module}/certs/ca.crt")) : ""
  sensitive   = true
}

output "client_certificate" {
  description = "Base64 encoded client certificate for authentication" #OUTPUT
  value       = fileexists("${path.module}/certs/client.crt") ? base64encode(file("${path.module}/certs/client.crt")) : ""
  sensitive   = true
}

output "client_key" {
  description = "Base64 encoded client key for authentication" #OUTPUT
  value       = fileexists("${path.module}/certs/client.key") ? base64encode(file("${path.module}/certs/client.key")) : ""
  sensitive   = true
}

output "client_certificate_data" {
  description = "Base64 encoded client certificate for authentication (for kubeconfig)" #OUTPUT
  value       = fileexists("${path.module}/certs/client.crt") ? base64encode(file("${path.module}/certs/client.crt")) : ""
}

output "client_key_data" {
  description = "Base64 encoded client key for authentication (for kubeconfig)" #OUTPUT
  value       = fileexists("${path.module}/certs/client.key") ? base64encode(file("${path.module}/certs/client.key")) : ""
}

# =============================================================================
# 🤖 WORKER NODE OUTPUTS
# =============================================================================

#OUTPUT - Worker node infrastructure details
output "worker_asg_name" {
  description = "Name of the Auto Scaling Group for worker nodes" #OUTPUT
  value       = aws_autoscaling_group.worker_asg.name
}

output "worker_launch_template_id" {
  description = "ID of the worker node launch template" #OUTPUT
  value = aws_launch_template.worker_lt.id
}

#OUTPUT - Enhanced worker nodes information with visual formatting
output "worker_nodes_info" {
  description = "Enhanced worker node management information with visual formatting" #UX
  value = <<EOT
\033[1;36m🤖 Worker Nodes\033[0m
\033[1;36m===============\033[0m
ASG Name:      \033[1;33m${aws_autoscaling_group.worker_asg.name}\033[0m
Launch Template: \033[1;33m${aws_launch_template.worker_lt.id}\033[0m
SSH Access:    \033[1;35mssh -i ${local.actual_key_name}.pem ubuntu@WORKER_PUBLIC_IP\033[0m

\033[1;32m🔍 Discovery command:\033[0m
\033[1;35maws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=guy-worker-node*" --output table\033[0m
EOT
}

# =============================================================================
# 🌐 LOAD BALANCER OUTPUTS
# =============================================================================

#OUTPUT - Load balancer details
output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer" #OUTPUT
  value       = aws_lb.polybot_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer" #OUTPUT
  value       = aws_lb.polybot_alb.zone_id
}

#OUTPUT - Enhanced network resources information with visual formatting
output "network_resources" {
  description = "Enhanced network resources information with visual formatting" #UX
  value = <<EOT
\033[1;36m🌐 Network Resources\033[0m
\033[1;36m===================\033[0m
VPC ID:        \033[1;33m${module.vpc.vpc_id}\033[0m
ALB DNS Name:  \033[1;34m${aws_lb.polybot_alb.dns_name}\033[0m
ALB Zone ID:   \033[1;33m${aws_lb.polybot_alb.zone_id}\033[0m

\033[1;32m🔗 Access your applications:\033[0m
  HTTP:  \033[1;34mhttp://${aws_lb.polybot_alb.dns_name}\033[0m
  HTTPS: \033[1;34mhttps://${aws_lb.polybot_alb.dns_name}\033[0m
EOT
}

# =============================================================================
# 🔑 IAM AND SECURITY OUTPUTS
# =============================================================================

#OUTPUT - Control plane IAM details
output "control_plane_iam_role_arn" {
  description = "ARN of the IAM role for the control plane node" #OUTPUT
  value       = aws_iam_role.control_plane_role.arn
}

output "control_plane_instance" {
  description = "Control plane EC2 instance resource" #OUTPUT
  value       = aws_instance.control_plane
}

# =============================================================================
# 🔐 SSH ACCESS OUTPUTS
# =============================================================================

#OUTPUT - SSH key information
output "ssh_key_name" {
  description = "Name of the SSH key pair" #OUTPUT
  value = local.actual_key_name
}

output "ssh_private_key_path" {
  description = "Path to the SSH private key" #OUTPUT
  value = var.key_name == "" ? local_file.private_key[0].filename : "Using your provided key: ${var.key_name}"
}

#OUTPUT - Enhanced SSH commands with visual formatting
output "ssh_command_control_plane" {
  description = "Enhanced SSH command for control plane access" #UX
  value = "ssh -i ${var.key_name != "" ? var.key_name : local_file.private_key[0].filename} ubuntu@${aws_instance.control_plane.public_ip}"
}

output "ssh_command_worker_nodes" {
  description = "Enhanced SSH command template for worker node access" #UX
  value = "ssh -i ${var.key_name != "" ? var.key_name : local_file.private_key[0].filename} ubuntu@WORKER_PUBLIC_IP"
}

# =============================================================================
# 🔍 TROUBLESHOOTING OUTPUTS
# =============================================================================

#OUTPUT - Worker node discovery command
output "worker_node_info" {
  description = "Command to discover worker node information" #OUTPUT
  value = "aws ec2 describe-instances --region ${var.region} --filters \"Name=tag:Name,Values=guy-worker-node*\" --query \"Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}\" --output table"
}

#OUTPUT - Enhanced debugging commands with visual formatting
output "debugging_commands" {
  description = "Enhanced debugging commands with visual formatting" #UX
  value = <<EOT
\033[1;31m🔍 Debugging Tools\033[0m
\033[1;31m==================\033[0m
\033[1;36m📋 Check logs:\033[0m      \033[1;35maws s3 ls s3://guy-polybot-logs/ | grep worker-init | sort -r | head -5\033[0m
\033[1;36m📄 View log file:\033[0m   \033[1;35maws s3 cp s3://guy-polybot-logs/LOGFILENAME -\033[0m
\033[1;36m⚙️ Check ASG:\033[0m       \033[1;35maws autoscaling describe-auto-scaling-groups --name ${aws_autoscaling_group.worker_asg.name}\033[0m
\033[1;36m🔄 Refresh tokens:\033[0m  \033[1;35mssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip} "sudo /usr/local/bin/refresh-join-token.sh"\033[0m
\033[1;36m🏥 Check kubelet:\033[0m   \033[1;35mssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip} "sudo systemctl status kubelet"\033[0m
EOT
}

#OUTPUT - Worker logs and monitoring
output "worker_logs_command" {
  description = "Command to check worker initialization logs" #OUTPUT
  value = "aws s3 ls s3://guy-polybot-logs/ --region ${var.region} | grep worker-init"
}

output "worker_logs_bucket" {
  description = "S3 bucket name for worker logs" #OUTPUT
  value = aws_s3_bucket.worker_logs.bucket
}

output "troubleshoot_worker_init" {
  description = "Command to troubleshoot worker initialization" #OUTPUT
  value = "aws s3 ls s3://guy-polybot-logs/ --region ${var.region} | grep worker-init | sort -r | head -5"
}

output "rotate_join_token" {
  description = "Command to rotate Kubernetes join token" #OUTPUT
  value = "ssh -i ${var.key_name != "" ? var.key_name : local_file.private_key[0].filename} ubuntu@${aws_instance.control_plane.public_ip} \"sudo systemctl start k8s-token-creator.service\""
}

# =============================================================================
# 📊 MONITORING AND VALIDATION OUTPUTS
# =============================================================================

#OUTPUT - Cluster validation commands
output "check_asg" {
  description = "Command to check Auto Scaling Group status" #OUTPUT
  value = "aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name ${aws_autoscaling_group.worker_asg.name}"
}

output "list_instances" {
  description = "Command to list all cluster instances" #OUTPUT
  value = "aws ec2 describe-instances --filters Name=tag:kubernetes.io/cluster/${var.cluster_name},Values=owned"
}

# =============================================================================
# 🔐 SECRETS MANAGEMENT OUTPUTS
# =============================================================================

#OUTPUT - Secrets Manager information
output "kubernetes_join_command_secrets" {
  description = "Secrets Manager secret names for join commands" #OUTPUT
  value = {
    main_secret = aws_secretsmanager_secret.kubernetes_join_command.name
    latest_secret = aws_secretsmanager_secret.kubernetes_join_command_latest.name
  }
}

# =============================================================================
# 📋 SCRIPT HASHES AND VERSIONING
# =============================================================================

output "control_plane_script_hash" {
  description = "Hash of the control plane user data script" #OUTPUT
  value       = terraform_data.control_plane_script_hash.id
}

# =============================================================================
# 🎯 DEPLOYMENT SUMMARY OUTPUT
# =============================================================================

#UX - Comprehensive deployment summary with visual formatting
output "deployment_summary" {
  description = "Comprehensive deployment summary with enhanced visual formatting" #UX
  value = <<EOT
\033[1;32m🎉 Kubernetes Cluster Deployment Summary\033[0m
\033[1;32m========================================\033[0m

\033[1;36m🏗️ Infrastructure:\033[0m
  VPC ID:        \033[1;33m${module.vpc.vpc_id}\033[0m
  Region:        \033[1;33m${var.region}\033[0m
  Cluster Name:  \033[1;33m${var.cluster_name}\033[0m

\033[1;36m🖥️ Control Plane:\033[0m
  Instance ID:   \033[1;33m${aws_instance.control_plane.id}\033[0m
  Public IP:     \033[1;33m${aws_instance.control_plane.public_ip}\033[0m
  API Endpoint:  \033[1;34mhttps://${aws_instance.control_plane.public_ip}:6443\033[0m

\033[1;36m🤖 Worker Nodes:\033[0m
  ASG Name:      \033[1;33m${aws_autoscaling_group.worker_asg.name}\033[0m
  Launch Template: \033[1;33m${aws_launch_template.worker_lt.id}\033[0m

\033[1;36m🌐 Load Balancer:\033[0m
  DNS Name:      \033[1;34m${aws_lb.polybot_alb.dns_name}\033[0m

\033[1;36m🔑 Access:\033[0m
  SSH Key:       \033[1;33m${local.actual_key_name}\033[0m
  Kubeconfig:    \033[1;33m${path.module}/../../kubeconfig.yaml\033[0m

\033[1;32m✅ Cluster is ready for use!\033[0m
EOT
}

# =============================================================================
# 🚀 QUICK START COMMANDS OUTPUT
# =============================================================================

#UX - Quick start commands with visual formatting
output "quick_start_commands" {
  description = "Quick start commands for immediate cluster use" #UX
  value = <<EOT
\033[1;35m🚀 Quick Start Commands\033[0m
\033[1;35m======================\033[0m

\033[1;36m1️⃣ Set kubeconfig:\033[0m
   \033[1;33mexport KUBECONFIG=${path.module}/../../kubeconfig.yaml\033[0m

\033[1;36m2️⃣ Verify cluster:\033[0m
   \033[1;33mkubectl get nodes\033[0m
   \033[1;33mkubectl cluster-info\033[0m

\033[1;36m3️⃣ Deploy test app:\033[0m
   \033[1;33mkubectl create deployment nginx --image=nginx\033[0m
   \033[1;33mkubectl expose deployment nginx --port=80 --type=NodePort\033[0m

\033[1;36m4️⃣ SSH to control plane:\033[0m
   \033[1;35mssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip}\033[0m

\033[1;32m🎯 Your cluster is ready to use!\033[0m
EOT
}

# =============================================================================
# 🔧 ADVANCED DEBUGGING OUTPUTS
# =============================================================================

#OUTPUT - Advanced debugging and maintenance commands
output "refresh_join_token_command" {
  description = "Command to refresh join token on control plane" #OUTPUT
  value = "sudo /usr/local/bin/refresh-join-token.sh"
}

output "ssh_debug_command" {
  description = "SSH debug command template for worker nodes" #OUTPUT
  value = "ssh -o StrictHostKeyChecking=no -vvv ubuntu@WORKER_IP_ADDRESS"
}

output "worker_logs_check" {
  description = "Command to check worker logs in S3" #OUTPUT
  value = "aws s3 ls s3://guy-polybot-logs/ | grep worker-init | sort -r | head -5"
}

output "view_worker_log" {
  description = "Command to view specific worker log file" #OUTPUT
  value = "aws s3 cp s3://guy-polybot-logs/LOGFILENAME -"
}

# =============================================================================
# 📍 LEGACY COMPATIBILITY OUTPUTS
# =============================================================================

#OUTPUT - Legacy outputs maintained for backward compatibility
output "init_logs_commands" {
  description = "Commands to check initialization logs (legacy compatibility)" #OUTPUT
  value = {
    control_plane = "ssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip} 'cat /var/log/k8s-control-plane-init.log'"
    worker_s3_logs = "aws s3 ls s3://guy-polybot-logs/ --region ${var.region} | grep worker-init"
  }
}

output "control_plane_ip" {
  description = "Control plane public IP (legacy compatibility)" #OUTPUT
  value = aws_instance.control_plane.public_ip
}

output "kubeconfig_path" {
  description = "Local kubeconfig file path (legacy compatibility)" #OUTPUT
  value = "${path.module}/../../kubeconfig.yaml"
}