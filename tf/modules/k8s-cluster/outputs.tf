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

output "kubernetes_api_endpoint" {
  value = "https://${aws_instance.control_plane.public_ip}:6443"
}

output "kubeconfig_filename" {
  value = local_file.kubeconfig.filename
}

output "ssh_key_name" {
  value = local.actual_key_name
}

output "ssh_private_key_path" {
  value = var.key_name == "" ? local_file.private_key[0].filename : "Using your provided key: ${var.key_name}"
}

output "worker_asg_name" {
  description = "Name of the Auto Scaling Group for worker nodes"
  value       = aws_autoscaling_group.worker_asg.name
}

output "worker_launch_template_id" {
  value = aws_launch_template.worker_lt.id
}

output "ssh_command_control_plane" {
  value = "ssh -i ${var.key_name != "" ? var.key_name : local_file.private_key[0].filename} ubuntu@${aws_instance.control_plane.public_ip}"
}

output "worker_node_info" {
  value = "To get worker node IPs: aws ec2 describe-instances --region ${var.region} --filters \"Name=tag:Name,Values=guy-worker-node*\" --query \"Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}\" --output table"
}

output "worker_logs_command" {
  value = "aws s3 ls s3://guy-polybot-logs/ --region ${var.region} | grep worker-init"
}

output "ssh_command_worker_nodes" {
  value = "SSH to worker nodes using: ssh -i ${var.key_name != "" ? var.key_name : local_file.private_key[0].filename} ubuntu@WORKER_PUBLIC_IP (replace WORKER_PUBLIC_IP with values from the worker_node_info command)"
}

output "troubleshoot_worker_init" {
  value = "To check worker initialization logs: aws s3 ls s3://guy-polybot-logs/ --region ${var.region} | grep worker-init | sort -r | head -5"
}

output "rotate_join_token" {
  value = "If workers can't join, try: ssh -i ${var.key_name != "" ? var.key_name : local_file.private_key[0].filename} ubuntu@${aws_instance.control_plane.public_ip} and run sudo systemctl start k8s-token-creator.service"
}

output "control_plane_id" {
  description = "Instance ID of the Kubernetes control plane"
  value       = aws_instance.control_plane.id
}

output "control_plane_script_hash" {
  description = "Hash of the control plane user data script"
  value       = terraform_data.control_plane_script_hash.id
}

output "worker_script_hash" {
  description = "Hash of the worker user data script"
  value       = terraform_data.worker_script_hash.id
}

output "refresh_join_token_command" {
  value = "sudo /usr/local/bin/refresh-join-token.sh"
}

output "ssh_debug_command" {
  value = "ssh -o StrictHostKeyChecking=no -vvv ubuntu@WORKER_IP_ADDRESS"
}

output "worker_logs_check" {
  value = "aws s3 ls s3://guy-polybot-logs/ | grep worker-init | sort -r | head -5"
}

output "view_worker_log" {
  value = "aws s3 cp s3://guy-polybot-logs/LOGFILENAME -"
}

output "check_asg" {
  value = "aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name guy-polybot-asg"
}

output "list_instances" {
  value = "aws ec2 describe-instances --filters Name=tag:kubernetes.io/cluster/kubernetes,Values=owned"
}

output "control_plane_info" {
  description = "Control plane information including SSH access"
  value = "📡 Control Plane\n------------------------------\nInstance ID:   ${aws_instance.control_plane.id}\nPublic IP:     ${aws_instance.control_plane.public_ip}\nPrivate IP:    ${aws_instance.control_plane.private_ip}\nSSH Command:   ssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip}"
}

output "kubernetes_access" {
  description = "Kubernetes API access details"
  value = "🛡️ Kubernetes Access\n------------------------------\nAPI Endpoint: https://${aws_instance.control_plane.public_ip}:6443\nKubeconfig:   ${local_file.kubeconfig.filename}"
}

output "worker_nodes_info" {
  description = "Worker node management commands"
  value = "🔧 Worker Nodes\n------------------------------\nASG name:      ${aws_autoscaling_group.worker_asg.name}\nSSH access:    ssh -i ${local.actual_key_name}.pem ubuntu@WORKER_PUBLIC_IP\nFind workers:  aws ec2 describe-instances --region ${var.region} --filters \"Name=tag:Name,Values=guy-worker-node*\" --output table"
}

output "debugging_commands" {
  description = "Useful debugging commands"
  value = "🔍 Debugging Tools\n------------------------------\nCheck logs:      aws s3 ls s3://guy-polybot-logs/ | grep worker-init | sort -r | head -5\nView log file:   aws s3 cp s3://guy-polybot-logs/LOGFILENAME -\nCheck ASG:       aws autoscaling describe-auto-scaling-groups --name guy-polybot-asg\nRefresh tokens:  ssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip} \"sudo /usr/local/bin/refresh-join-token.sh\""
}

output "network_resources" {
  description = "Network resources information"
  value = "🌐 Network Resources\n------------------------------\nVPC ID:        ${module.vpc.vpc_id}\nALB DNS name:  ${aws_lb.polybot_alb.dns_name}\nALB Zone ID:   ${aws_lb.polybot_alb.zone_id}"
}

output "deployment_summary" {
  description = "Summary of the deployed infrastructure"
  value = <<-EOT
    
    ========================================================
    🎉 KUBERNETES CLUSTER DEPLOYMENT COMPLETE! 🎉
    ========================================================
    
    🧠 DEPLOYMENT SUMMARY:
    
    🟢 Control Plane:
       • Public IP: ${aws_instance.control_plane.public_ip}
       • Instance ID: ${aws_instance.control_plane.id}
       • SSH Command: ssh -i <your-key.pem> ubuntu@${aws_instance.control_plane.public_ip}
    
    📦 Worker Node(s):
       • Count: ${var.worker_count}
       • Auto Scaling Group: ${aws_autoscaling_group.worker_asg.name}
       • Instance Type: ${var.worker_instance_type}
    
    🔐 Kubeconfig:
       • Path: ${local_file.kubeconfig.filename}
       • Usage: export KUBECONFIG=${local_file.kubeconfig.filename}
    
    🌐 Load Balancer:
       • DNS Name: ${aws_lb.polybot_alb.dns_name}
       • ARN: ${aws_lb.polybot_alb.arn}
    
    📚 USEFUL COMMANDS:
    
    • Check cluster status:
      kubectl --kubeconfig=${local_file.kubeconfig.filename} get nodes
    
    • View all pods:
      kubectl --kubeconfig=${local_file.kubeconfig.filename} get pods -A
    
    • View control plane logs:
      ssh -i <your-key.pem> ubuntu@${aws_instance.control_plane.public_ip} "cat /var/log/k8s-control-plane-init.log"
    
    • View worker logs in S3:
      aws s3 ls s3://${aws_s3_bucket.worker_logs.id}/ | grep worker-init
    
    ========================================================
  EOT
}

output "init_logs_commands" {
  description = "Commands to view initialization logs on control plane and worker nodes"
  value = <<-EOT
    # Control Plane Init Log
    ssh -i ${local.actual_key_name}.pem ubuntu@${aws_instance.control_plane.public_ip} 'cat /home/ubuntu/init_summary.log'
    
    # Worker Nodes: Get worker IPs with the command below, then view logs:
    # aws ec2 describe-instances --region ${var.region} --filters "Name=tag:Name,Values=${aws_autoscaling_group.worker_asg.name}*" "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,PublicIP:PublicIpAddress}" --output table
    # Then for each worker:
    # ssh -i ${local.actual_key_name}.pem ubuntu@WORKER_PUBLIC_IP 'cat /home/ubuntu/init_summary.log'
  EOT
}

output "control_plane_ip" {
  description = "Public IP address of the Kubernetes control plane"
  value       = aws_instance.control_plane.public_ip
}

output "worker_logs_bucket" {
  description = "S3 bucket for worker logs"
  value       = aws_s3_bucket.worker_logs.bucket
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.polybot_alb.dns_name
}

output "kubernetes_join_command_secrets" {
  description = "Secret names containing the Kubernetes join command"
  value = [
    aws_secretsmanager_secret.kubernetes_join_command.name,
    aws_secretsmanager_secret.kubernetes_join_command_latest.name
  ]
}

output "kubeconfig_path" {
  description = "Path to the kubeconfig file"
  value       = "${path.module}/kubeconfig"
}