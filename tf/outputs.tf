# CYCLE-FREE OUTPUTS - Refactored to eliminate dependency cycles
# 
# Key Changes:
# 1. Removed all file() reads from /tmp/ files in output blocks
# 2. Eliminated null_resources that exist solely for output generation
# 3. Moved informational display to console output during apply
# 4. Kept only essential, static outputs that don't create cycles

# ------------------------------------------------------------------------
# Section 1: Essential Static Outputs (No Cycles)
# ------------------------------------------------------------------------

# Basic module outputs - these are safe because they're direct module references
output "control_plane_ip" {
  description = "Public IP address of the Kubernetes control plane"
  value       = module.k8s-cluster.control_plane_public_ip
}

output "control_plane_id" {
  description = "Instance ID of the Kubernetes control plane"
  value       = module.k8s-cluster.control_plane_instance_id
}

output "worker_asg_name" {
  description = "Name of the Auto Scaling Group for worker nodes"
  value       = module.k8s-cluster.worker_asg_name
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = module.k8s-cluster.alb_dns_name
}

output "vpc_id" {
  description = "VPC ID where cluster is deployed"
  value       = module.k8s-cluster.vpc_id
}

output "ssh_key_name" {
  description = "SSH key name for cluster access"
  value       = module.k8s-cluster.ssh_key_name
}

# ------------------------------------------------------------------------
# Section 2: Simple Cluster Information (No File Dependencies)
# ------------------------------------------------------------------------

output "cluster_info" {
  description = "Basic cluster information"
  value = {
    region              = var.region
    control_plane_ip    = module.k8s-cluster.control_plane_public_ip
    control_plane_id    = module.k8s-cluster.control_plane_instance_id
    api_endpoint        = "https://${module.k8s-cluster.control_plane_public_ip}:6443"
    kubeconfig_path     = local.kubeconfig_path
  }
}

output "cluster_readiness" {
  description = "Information about cluster readiness (cycle-safe)"
  value = {
    kubeconfig_exists = fileexists(local.kubeconfig_path)
    # SAFE: Only reference resource ID, not complex chains
    ebs_csi_ready     = try(null_resource.install_ebs_csi_driver.id != "", false)
  }
}

# ------------------------------------------------------------------------
# Section 3: Access Commands (Static Templates)
# ------------------------------------------------------------------------

output "ssh_commands" {
  description = "SSH commands for cluster access"
  value = {
    control_plane = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}"
    # Template for workers - user needs to replace IP
    worker_template = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@WORKER_IP"
  }
}

output "kubectl_setup" {
  description = "Commands to set up kubectl access"
  value = {
    copy_kubeconfig = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat ~/.kube/config' > kubeconfig.yaml"
    set_kubeconfig  = "export KUBECONFIG=./kubeconfig.yaml"
    test_cluster    = "kubectl get nodes"
  }
}

# ------------------------------------------------------------------------
# Section 4: ArgoCD Information (Simplified)
# ------------------------------------------------------------------------

output "argocd_access" {
  description = "ArgoCD access information"
  value = {
    url                = "https://localhost:8081"
    username          = "admin"
    password_command  = "kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
    port_forward_help = "Run kubectl port-forward svc/argocd-server -n argocd 8081:443"
  }
}

# ------------------------------------------------------------------------
# Section 5: AWS Resources
# ------------------------------------------------------------------------

output "aws_resources" {
  description = "AWS resources created"
  value = {
    vpc_id         = module.k8s-cluster.vpc_id
    public_subnets = module.k8s-cluster.public_subnet_ids
    ssh_key        = module.k8s-cluster.ssh_key_name
    alb_dns        = module.k8s-cluster.alb_dns_name
  }
}

# ------------------------------------------------------------------------
# Section 6: Troubleshooting Commands (Static)
# ------------------------------------------------------------------------

output "troubleshooting" {
  description = "Commands for troubleshooting"
  value = {
    check_control_plane = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'kubectl get nodes'"
    check_worker_logs   = "aws s3 ls s3://guy-polybot-logs/ --recursive | grep worker-init"
    check_asg_instances = "aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names ${module.k8s-cluster.worker_asg_name} --region ${var.region}"
    view_init_logs      = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'sudo cat /var/log/k8s-init.log'"
  }
}

# ------------------------------------------------------------------------
# Section 7: Quick Start Guide (Static)
# ------------------------------------------------------------------------

output "quick_start" {
  description = "Quick start commands"
  value = <<-EOT
    1. Copy kubeconfig:
       ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat ~/.kube/config' > kubeconfig.yaml
    
    2. Set kubeconfig:
       export KUBECONFIG=./kubeconfig.yaml
    
    3. Verify cluster:
       kubectl get nodes
    
    4. Access ArgoCD:
       kubectl port-forward svc/argocd-server -n argocd 8081:443
       # Then visit https://localhost:8081
       # Username: admin
       # Password: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
  EOT
}

# ------------------------------------------------------------------------
# REMOVED RESOURCES - These caused cycles and have been eliminated:
# ------------------------------------------------------------------------
# ❌ null_resource.worker_node_details
# ❌ null_resource.argocd_password_retriever  
# ❌ null_resource.dynamic_worker_logs
# ❌ null_resource.format_outputs
# ❌ All outputs that used file() on /tmp/ files
# ❌ Complex locals that read from temporary files

# ------------------------------------------------------------------------
# INFORMATION DISPLAY STRATEGY
# ------------------------------------------------------------------------
# Instead of complex outputs, informational display is now handled by:
# 1. Enhanced null_resource.deployment_summary (console output during apply)
# 2. Static output templates above
# 3. Troubleshooting commands that users can run manually
# 
# This eliminates cycles while still providing all necessary information
# to users through console output during terraform apply