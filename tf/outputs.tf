# ENHANCED OUTPUTS - Comprehensive cluster information
# 
# Provides organized, informative outputs with actual values where possible
# Includes worker node information, ArgoCD details, and comprehensive cluster status

# ------------------------------------------------------------------------
# Section 1: 🏗️ INFRASTRUCTURE OVERVIEW
# ------------------------------------------------------------------------

output "cluster_overview" {
  description = "🏗️ Complete cluster infrastructure overview"
  value = {
    "🌍 Region" = var.region
    "🏷️ Cluster Name" = local.cluster_name
    "🌐 VPC ID" = module.k8s-cluster.vpc_id
    "🌎 Domain" = var.domain_name
    "📁 Kubeconfig Location" = local.kubeconfig_path
  }
}

output "control_plane_info" {
  description = "🖥️ Control plane detailed information"
  value = {
    "📍 Instance ID" = module.k8s-cluster.control_plane_instance_id
    "🌐 Public IP" = module.k8s-cluster.control_plane_public_ip
    "🔒 Private IP" = module.k8s-cluster.control_plane_private_ip
    "🔗 API Endpoint" = "https://${module.k8s-cluster.control_plane_public_ip}:6443"
    "🔑 SSH Key" = module.k8s-cluster.ssh_key_name
    "💻 SSH Command" = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}"
  }
}

output "worker_nodes_info" {
  description = "🤖 Worker nodes and Auto Scaling information"
  value = {
    "🤖 ASG Name" = module.k8s-cluster.worker_asg_name
    "🚀 Launch Template" = module.k8s-cluster.worker_launch_template_id
    "📊 Desired Workers" = var.desired_worker_nodes
    "🔍 Discovery Command" = "aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names ${module.k8s-cluster.worker_asg_name} --region ${var.region} --query 'AutoScalingGroups[0].{Desired:DesiredCapacity,Min:MinSize,Max:MaxSize,Current:length(Instances)}' --output table"
    "📋 List Workers" = "aws ec2 describe-instances --region ${var.region} --filters 'Name=tag:aws:autoscaling:groupName,Values=${module.k8s-cluster.worker_asg_name}' 'Name=instance-state-name,Values=running' --query 'Reservations[*].Instances[*].{Name:Tags[?Key==`Name`]|[0].Value,InstanceId:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}' --output table"
  }
}

output "network_resources" {
  description = "🌐 Network and load balancing information"
  value = {
    "⚖️ ALB DNS Name" = module.k8s-cluster.alb_dns_name
    "🌐 ALB Zone ID" = module.k8s-cluster.alb_zone_id
    "🔗 Application URL" = "https://${var.domain_name}"
    "🏠 Public Subnets" = module.k8s-cluster.public_subnet_ids
    "🔒 Private Subnets" = module.k8s-cluster.private_subnet_ids
  }
}

# ------------------------------------------------------------------------
# Section 2: ☸️ KUBERNETES CLUSTER STATUS
# ------------------------------------------------------------------------

output "kubernetes_access" {
  description = "☸️ Kubernetes cluster access information"
  value = {
    "📁 Kubeconfig Path" = local.kubeconfig_path
    "✅ Kubeconfig Exists" = fileexists(local.kubeconfig_path)
    "🔐 Kubeconfig Secret" = module.k8s-cluster.kubeconfig_secret_name_output
    "🎫 Join Command Secret" = module.k8s-cluster.kubernetes_join_command_secrets.latest_secret
    "💻 Quick Setup" = "export KUBECONFIG=${local.kubeconfig_path} && kubectl get nodes"
  }
}

output "cluster_commands" {
  description = "🛠️ Essential cluster management commands"
  value = {
    "📊 Check Nodes" = "kubectl --kubeconfig=${local.kubeconfig_path} get nodes -o wide"
    "🔍 Check Pods" = "kubectl --kubeconfig=${local.kubeconfig_path} get pods --all-namespaces"
    "🏥 Cluster Health" = "kubectl --kubeconfig=${local.kubeconfig_path} get componentstatuses"
    "📋 Cluster Info" = "kubectl --kubeconfig=${local.kubeconfig_path} cluster-info"
  }
}

# ------------------------------------------------------------------------
# Section 3: 🚀 ARGOCD GITOPS PLATFORM
# ------------------------------------------------------------------------

output "argocd_complete_access" {
  description = "🚀 Complete ArgoCD access and management information"
  value = {
    "🌐 Access URL" = "https://localhost:8080"
    "👤 Username" = "admin"
    "🔑 Password Retrieval" = "kubectl --kubeconfig=${local.kubeconfig_path} -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || echo 'Secret not found or changed'"
    "🔗 Port Forward Command" = "kubectl --kubeconfig=${local.kubeconfig_path} port-forward svc/argocd-server -n argocd 8080:443"
    "📱 Applications Check" = "kubectl --kubeconfig=${local.kubeconfig_path} get applications -n argocd"
    "🔍 Controller Logs" = "kubectl --kubeconfig=${local.kubeconfig_path} logs -n argocd -l app.kubernetes.io/name=argocd-application-controller -f"
    "🎯 Expected Apps" = ["mongodb", "polybot", "yolo5"]
  }
}

# ------------------------------------------------------------------------
# Section 4: 🔧 AWS RESOURCES & INFRASTRUCTURE
# ------------------------------------------------------------------------

output "aws_infrastructure" {
  description = "🔧 AWS resources and infrastructure details"
  value = {
    "🏗️ Core Infrastructure" = {
      "Region" = var.region
      "VPC ID" = module.k8s-cluster.vpc_id
      "Public Subnets" = length(module.k8s-cluster.public_subnet_ids)
      "Private Subnets" = length(module.k8s-cluster.private_subnet_ids)
    }
    "🖥️ Compute Resources" = {
      "Control Plane Instance" = module.k8s-cluster.control_plane_instance_id
      "Worker ASG" = module.k8s-cluster.worker_asg_name
      "Launch Template" = module.k8s-cluster.worker_launch_template_id
      "Desired Workers" = var.desired_worker_nodes
    }
    "🔐 Security & Access" = {
      "SSH Key Name" = module.k8s-cluster.ssh_key_name
      "Control Plane IAM Role" = module.k8s-cluster.control_plane_iam_role_arn
    }
    "💾 Storage & Logs" = {
      "Worker Logs Bucket" = module.k8s-cluster.worker_logs_bucket
    }
  }
}

# ------------------------------------------------------------------------
# Section 5: 🛠️ QUICK START & TROUBLESHOOTING
# ------------------------------------------------------------------------

output "quick_start_guide" {
  description = "🛠️ Complete quick start guide"
  value = <<-EOT
🎉 POLYBOT KUBERNETES CLUSTER READY! 🎉

📋 QUICK START STEPS:
╭────────────────────────────────────────────────────────────────╮
│ 1️⃣ SET UP KUBECTL ACCESS:                                       │
│    export KUBECONFIG=${local.kubeconfig_path}                   │
│    kubectl get nodes                                            │
│                                                                │
│ 2️⃣ ACCESS ARGOCD UI:                                            │
│    kubectl port-forward svc/argocd-server -n argocd 8080:443   │
│    Open: https://localhost:8080                                │
│    Username: admin                                             │
│    Password: kubectl get secret argocd-initial-admin-secret    │
│             -n argocd -o jsonpath='{.data.password}' | base64 -d│
│                                                                │
│ 3️⃣ SSH TO CONTROL PLANE:                                        │
│    ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}                │
│                                                                │
│ 4️⃣ CHECK CLUSTER STATUS:                                        │
│    kubectl get pods --all-namespaces                          │
│    kubectl get applications -n argocd                         │
╰────────────────────────────────────────────────────────────────╯

🔍 TROUBLESHOOTING:
• Logs: kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller
• Workers: aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names ${module.k8s-cluster.worker_asg_name}
• Health: kubectl get componentstatuses
EOT
}

# ------------------------------------------------------------------------
# Section 6: 🎯 NEXT STEPS
# ------------------------------------------------------------------------

output "next_steps" {
  description = "🎯 Recommended next steps"
  value = {
    "immediate_actions" = [
      "🔗 Access ArgoCD UI using the port-forward command above",
      "🔍 Verify applications are syncing properly in ArgoCD",
      "🚀 Deploy additional applications via ArgoCD or kubectl",
      "📊 Monitor cluster health and application status"
    ]
    "monitoring_setup" = [
      "🔧 Configure monitoring and logging as needed",
      "📈 Set up alerts for cluster health",
      "💾 Configure backup strategies"
    ]
    "security_hardening" = [
      "🔒 Review and harden security settings",
      "🛡️ Implement network policies",
      "🔐 Rotate default passwords and secrets"
    ]
  }
}

# Legacy outputs (kept for compatibility)
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

# Remove or simplify these old outputs
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
  description = "Information about cluster readiness"
  value = {
    kubeconfig_exists = fileexists(local.kubeconfig_path)
  }
}

output "argocd_access" {
  description = "ArgoCD access information"
  value = {
    url                = "https://localhost:8080"
    username          = "admin"
    password_command  = "kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
    port_forward_help = "kubectl port-forward svc/argocd-server -n argocd 8080:443"
  }
}

output "aws_resources" {
  description = "AWS resources created"
  sensitive   = true
  value = {
    vpc_id         = module.k8s-cluster.vpc_id
    public_subnets = module.k8s-cluster.public_subnet_ids
    ssh_key        = module.k8s-cluster.ssh_key_name
    alb_dns        = module.k8s-cluster.alb_dns_name
  }
}

output "ssh_commands" {
  description = "SSH commands for cluster access"
  sensitive   = true
  value = {
    control_plane = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}"
    worker_template = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@WORKER_IP"
  }
}

output "kubectl_setup" {
  description = "Commands to set up kubectl access"
  sensitive   = true
  value = {
    copy_kubeconfig = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat ~/.kube/config' > kubeconfig.yaml"
    set_kubeconfig  = "export KUBECONFIG=./kubeconfig.yaml"
    test_cluster    = "kubectl get nodes"
  }
}

output "troubleshooting" {
  description = "Commands for troubleshooting"
  sensitive   = true
  value = {
    check_control_plane = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'kubectl get nodes'"
    check_worker_logs   = "aws s3 ls s3://guy-polybot-logs/ --recursive | grep worker-init"
    check_asg_instances = "aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names ${module.k8s-cluster.worker_asg_name} --region ${var.region}"
    view_init_logs      = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'sudo cat /var/log/k8s-init.log'"
  }
}

output "quick_start" {
  description = "Quick start commands"
  sensitive   = true
  value = <<-EOT
    1. Copy kubeconfig:
       ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat ~/.kube/config' > kubeconfig.yaml
    
    2. Set kubeconfig:
       export KUBECONFIG=./kubeconfig.yaml
    
    3. Verify cluster:
       kubectl get nodes
    
    4. Access ArgoCD:
       kubectl port-forward svc/argocd-server -n argocd 8080:443
       # Then visit https://localhost:8080
       # Username: admin
       # Password: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
  EOT
}

output "generated_secrets_info" {
  description = "Information about generated secrets and credentials"
  sensitive   = true
  value = {
    ssh_key_generated = var.key_name == "" ? true : false
    ssh_key_location = var.key_name == "" ? "${path.module}/polybot-key.pem" : "Using provided key: ${var.key_name}"
    argocd_password_location = "kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
  }
}