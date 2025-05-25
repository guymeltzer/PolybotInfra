# REORGANIZED OUTPUTS - Structured into logical sections

# ------------------------------------------------------------------------
# Section 1: Kubernetes Infrastructure
# ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Section 2: Control Plane Node Details
# ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Section 3: Worker Node Details
# ------------------------------------------------------------------------

# Dynamically get worker node details (attempts to get them if available)
resource "null_resource" "worker_node_details" {
  triggers = {
    worker_asg_name = module.k8s-cluster.worker_asg_name
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}" \
        --output json > /tmp/worker_nodes.json || echo '[]' > /tmp/worker_nodes.json
      echo "" > /tmp/worker_nodes_formatted.txt
      jq -r '.[][] | "Name: \(.Name)\nInstanceId: \(.InstanceId)\nPrivateIP: \(.PrivateIP)\nPublicIP: \(.PublicIP)\nState: \(.State)\n---"' /tmp/worker_nodes.json > /tmp/worker_nodes_formatted.txt
    EOT
  }
  depends_on = [module.k8s-cluster.aws_autoscaling_group.worker_asg]
}

output "worker_nodes" {
  description = "Worker node details (running instances only)"
  value = fileexists("/tmp/worker_nodes.json") ? (length(file("/tmp/worker_nodes.json")) > 2 ? jsondecode(file("/tmp/worker_nodes.json")) : []) : []
}

output "worker_nodes_formatted" {
  description = "Formatted worker node details for easy reading"
  value = fileexists("/tmp/worker_nodes_formatted.txt") ? file("/tmp/worker_nodes_formatted.txt") : "No worker nodes information available"
}

# ------------------------------------------------------------------------
# Section 4: Kubernetes Access Commands
# ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Section 5: ArgoCD Information
# ------------------------------------------------------------------------

# Resource to retrieve ArgoCD password for output display
resource "null_resource" "argocd_password_retriever" {
  triggers = {
    argocd_install_id = null_resource.install_argocd[0].id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      if [ -f "${local.kubeconfig_path}" ]; then
        PASSWORD=$(KUBECONFIG="${local.kubeconfig_path}" kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d)
        if [ -n "$PASSWORD" ]; then
          echo "$PASSWORD" > /tmp/argocd-admin-password.txt
        else
          echo "Password not available yet. ArgoCD may still be initializing." > /tmp/argocd-admin-password.txt
        fi
      else
        echo "Kubeconfig not found." > /tmp/argocd-admin-password.txt
      fi
      cat > /tmp/argocd-info.txt << 'INFOEOF'
      🔐 ArgoCD Access Information
      ---------------------------
      🌐 URL: https://localhost:8081
      👤 Username: admin
      🔑 Password: $(cat /tmp/argocd-admin-password.txt)
      Note: Port forwarding is managed by ~/argocd-ssh-tunnel.sh
INFOEOF
    EOT
  }
  depends_on = [null_resource.install_argocd, module.k8s-cluster.aws_instance.control_plane]
}

output "argocd_info" {
  description = "Detailed ArgoCD access information"
  value = <<EOT
🔐 ArgoCD Access Information
---------------------------
To access ArgoCD, run the script: ~/argocd-ssh-tunnel.sh

URL: https://localhost:8081 
Username: admin
Password: ${fileexists("/tmp/argocd-admin-password.txt") ? file("/tmp/argocd-admin-password.txt") : "Not available yet. Run: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath=\"{.data.password}\" | base64 -d"}
EOT
}

# ------------------------------------------------------------------------
# Section 6: Polybot Application URLs
# ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Section 7: Polybot AWS Resources
# ------------------------------------------------------------------------

# Development Environment Outputs
# output "polybot_dev_resources" {
#   description = "Development environment resources"
#   value = {
#     s3_bucket   = module.polybot_dev.s3_bucket_name
#     sqs_queue   = module.polybot_dev.sqs_queue_url
#     domain_name = module.polybot_dev.domain_name
#   }
# }

# Production Environment Outputs
# output "polybot_prod_resources" {
#   description = "Production environment resources"
#   value = {
#     s3_bucket   = module.polybot_prod.s3_bucket_name
#     sqs_queue   = module.polybot_prod.sqs_queue_url
#     domain_name = module.polybot_prod.domain_name
#   }
# }

# ------------------------------------------------------------------------
# Section 8: SSH Access Details
# ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Section 9: Troubleshooting Commands
# ------------------------------------------------------------------------

# New dynamic worker logs command that uses actual worker public IPs
resource "null_resource" "dynamic_worker_logs" {
  triggers = {
    worker_asg_name = module.k8s-cluster.worker_asg_name
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      WORKER_DATA=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,PublicIP:PublicIpAddress}" \
        --output json)
      echo "# Dynamic Worker Node Log Commands" > /tmp/worker_log_commands.txt
      echo "# Generated $(date)" >> /tmp/worker_log_commands.txt
      echo "" >> /tmp/worker_log_commands.txt
      for row in $(echo "$WORKER_DATA" | jq -r '.[][] | @base64'); do
        _jq() {
          echo $row | base64 --decode | jq -r $1
        }
        NAME=$(_jq '.Name')
        IP=$(_jq '.PublicIP')
        if [ -n "$IP" ]; then
          echo "# Worker: $NAME" >> /tmp/worker_log_commands.txt
          echo "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@$IP 'cat /home/ubuntu/init_summary.log'" >> /tmp/worker_log_commands.txt
          echo "" >> /tmp/worker_log_commands.txt
        fi
      done
    EOT
  }
  depends_on = [module.k8s-cluster.aws_autoscaling_group.worker_asg]
}

output "dynamic_worker_logs" {
  description = "Commands to view logs on each worker node with actual IPs"
  value = fileexists("/tmp/worker_log_commands.txt") ? file("/tmp/worker_log_commands.txt") : "Worker log commands not available yet"
}

# ------------------------------------------------------------------------
# Section 10: Complete Deployment Output
# ------------------------------------------------------------------------

# Define local values for clean output formatting
locals {
  # Clean, complete deployment info that doesn't show heredoc markers
  deployment_info = fileexists("/tmp/final_output.txt") ? file("/tmp/final_output.txt") : "Deployment information not available yet"
  
  # ArgoCD password for reference
  argocd_password = fileexists("/tmp/argocd-admin-password.txt") ? file("/tmp/argocd-admin-password.txt") : "Not available yet"
}

# Main consolidated output for all deployment information
output "deployment_info" {
  description = "Complete deployment information including access details, node information, and endpoints"
  value = local.deployment_info
}

# Clean ArgoCD access information
output "argocd" {
  description = "ArgoCD access information"
  value = trimspace("URL: https://localhost:8081\nUsername: admin\nPassword: ${local.argocd_password}\nConnect: Run ~/argocd-ssh-tunnel.sh to establish the connection")
}

# Essential cluster information in structured format
output "cluster" {
  description = "Essential cluster information for scripts"
  sensitive = true
  value = {
    api_endpoint = "https://${try(module.k8s-cluster.control_plane_public_ip, "localhost")}:6443"
    control_plane = {
      public_ip = try(module.k8s-cluster.control_plane_public_ip, "")
      ssh = "ssh -i ${try(module.k8s-cluster.ssh_key_name, "key")}.pem ubuntu@${try(module.k8s-cluster.control_plane_public_ip, "localhost")}"
    }
    kubeconfig_cmd = "ssh -i ${try(module.k8s-cluster.ssh_key_name, "key")}.pem ubuntu@${try(module.k8s-cluster.control_plane_public_ip, "localhost")} 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=./kubeconfig.yaml"
    alb_dns = try(module.k8s-cluster.alb_dns_name, "")
  }
}

# Application endpoints
output "endpoints" {
  description = "Application endpoints"
  value = {
    dev = "Not available - polybot_dev module not loaded"
    prod = "Not available - polybot_prod module not loaded"
    argocd = "https://localhost:8081 (Run ~/argocd-ssh-tunnel.sh first)"
  }
}

# AWS resources
output "aws_resources" {
  description = "AWS resources created for the application"
  sensitive = true
  value = {
    vpc_id = module.k8s-cluster.vpc_id
    subnets = module.k8s-cluster.public_subnet_ids
    ssh_key = module.k8s-cluster.ssh_key_name
    # Remove references to polybot_dev and polybot_prod modules
    # Since these modules are no longer available
    /*
    dev = {
      s3_bucket = module.polybot_dev.s3_bucket_name
      sqs_queue = module.polybot_dev.sqs_queue_url
      domain = module.polybot_dev.domain_name
    }
    prod = {
      s3_bucket = module.polybot_prod.s3_bucket_name
      sqs_queue = module.polybot_prod.sqs_queue_url
      domain = module.polybot_prod.domain_name
    }
    */
  }
}

# RESOURCES FOR GENERATING OUTPUT FILES
# These resources don't create outputs directly but generate the files used by outputs

# Resource to format all outputs into a single file
resource "null_resource" "format_outputs" {
  triggers = {
    cluster_id = module.k8s-cluster.control_plane_instance_id
    worker_asg_name = module.k8s-cluster.worker_asg_name
    argocd_install_id = null_resource.install_argocd[0].id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      cat > /tmp/final_output.txt << 'EOF'
      =================================================================
                    POLYBOT KUBERNETES CLUSTER DEPLOYMENT
      =================================================================
      EOF
      echo -e "🔐 ARGOCD ACCESS" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      ARGOCD_PASSWORD=""
      if [ -f "/tmp/argocd-admin-password.txt" ]; then
        ARGOCD_PASSWORD=$(cat /tmp/argocd-admin-password.txt)
      fi
      echo -e "URL: https://localhost:8081" >> /tmp/final_output.txt
      echo -e "Username: admin" >> /tmp/final_output.txt
      echo -e "Password: $ARGOCD_PASSWORD" >> /tmp/final_output.txt
      echo -e "Connection: Run ~/argocd-ssh-tunnel.sh" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      echo -e "🔧 CONTROL PLANE" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      PUBLIC_IP=${module.k8s-cluster.control_plane_public_ip}
      INSTANCE_ID=${module.k8s-cluster.control_plane_instance_id}
      PRIVATE_IP=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=guy-control-plane" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)
      echo -e "Instance ID: $INSTANCE_ID" >> /tmp/final_output.txt
      echo -e "Public IP:   $PUBLIC_IP" >> /tmp/final_output.txt
      echo -e "Private IP:  $PRIVATE_IP" >> /tmp/final_output.txt
      echo -e "SSH Command: ssh -i polybot-key.pem ubuntu@$PUBLIC_IP" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      echo -e "🖥️ WORKER NODES" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      WORKER_DATA=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,ID:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}" \
        --output json)
      NODE_COUNT=$(echo "$WORKER_DATA" | jq -r '.[][][]' | grep "ID" | wc -l)
      echo -e "Worker Count: $NODE_COUNT" >> /tmp/final_output.txt
      if [ "$NODE_COUNT" -gt 0 ]; then
        echo -e "\nWorker Node Details:" >> /tmp/final_output.txt
        WORKER_LINES=$(echo "$WORKER_DATA" | jq -r '.[][] | "- " + .Name + ": ID: " + .ID + ", Private IP: " + .PrivateIP + ", Public IP: " + .PublicIP + ", State: " + .State')
        echo "$WORKER_LINES" >> /tmp/final_output.txt
        echo -e "\nWorker Node SSH Commands:" >> /tmp/final_output.txt
        echo "$WORKER_DATA" | jq -r '.[][] | "ssh -i polybot-key.pem ubuntu@" + .PublicIP + " # " + .Name' >> /tmp/final_output.txt
      else
        echo -e "No worker nodes found. They may still be starting up." >> /tmp/final_output.txt
      fi
      echo "" >> /tmp/final_output.txt
      echo -e "📜 LOGS AND TROUBLESHOOTING" >> /tmp/final_output.txt
      echo -e "----------------------------" >> /tmp/final_output.txt
      echo -e "Control Plane Init Log:" >> /tmp/final_output.txt
      echo -e "ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'cat /home/ubuntu/init_summary.log'" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      if [ "$NODE_COUNT" -gt 0 ]; then
        echo -e "Worker Node Init Logs:" >> /tmp/final_output.txt
        echo "$WORKER_DATA" | jq -r '.[][] | "ssh -i polybot-key.pem ubuntu@" + .PublicIP + " \"cat /home/ubuntu/init_summary.log\" # " + .Name' >> /tmp/final_output.txt
        echo "" >> /tmp/final_output.txt
      fi
      echo -e "☸️ KUBERNETES ACCESS" >> /tmp/final_output.txt
      echo -e "---------------------" >> /tmp/final_output.txt
      echo -e "API Endpoint: https://$PUBLIC_IP:6443" >> /tmp/final_output.txt
      echo -e "Kubeconfig:   ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=./kubeconfig.yaml" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      echo -e "🌐 APPLICATION ENDPOINTS" >> /tmp/final_output.txt
      echo -e "------------------------" >> /tmp/final_output.txt
      echo -e "Dev URL:  Not available (polybot_dev module not loaded)" >> /tmp/final_output.txt
      echo -e "Prod URL: Not available (polybot_prod module not loaded)" >> /tmp/final_output.txt
      ALB_DNS=${module.k8s-cluster.alb_dns_name}
      echo -e "Load Balancer DNS: $ALB_DNS" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      echo -e "✅ TERRAFORM DEPLOYMENT COMPLETE" >> /tmp/final_output.txt
      echo -e "==========================================" >> /tmp/final_output.txt
    EOT
  }
  depends_on = [
    null_resource.argocd_password_retriever,
    null_resource.worker_node_details,
    null_resource.dynamic_worker_logs,
    module.k8s-cluster.aws_instance.control_plane,
    module.k8s-cluster.aws_autoscaling_group.worker_asg
  ]
}

# Additional helpful cluster information
output "kubernetes_info" {
  description = "Information about the Kubernetes cluster"
  value = {
    control_plane_ip = try(module.k8s-cluster.control_plane_public_ip, "")
    kubeconfig_path  = local.kubeconfig_path
    worker_nodes     = try(module.k8s-cluster.worker_nodes, [])
  }
}

output "cluster_readiness" {
  description = "Information about cluster readiness"
  value = {
    kubeconfig_ready = fileexists(local.kubeconfig_path)
    ebs_csi_ready    = try(null_resource.install_ebs_csi_driver.id, "")
  }
}

# Add cluster_kubeconfig output that provides the kubeconfig content
output "cluster_kubeconfig" {
  description = "Kubeconfig content for accessing the cluster"
  value       = fileexists("${path.module}/kubeconfig.yaml") ? file("${path.module}/kubeconfig.yaml") : "Kubeconfig not available yet"
  sensitive   = true
}

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

output "worker_logs_bucket" {
  description = "S3 bucket containing worker node logs"
  value       = module.k8s-cluster.worker_logs_bucket
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer in front of the Kubernetes cluster"
  value       = module.k8s-cluster.alb_dns_name
}

output "kubernetes_join_command_secrets" {
  description = "Secret names containing the Kubernetes join command"
  value       = module.k8s-cluster.kubernetes_join_command_secrets
}

output "ssh_key_path" {
  description = "Path to the SSH key for connecting to cluster nodes"
  value       = "Use 'polybot-key.pem' to SSH as 'ubuntu@${module.k8s-cluster.control_plane_ip}'"
}

output "connection_commands" {
  description = "Commands to connect to the Kubernetes cluster"
  value = <<-EOT
    # SSH to control plane:
    ssh -i polybot-key.pem ubuntu@${module.k8s-cluster.control_plane_ip}
    
    # Check cluster status:
    ssh -i polybot-key.pem ubuntu@${module.k8s-cluster.control_plane_ip} "kubectl get nodes"
    
    # View control plane logs:
    ssh -i polybot-key.pem ubuntu@${module.k8s-cluster.control_plane_ip} "sudo cat /var/log/k8s-control-plane-init.log"
    
    # View join command logs:
    ssh -i polybot-key.pem ubuntu@${module.k8s-cluster.control_plane_ip} "sudo cat /var/log/k8s-token-creator.log"
    
    # Access worker logs in S3:
    aws s3 ls s3://${module.k8s-cluster.worker_logs_bucket}/
  EOT
}

#DEBUGGABLE: Comprehensive debug outputs for Terraform apply
output "debug_logs_location" {
  description = "Location of all debug logs and artifacts"
  value = {
    main_log           = "logs/tf_debug.log"
    cluster_state      = "logs/cluster_state/"
    kubernetes_state   = "logs/kubernetes_state/"
    deployment_summary = "logs/deployment_summary_*.json"
    debug_bundle       = "logs/debug-bundle-*.tgz"
  }
}

output "deployment_status" {
  description = "Overall deployment status and key information"
  value = {
    region               = var.region
    cluster_name         = try(module.k8s-cluster.cluster_name, "unknown")
    control_plane_ip     = try(module.k8s-cluster.control_plane_public_ip, "not available")
    control_plane_id     = try(module.k8s-cluster.control_plane_instance_id, "not available")
    vpc_id              = try(module.k8s-cluster.vpc_id, "not available")
    kubeconfig_path     = local.kubeconfig_path
    kubeconfig_ready    = local.k8s_ready
  }
}

output "debug_analysis_summary" {
  description = "Summary of debug analysis for quick troubleshooting"
  value = {
    logs_directory_exists = fileexists("logs/tf_debug.log") ? "✅ Found" : "❌ Missing"
    cluster_state_files   = try(length(fileset("logs/cluster_state", "*.json")) > 0, false) ? "✅ Available" : "⚠️ None found"
    kubernetes_state      = try(length(fileset("logs/kubernetes_state", "*.json")) > 0, false) ? "✅ Available" : "⚠️ None found"
    debug_bundle_created  = try(length(fileset("logs", "debug-bundle-*.tgz")) > 0, false) ? "✅ Created" : "⚠️ Not found"
  }
}

output "error_analysis" {
  description = "Error analysis from debug logs"
  value = fileexists("logs/tf_debug.log") ? {
    total_lines    = try(length(split("\n", file("logs/tf_debug.log"))), 0)
    error_count    = try(length(regexall("\"status\":\"error\"", file("logs/tf_debug.log"))), 0)
    warning_count  = try(length(regexall("\"status\":\"warning\"", file("logs/tf_debug.log"))), 0)
    success_count  = try(length(regexall("\"status\":\"success\"", file("logs/tf_debug.log"))), 0)
  } : {
    status = "❌ Debug log not available"
    total_lines = 0
    error_count = 0
    warning_count = 0
    success_count = 0
  }
}

output "troubleshooting_commands" {
  description = "Key commands for troubleshooting deployment issues"
  value = {
    view_errors           = "grep '\"status\":\"error\"' logs/tf_debug.log"
    check_timing          = "grep -E '(start|complete)' logs/tf_debug.log"
    list_debug_files      = "find logs/ -type f | sort"
    check_control_plane   = try("ssh ubuntu@${module.k8s-cluster.control_plane_public_ip} 'kubectl get nodes'", "Control plane IP not available")
    check_aws_identity    = "aws sts get-caller-identity"
    verify_region_access  = "aws ec2 describe-regions --region ${var.region}"
  }
}

output "next_steps" {
  description = "Recommended next steps based on deployment status"
  value = local.k8s_ready ? {
    status = "🎉 Deployment appears successful!"
    actions = [
      "✅ Verify cluster: kubectl --kubeconfig=${local.kubeconfig_path} get nodes",
      "✅ Check pods: kubectl --kubeconfig=${local.kubeconfig_path} get pods --all-namespaces",
      "✅ Access ArgoCD: Run the ArgoCD tunnel script if available",
      "✅ Review logs: Check logs/tf_debug.log for any warnings"
    ]
  } : {
    status = "⚠️ Deployment may need attention"
    actions = [
      "🔍 Check errors: grep '\"status\":\"error\"' logs/tf_debug.log",
      "🔍 Verify AWS access: aws sts get-caller-identity",
      "🔍 Check control plane: SSH to instance if available",
      "🔍 Review debug bundle: Latest debug-bundle-*.tgz in logs/"
    ]
  }
}

output "debug_environment_info" {
  description = "Debug environment configuration for troubleshooting"
  value = {
    terraform_workspace = terraform.workspace
    debug_config = local.debug_config
    debug_environment = local.debug_environment
    skip_resources = {
      argocd     = local.skip_argocd
      namespaces = local.skip_namespaces
    }
  }
}

# Special output for copy-paste debugging
output "copy_paste_debug_info" {
  description = "Debug information formatted for easy copy-paste to Cursor AI"
  value = fileexists("logs/tf_debug.log") ? join("\n", [
    "=== TERRAFORM DEBUG SUMMARY ===",
    "Region: ${var.region}",
    "Cluster: ${try(module.k8s-cluster.cluster_name, "unknown")}",
    "Control Plane: ${try(module.k8s-cluster.control_plane_public_ip, "not available")}",
    "Kubeconfig Ready: ${local.k8s_ready}",
    "Error Count: ${try(length(regexall("\"status\":\"error\"", file("logs/tf_debug.log"))), 0)}",
    "Warning Count: ${try(length(regexall("\"status\":\"warning\"", file("logs/tf_debug.log"))), 0)}",
    "Last 3 Log Entries:",
    try(join("\n", slice(split("\n", file("logs/tf_debug.log")), 
                         max(0, length(split("\n", file("logs/tf_debug.log"))) - 3),
                         length(split("\n", file("logs/tf_debug.log"))))), "No log entries available"),
    "=== END DEBUG SUMMARY ==="
  ]) : "Debug log not available - check if terraform apply completed successfully"
}

# Final deployment readiness check
output "deployment_readiness_check" {
  description = "Final check of deployment readiness"
  value = {
    infrastructure_ready = try(module.k8s-cluster.control_plane_instance_id != "", false)
    kubeconfig_available = local.kubeconfig_exists
    kubernetes_ready     = local.k8s_ready
    debug_logs_created   = fileexists("logs/tf_debug.log")
    overall_status = (
      try(module.k8s-cluster.control_plane_instance_id != "", false) &&
      local.kubeconfig_exists &&
      fileexists("logs/tf_debug.log")
    ) ? "🎉 READY" : "⚠️ NEEDS ATTENTION"
  }
}