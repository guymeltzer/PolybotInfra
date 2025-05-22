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
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      # Get running worker nodes with full details
      aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}" \
        --output json > /tmp/worker_nodes.json || echo '[]' > /tmp/worker_nodes.json
      
      # Create a formatted text version for output display
      echo "" > /tmp/worker_nodes_formatted.txt
      jq -r '.[][] | "Name: \(.Name)\nInstanceId: \(.InstanceId)\nPrivateIP: \(.PrivateIP)\nPublicIP: \(.PublicIP)\nState: \(.State)\n---"' /tmp/worker_nodes.json > /tmp/worker_nodes_formatted.txt
    EOT
  }
}

output "worker_nodes" {
  description = "Worker node details (running instances only)"
  value = fileexists("/tmp/worker_nodes.json") ? jsondecode(file("/tmp/worker_nodes.json")) : []
}

output "worker_nodes_formatted" {
  description = "Formatted worker node details for easy reading"
  value = fileexists("/tmp/worker_nodes_formatted.txt") ? file("/tmp/worker_nodes_formatted.txt") : "No worker nodes information available"
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

# Resource to retrieve ArgoCD password for output display
resource "null_resource" "argocd_password_retriever" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      # Retrieve ArgoCD password if available
      if [ -f "/tmp/argocd-admin-password.txt" ]; then
        cat /tmp/argocd-admin-password.txt > /tmp/argocd-password-output.txt
      elif [ -f "${local.kubeconfig_path}" ]; then
        # Try to get it directly if file not found
        PASSWORD=$(KUBECONFIG="${local.kubeconfig_path}" kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d)
        if [ -n "$PASSWORD" ]; then
          echo "$PASSWORD" > /tmp/argocd-password-output.txt
        else
          echo "Password not available yet. ArgoCD may still be initializing." > /tmp/argocd-password-output.txt
        fi
      else
        echo "Password not available yet. Kubeconfig not found." > /tmp/argocd-password-output.txt
      fi
      
      # Create colorful ArgoCD info
      cat > /tmp/argocd-info.txt << 'INFOEOF'
🔐 ArgoCD Access Information
---------------------------
INFOEOF
      
      echo -e "🌐 URL: \033[1;36mhttps://localhost:8080\033[0m (Port forwarding automatically started)" >> /tmp/argocd-info.txt
      echo -e "👤 Username: \033[1;32madmin\033[0m" >> /tmp/argocd-info.txt
      echo -e "🔑 Password: \033[1;32m$(cat /tmp/argocd-password-output.txt)\033[0m" >> /tmp/argocd-info.txt
      echo "" >> /tmp/argocd-info.txt
      echo -e "Note: If port forwarding isn't working, run: \033[1;33m./argocd-connect.sh\033[0m" >> /tmp/argocd-info.txt
    EOT
  }

  depends_on = [
    null_resource.argocd_access_helper
  ]
}

output "argocd_info" {
  description = "Detailed ArgoCD access information"
  value = fileexists("/tmp/argocd-info.txt") ? file("/tmp/argocd-info.txt") : <<-EOT
    🔐 ArgoCD Access Information
    ---------------------------
    URL: https://localhost:8080 
    Username: admin
    Password: Not available yet. ArgoCD may still be initializing.
    
    If ArgoCD isn't accessible, run: ./argocd-connect.sh
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

# New dynamic worker logs command that uses actual worker public IPs
resource "null_resource" "dynamic_worker_logs" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      # Get running worker nodes
      WORKER_DATA=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,PublicIP:PublicIpAddress}" \
        --output json)
      
      echo "# Dynamic Worker Node Log Commands" > /tmp/worker_log_commands.txt
      echo "# Generated $(date)" >> /tmp/worker_log_commands.txt
      echo "" >> /tmp/worker_log_commands.txt
      
      # Generate dynamic log commands with actual IPs
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
}

output "dynamic_worker_logs" {
  description = "Commands to view logs on each worker node with actual IPs"
  value = fileexists("/tmp/worker_log_commands.txt") ? file("/tmp/worker_log_commands.txt") : "Worker log commands not available yet"
}

# ------------------------------------------------------------------------
# Section 10: Complete Deployment Output
# ------------------------------------------------------------------------

resource "null_resource" "format_outputs" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      # Create visually appealing, colorful output
      cat > /tmp/final_output.txt << 'EOF'
🎉 =================================================================== 🎉
                POLYBOT KUBERNETES CLUSTER DEPLOYMENT
🎉 =================================================================== 🎉

EOF
      
      # ----- ARGOCD INFO -----
      if [ -f "/tmp/argocd-info.txt" ]; then
        cat /tmp/argocd-info.txt >> /tmp/final_output.txt
      else
        echo -e "🔐 \033[1;34mArgoCD Access\033[0m" >> /tmp/final_output.txt
        echo -e "-------------------" >> /tmp/final_output.txt
        echo -e "URL: \033[1;36mhttps://localhost:8080\033[0m" >> /tmp/final_output.txt
        echo -e "Username: \033[1;32madmin\033[0m" >> /tmp/final_output.txt
        echo -e "Password: Run argocd-connect.sh to retrieve" >> /tmp/final_output.txt
        echo "" >> /tmp/final_output.txt
      fi
      
      # ----- CONTROL PLANE INFO -----
      echo -e "\n\033[1;34m🔧 Control Plane\033[0m" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=guy-control-plane" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=guy-control-plane" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].InstanceId" --output text)
      PRIVATE_IP=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=guy-control-plane" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)
        
      echo -e "Instance ID: \033[1;32m$INSTANCE_ID\033[0m" >> /tmp/final_output.txt
      echo -e "Public IP:   \033[1;32m$PUBLIC_IP\033[0m" >> /tmp/final_output.txt
      echo -e "Private IP:  \033[1;32m$PRIVATE_IP\033[0m" >> /tmp/final_output.txt
      echo -e "SSH Command: \033[1;36mssh -i polybot-key.pem ubuntu@$PUBLIC_IP\033[0m" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- WORKER NODES INFO -----
      echo -e "\033[1;34m🖥️ Worker Nodes\033[0m" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      
      if [ -f "/tmp/worker_nodes_formatted.txt" ]; then
        # Count the nodes by counting the separator pattern
        NODE_COUNT=$(grep -c "\-\-\-" /tmp/worker_nodes_formatted.txt || echo 0)
        echo -e "Worker Count: \033[1;32m$NODE_COUNT\033[0m" >> /tmp/final_output.txt
        echo "" >> /tmp/final_output.txt
        
        # Format worker nodes in a cleaner way without excessive escape sequences
        echo -e "\033[1;33mWorker Nodes Details:\033[0m" >> /tmp/final_output.txt
        jq -r '.[][] | "\033[1;36m- \(.Name):\033[0m ID: \033[1;32m\(.InstanceId)\033[0m, Private IP: \033[1;37m\(.PrivateIP)\033[0m, Public IP: \033[1;37m\(.PublicIP)\033[0m, State: \033[1;32m\(.State)\033[0m"' /tmp/worker_nodes.json >> /tmp/final_output.txt
      else
        echo -e "\033[1;33mNo worker node information available yet\033[0m" >> /tmp/final_output.txt
      fi
      
      # ----- LOGS AND TROUBLESHOOTING -----
      echo -e "\n\033[1;34m📜 Logs and Troubleshooting\033[0m" >> /tmp/final_output.txt
      echo -e "----------------------------" >> /tmp/final_output.txt
      
      echo -e "\033[1;33mControl Plane Init Log:\033[0m" >> /tmp/final_output.txt
      echo -e "\033[1;36mssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'cat /home/ubuntu/init_summary.log'\033[0m" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # Add dynamic worker logs
      if [ -f "/tmp/worker_log_commands.txt" ]; then
        echo -e "\033[1;33mWorker Node Init Logs:\033[0m" >> /tmp/final_output.txt
        cat /tmp/worker_log_commands.txt | sed 's/ssh -i/\\\\033[1;36mssh -i/' | sed 's/log'\''/log\\\\033[0m'\''/g' >> /tmp/final_output.txt
      fi
      
      # ----- KUBERNETES ACCESS -----
      echo -e "\n\033[1;34m☸️ Kubernetes Access\033[0m" >> /tmp/final_output.txt
      echo -e "---------------------" >> /tmp/final_output.txt
      echo -e "API Endpoint: \033[1;36mhttps://$PUBLIC_IP:6443\033[0m" >> /tmp/final_output.txt
      echo -e "Kubeconfig:   \033[1;36mssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=\$\$(pwd)/kubeconfig.yaml\033[0m" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- APPLICATION ENDPOINTS -----
      echo -e "\033[1;34m🌐 Application Endpoints\033[0m" >> /tmp/final_output.txt
      echo -e "------------------------" >> /tmp/final_output.txt
      echo -e "Dev URL:  \033[1;36mhttps://dev-polybot.${terraform.workspace}.devops-int-college.com\033[0m" >> /tmp/final_output.txt
      echo -e "Prod URL: \033[1;36mhttps://polybot.${terraform.workspace}.devops-int-college.com\033[0m" >> /tmp/final_output.txt
      
      # Get ALB DNS from AWS
      ALB_DNS=$(aws elbv2 describe-load-balancers --region ${var.region} \
        --query "LoadBalancers[?contains(LoadBalancerName, 'guy-polybot-lb')].DNSName" \
        --output text)
      
      echo -e "Load Balancer DNS: \033[1;32m$ALB_DNS\033[0m" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- CLOSING -----
      echo -e "\033[1;32m✅ Terraform Deployment Complete!\033[0m" >> /tmp/final_output.txt
      echo -e "\033[1;34m=================================================================\033[0m" >> /tmp/final_output.txt
    EOT
  }

  depends_on = [
    null_resource.argocd_password_retriever,
    null_resource.worker_node_details,
    null_resource.dynamic_worker_logs,
    null_resource.argocd_access_helper
  ]
}

output "complete_deployment_info" {
  description = "Complete formatted deployment information"
  value = fileexists("/tmp/final_output.txt") ? file("/tmp/final_output.txt") : "Deployment information not available yet"
}