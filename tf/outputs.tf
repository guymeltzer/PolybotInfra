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
    # Use meaningful triggers instead of timestamp
    worker_count = length(jsondecode(file(fileexists("/tmp/worker_nodes.json") ? "/tmp/worker_nodes.json" : "/dev/null"))) > 0 ? length(jsondecode(file("/tmp/worker_nodes.json"))) : 0
    # Don't use filemd5 on kubeconfig as it changes during apply
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
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

# ------------------------------------------------------------------------
# Section 5: ArgoCD Information
# ------------------------------------------------------------------------

# Resource to retrieve ArgoCD password for output display
resource "null_resource" "argocd_password_retriever" {
  triggers = {
    # Only trigger when ArgoCD is installed or kubeconfig changes
    argocd_status = fileexists("/tmp/argocd_already_installed") ? file("/tmp/argocd_already_installed") : "unknown"
    # Don't use filemd5 on kubeconfig as it changes during apply
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
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
      
      echo -e "🌐 URL: \033[1;36mhttps://localhost:8081\033[0m (Port forwarding running automatically)" >> /tmp/argocd-info.txt
      echo -e "👤 Username: \033[1;32madmin\033[0m" >> /tmp/argocd-info.txt
      echo -e "🔑 Password: \033[1;32m$(cat /tmp/argocd-password-output.txt)\033[0m" >> /tmp/argocd-info.txt
      echo "" >> /tmp/argocd-info.txt
      echo -e "Note: Port forwarding is managed automatically by Terraform" >> /tmp/argocd-info.txt
    EOT
  }

  depends_on = [
    null_resource.argocd_direct_access
  ]
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

# ------------------------------------------------------------------------
# Section 9: Troubleshooting Commands
# ------------------------------------------------------------------------

# New dynamic worker logs command that uses actual worker public IPs
resource "null_resource" "dynamic_worker_logs" {
  triggers = {
    # Use meaningful triggers instead of timestamp
    worker_count = length(jsondecode(file(fileexists("/tmp/worker_nodes.json") ? "/tmp/worker_nodes.json" : "/dev/null"))) > 0 ? length(jsondecode(file("/tmp/worker_nodes.json"))) : 0
    # Don't use filemd5 on kubeconfig as it changes during apply
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
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
  value = {
    api_endpoint = "https://${module.k8s-cluster.control_plane_public_ip}:6443"
    control_plane = {
      public_ip = module.k8s-cluster.control_plane_public_ip
      ssh = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip}"
    }
    kubeconfig_cmd = "ssh -i ${module.k8s-cluster.ssh_key_name}.pem ubuntu@${module.k8s-cluster.control_plane_public_ip} 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=./kubeconfig.yaml"
    alb_dns = module.k8s-cluster.alb_dns_name
  }
}

# Application endpoints
output "endpoints" {
  description = "Application endpoints"
  value = {
    dev = "https://dev-polybot.${terraform.workspace}.devops-int-college.com"
    prod = "https://polybot.${terraform.workspace}.devops-int-college.com"
    argocd = "https://localhost:8081 (Run ~/argocd-ssh-tunnel.sh first)"
  }
}

# AWS resources
output "aws_resources" {
  description = "AWS resources created for the application"
  value = {
    vpc_id = module.k8s-cluster.vpc_id
    subnets = module.k8s-cluster.public_subnet_ids
    ssh_key = module.k8s-cluster.ssh_key_name
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
  }
}

# RESOURCES FOR GENERATING OUTPUT FILES
# These resources don't create outputs directly but generate the files used by outputs

# Resource to format all outputs into a single file
resource "null_resource" "format_outputs" {
  triggers = {
    # Create meaningful triggers that depend on actual resources
    worker_nodes = null_resource.worker_node_details.id
    argocd_password = null_resource.argocd_password_retriever.id
    worker_logs = null_resource.dynamic_worker_logs.id
    # Don't use filemd5 on kubeconfig as it changes during apply
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      # Create visually appealing output without ANSI color codes
      cat > /tmp/final_output.txt << 'EOF'
=================================================================
                POLYBOT KUBERNETES CLUSTER DEPLOYMENT
=================================================================

EOF
      
      # ----- ARGOCD INFO -----
      echo -e "🔐 ARGOCD ACCESS" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      
      # Get password if available
      ARGOCD_PASSWORD=""
      if [ -f "/tmp/argocd-admin-password.txt" ]; then
        ARGOCD_PASSWORD=$(cat /tmp/argocd-admin-password.txt)
      fi
      
      echo -e "URL: https://localhost:8081" >> /tmp/final_output.txt
      echo -e "Username: admin" >> /tmp/final_output.txt
      echo -e "Password: $ARGOCD_PASSWORD" >> /tmp/final_output.txt
      echo -e "Connection: Run ~/argocd-ssh-tunnel.sh" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- CONTROL PLANE INFO -----
      echo -e "🔧 CONTROL PLANE" >> /tmp/final_output.txt
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
        
      echo -e "Instance ID: $INSTANCE_ID" >> /tmp/final_output.txt
      echo -e "Public IP:   $PUBLIC_IP" >> /tmp/final_output.txt
      echo -e "Private IP:  $PRIVATE_IP" >> /tmp/final_output.txt
      echo -e "SSH Command: ssh -i polybot-key.pem ubuntu@$PUBLIC_IP" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- WORKER NODES INFO -----
      echo -e "🖥️ WORKER NODES" >> /tmp/final_output.txt
      echo -e "-------------------" >> /tmp/final_output.txt
      
      # Directly get worker node information from AWS to be more reliable
      WORKER_DATA=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,ID:InstanceId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}" \
        --output json)
          
      # Count the number of worker nodes
      NODE_COUNT=$(echo "$WORKER_DATA" | jq -r '.[][][]' | grep "ID" | wc -l)
      echo -e "Worker Count: $NODE_COUNT" >> /tmp/final_output.txt
      
      # Format worker details
      if [ "$NODE_COUNT" -gt 0 ]; then
        echo -e "\nWorker Node Details:" >> /tmp/final_output.txt
        
        # Get running worker nodes with their public IPs
        WORKER_LINES=$(echo "$WORKER_DATA" | jq -r '.[][] | "- " + .Name + ": ID: " + .ID + ", Private IP: " + .PrivateIP + ", Public IP: " + .PublicIP + ", State: " + .State')
        echo "$WORKER_LINES" >> /tmp/final_output.txt
        
        # Extract worker node log commands for later use
        echo -e "\nWorker Node SSH Commands:" >> /tmp/final_output.txt
        echo "$WORKER_DATA" | jq -r '.[][] | "ssh -i polybot-key.pem ubuntu@" + .PublicIP + " # " + .Name' >> /tmp/final_output.txt
      else
        echo -e "No worker nodes found. They may still be starting up." >> /tmp/final_output.txt
      fi
      echo "" >> /tmp/final_output.txt
      
      # ----- LOGS AND TROUBLESHOOTING -----
      echo -e "📜 LOGS AND TROUBLESHOOTING" >> /tmp/final_output.txt
      echo -e "----------------------------" >> /tmp/final_output.txt
      
      echo -e "Control Plane Init Log:" >> /tmp/final_output.txt
      echo -e "ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'cat /home/ubuntu/init_summary.log'" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # Add worker node log commands
      if [ "$NODE_COUNT" -gt 0 ]; then
        echo -e "Worker Node Init Logs:" >> /tmp/final_output.txt
        echo "$WORKER_DATA" | jq -r '.[][] | "ssh -i polybot-key.pem ubuntu@" + .PublicIP + " \"cat /home/ubuntu/init_summary.log\" # " + .Name' >> /tmp/final_output.txt
        echo "" >> /tmp/final_output.txt
      fi
      
      # ----- KUBERNETES ACCESS -----
      echo -e "☸️ KUBERNETES ACCESS" >> /tmp/final_output.txt
      echo -e "---------------------" >> /tmp/final_output.txt
      echo -e "API Endpoint: https://$PUBLIC_IP:6443" >> /tmp/final_output.txt
      echo -e "Kubeconfig:   ssh -i polybot-key.pem ubuntu@$PUBLIC_IP 'cat /home/ubuntu/.kube/config' > kubeconfig.yaml && export KUBECONFIG=./kubeconfig.yaml" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- APPLICATION ENDPOINTS -----
      echo -e "🌐 APPLICATION ENDPOINTS" >> /tmp/final_output.txt
      echo -e "------------------------" >> /tmp/final_output.txt
      echo -e "Dev URL:  https://dev-polybot.${terraform.workspace}.devops-int-college.com" >> /tmp/final_output.txt
      echo -e "Prod URL: https://polybot.${terraform.workspace}.devops-int-college.com" >> /tmp/final_output.txt
      
      # Get ALB DNS from AWS
      ALB_DNS=$(aws elbv2 describe-load-balancers --region ${var.region} \
        --query "LoadBalancers[?contains(LoadBalancerName, 'guy-polybot-lb')].DNSName" \
        --output text)
      
      echo -e "Load Balancer DNS: $ALB_DNS" >> /tmp/final_output.txt
      echo "" >> /tmp/final_output.txt
      
      # ----- CLOSING -----
      echo -e "✅ TERRAFORM DEPLOYMENT COMPLETE" >> /tmp/final_output.txt
      echo -e "==========================================" >> /tmp/final_output.txt
    EOT
  }

  depends_on = [
    null_resource.argocd_password_retriever,
    null_resource.worker_node_details,
    null_resource.dynamic_worker_logs,
    null_resource.argocd_direct_access
  ]
}