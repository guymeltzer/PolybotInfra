provider "aws" {
  region = var.region
}

provider "tls" {}

# Resource to clean problematic resources from Terraform state
resource "terraform_data" "clean_kubernetes_state" {
  # Use more deterministic triggers that don't cause unnecessary runs
  triggers_replace = {
    # Only run when the kubeconfig changes or is created/deleted
    kubeconfig_status = fileexists("${path.module}/kubeconfig.yaml") ? filemd5("${path.module}/kubeconfig.yaml") : "not_exists"
  }

  provisioner "local-exec" {
    # Use a simple echo command to avoid bash syntax issues
    command = "echo 'Skipping Kubernetes state cleanup to avoid errors'"
  }
}

# Define a local provider for first-time setup
provider "local" {}

# Resource to automate secrets management and cleanup
resource "terraform_data" "manage_secrets" {
  depends_on = [terraform_data.clean_kubernetes_state]

  # Only run when relevant files change
  triggers_replace = {
    # Run when relevant configuration files change
    tfvars_exists = fileexists("${path.module}/region.${var.region}.tfvars") ? filemd5("${path.module}/region.${var.region}.tfvars") : "not_exists"
    variables_hash = filemd5("${path.module}/variables.tf")
  }

  # Run script to check and clean up secrets
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      
      echo "Checking for stale AWS secrets..."
      
      # Check if jq is installed
      if ! command -v jq &> /dev/null; then
        echo "jq not found, skipping secret cleanup"
        exit 0
      fi
       
      # Check if AWS CLI is available
      if ! command -v aws &> /dev/null; then
        echo "AWS CLI not found, skipping secret cleanup"
        exit 0
      fi
       
      # Function to check for duplicate secrets
      check_duplicate_secrets() {
        local prefix="$1"
         
        echo "Checking for duplicates with prefix: $prefix"
         
        SECRETS=$(aws secretsmanager list-secrets \
          --region ${var.region} \
          --filters Key=name,Values="$prefix" \
          --query "SecretList[*].{Name:Name,ARN:ARN}" \
          --output json 2>/dev/null) || {
            echo "Failed to fetch secrets"
            return 0
          }
         
        COUNT=$(echo "$SECRETS" | jq -r 'length')
         
        if [ "$COUNT" -le 1 ]; then
          echo "No duplicate secrets found for $prefix"
          return 0
        fi
         
        echo "Found $COUNT secrets with prefix $prefix, cleaning up..."
         
        # Get all but the newest secret
        SECRETS_TO_DELETE=$(echo "$SECRETS" | jq -r '.[0:-1] | .[].Name')
         
        # Delete the older secrets
        for SECRET_NAME in $SECRETS_TO_DELETE; do
          echo "Force deleting $SECRET_NAME"
          aws secretsmanager delete-secret \
            --secret-id "$SECRET_NAME" \
            --force-delete-without-recovery \
            --region ${var.region} >/dev/null 2>&1 || echo "Failed to delete $SECRET_NAME"
        done
      }
       
      # Check each prefix directly instead of using arrays
      echo "Checking dev environment secrets..."
      check_duplicate_secrets "guy-polybot-dev-telegram-token"
      check_duplicate_secrets "guy-polybot-dev-docker-credentials"
      check_duplicate_secrets "guy-polybot-dev-secrets"
       
      echo "Checking prod environment secrets..."
      check_duplicate_secrets "guy-polybot-prod-telegram-token"
      check_duplicate_secrets "guy-polybot-prod-docker-credentials"
      check_duplicate_secrets "guy-polybot-prod-secrets"
       
      echo "Secret cleanup complete"
    EOT
  }
}

# Resource to ensure proper initialization before anything else runs
resource "terraform_data" "init_environment" {
  depends_on = [terraform_data.manage_secrets]

  # Use a more deterministic trigger that won't cause cycles
  triggers_replace = {
    # Trigger on kubeconfig presence/absence without referencing module.k8s-cluster
    run_kubeconfig = fileexists("./kubeconfig.yaml") ? filemd5("./kubeconfig.yaml") : "notexists"
  }

  # Create a valid kubeconfig before any resources are created
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      
      # Look for control plane instance
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      # Look for public IP if instance exists
      if [ "$INSTANCE_ID" != "None" ] && [ ! -z "$INSTANCE_ID" ]; then
        PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        
        # If we have a public IP, try to get the real kubeconfig
        if [ "$PUBLIC_IP" != "None" ] && [ ! -z "$PUBLIC_IP" ]; then
          echo "Control plane found with IP: $PUBLIC_IP, checking for kubeconfig"
          
          if aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
             --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
            
            echo "Control plane has SSM available, retrieving kubeconfig"
            # Try to get a real kubeconfig
            aws ssm send-command --region ${var.region} --document-name "AWS-RunShellScript" \
              --instance-ids "$INSTANCE_ID" --parameters 'commands=["cat /etc/kubernetes/admin.conf"]' \
              --output text --query "Command.CommandId" > /tmp/command_id.txt
            
            sleep 5
            
            # Get the kubeconfig content
            aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) \
              --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text > /tmp/admin_conf.txt
            
            # Check if we got a valid kubeconfig
            if [ -s /tmp/admin_conf.txt ] && grep -q "apiVersion: v1" /tmp/admin_conf.txt; then
              echo "Got valid kubeconfig, updating with correct IP"
              cat /tmp/admin_conf.txt | sed "s|server:.*|server: https://$PUBLIC_IP:6443|" > ./kubeconfig.yaml
              chmod 600 ./kubeconfig.yaml
              echo "Successfully created kubeconfig with real IP"
              exit 0
            fi
          fi
        fi
      fi
      
      # If we're at this point, we didn't get a valid kubeconfig
      echo "Creating placeholder kubeconfig"
      
      # Since we should only get here during initial setup, if a valid kubeconfig exists, DON'T overwrite it
      if [ -f "./kubeconfig.yaml" ] && ! grep -q "server: https://placeholder:6443" ./kubeconfig.yaml; then
        echo "Found existing valid kubeconfig, not overwriting with placeholder"
        exit 0
      fi
      
      # Create a minimal placeholder kubeconfig that won't cause connection errors
      cat > "./kubeconfig.yaml" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:9999
    insecure-skip-tls-verify: true
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
users:
- name: admin
  user:
    token: placeholder
EOF

      chmod 600 "./kubeconfig.yaml"
      echo "Created placeholder kubeconfig successfully with unused local address"
    EOT
  }
}

# Resource to wait for Kubernetes API to be fully available - with improved triggers
resource "null_resource" "wait_for_kubernetes" {
  count = 1

  # Only trigger when the kubeconfig changes, not directly on module.k8s-cluster
  triggers = {
    # Ensure this runs when the kubeconfig is updated
    kubeconfig_md5 = fileexists("${local.kubeconfig_path}") ? filemd5("${local.kubeconfig_path}") : "nonexistent"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e
      
      # Get the control plane instance ID
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
        echo "No running control plane instance found"
        exit 0
      fi
      
      # Get the public IP of the control plane
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
      
      if [ "$PUBLIC_IP" == "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo "Control plane instance doesn't have a public IP yet"
        exit 0
      fi
      
      echo "Found control plane public IP: $PUBLIC_IP"
      
      echo "Waiting for Kubernetes API at https://$PUBLIC_IP:6443 to be ready..."
      
      # Function to test if API is reachable
      test_api() {
        curl -k -s --max-time 5 https://$PUBLIC_IP:6443/healthz
      }
      
      # Wait for API to be ready with retries
      MAX_ATTEMPTS=10
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "Attempt $i/$MAX_ATTEMPTS - Testing API connection..."
        if test_api | grep -q "ok"; then
          echo "API server is ready!"
          exit 0
        fi
        
        if [ $i -eq $MAX_ATTEMPTS ]; then
          echo "WARNING: API server not responding after $MAX_ATTEMPTS attempts, but continuing..."
          exit 0
        else
          echo "API not ready yet, waiting 10 seconds..."
          sleep 10
        fi
      done
    EOT
  }
}

# Resource that checks if ArgoCD is already deployed before spending time installing it
resource "null_resource" "check_argocd_status" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.wait_for_kubernetes,
    terraform_data.kubectl_provider_config
  ]
  
  # Only trigger on kubeconfig changes, not directly on control plane changes
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Check if argocd is already deployed
      if kubectl get deployments -n argocd argocd-server &>/dev/null; then
        echo "ArgoCD server already deployed, skipping installation"
        # Mark as already installed
        echo "true" > /tmp/argocd_already_installed
      else
        echo "ArgoCD not found, will proceed with installation"
        echo "false" > /tmp/argocd_already_installed
      fi
    EOT
  }
}

# Install ArgoCD only if not already installed
resource "null_resource" "install_argocd" {
  count = local.skip_argocd ? 0 : 1
  
  # Ensure all prerequisites are met but avoid direct module references
  depends_on = [
    null_resource.create_namespaces,
    null_resource.providers_ready,
    null_resource.check_argocd_status,
    null_resource.install_ebs_csi_driver
  ]
  
  # Only run when needed based on whether ArgoCD is already installed
  # Avoid direct references to the cluster module to prevent cycles
  triggers = {
    # Use the check_argocd_status resource as the trigger
    needs_install = fileexists("/tmp/argocd_already_installed") ? file("/tmp/argocd_already_installed") != "true" : true,
    # Also trigger on kubeconfig changes
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Checking if ArgoCD needs to be installed..."
      KUBECONFIG="${local.kubeconfig_path}"
      
      if [ -f "/tmp/argocd_already_installed" ] && [ "$(cat /tmp/argocd_already_installed)" == "true" ]; then
        echo "ArgoCD already installed, skipping installation"
        exit 0
      fi
      
      echo "Ensuring argocd namespace exists..."
      kubectl --kubeconfig="$KUBECONFIG" create namespace argocd --dry-run=client -o yaml | kubectl --kubeconfig="$KUBECONFIG" apply --validate=false -f -
      
      echo "Installing ArgoCD..."
      kubectl --kubeconfig="$KUBECONFIG" apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
      
      # Wait for ArgoCD to be ready
      echo "Waiting for ArgoCD to be ready..."
      for i in {1..30}; do
        if kubectl --kubeconfig="$KUBECONFIG" -n argocd get deployment/argocd-server &>/dev/null; then
          echo "ArgoCD server deployment found, waiting for it to be ready..."
          kubectl --kubeconfig="$KUBECONFIG" -n argocd wait --for=condition=available --timeout=300s deployment/argocd-server || true
          break
        fi
        echo "Waiting for ArgoCD server deployment to appear... ($i/30)"
        sleep 10
      done
      
      echo "ArgoCD installation complete"
    EOT
  }
}

# Get ArgoCD admin password and set up automatic port forwarding directly in Terraform
resource "null_resource" "argocd_direct_access" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.install_argocd
  ]
  
  # Only run when ArgoCD changes or kubeconfig changes - don't reference cluster directly
  triggers = {
    argocd_install = null_resource.install_argocd[0].id
    kubeconfig = terraform_data.kubectl_provider_config[0].id
    ssh_key_exists = fileexists("${path.module}/polybot-key.pem") ? filemd5("${path.module}/polybot-key.pem") : "notexists"
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      
      # Set up connection to the cluster
      export KUBECONFIG="${local.kubeconfig_path}"
      echo "Retrieving ArgoCD credentials..."
      
      # Wait for the ArgoCD server and admin secret to be available
      for i in {1..10}; do
        if kubectl -n argocd get secret argocd-initial-admin-secret &>/dev/null; then
          ADMIN_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
          if [ -n "$ADMIN_PASSWORD" ]; then
            echo "ArgoCD admin password: $ADMIN_PASSWORD"
            echo "$ADMIN_PASSWORD" > /tmp/argocd-admin-password.txt
            chmod 600 /tmp/argocd-admin-password.txt
            break
          fi
        fi
        
        if [ $i -eq 10 ]; then
          echo "Failed to retrieve ArgoCD password after multiple attempts"
          echo "You can manually retrieve it with: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath=\"{.data.password}\" | base64 -d"
        else
          echo "Waiting for ArgoCD admin secret to be available... Attempt $i/10"
          sleep 15
        fi
      done
      
      # Get control plane public IP
      CONTROL_PLANE_IP=$(aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=guy-control-plane" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
      
      if [ -z "$CONTROL_PLANE_IP" ] || [ "$CONTROL_PLANE_IP" == "None" ]; then
        echo "❌ Could not retrieve control plane IP address"
        exit 1
      fi
      
      # Create an SSH tunnel script without any variable interpolation
      cat > ~/argocd-ssh-tunnel.sh << 'EOF'
#!/bin/bash
# ArgoCD SSH Tunnel Script - Generated by Terraform

# Configuration
SSH_KEY="$HOME/polybot-key.pem"
CONTROL_PLANE_IP="CONTROL_PLANE_IP_PLACEHOLDER"
LOCAL_PORT=8081
NAMESPACE="argocd"
SERVICE="argocd-server"
REMOTE_PORT=443

function cleanup() {
  echo "Cleaning up connections..."
  pkill -f "ssh.*-L $LOCAL_PORT:localhost:$LOCAL_PORT" > /dev/null 2>&1 || true
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP "pkill -f 'kubectl.*port-forward'" > /dev/null 2>&1 || true
  echo "Tunnel closed."
  exit 0
}

trap cleanup EXIT INT TERM

# Check commands
if ! command -v ssh &> /dev/null; then
  echo "Error: ssh command not found."
  exit 1
fi

# Check SSH key
if [ ! -f "$SSH_KEY" ]; then
  echo "Error: SSH key not found at $SSH_KEY"
  exit 1
fi

chmod 600 "$SSH_KEY"

# Kill existing processes on the port
if lsof -ti:$LOCAL_PORT > /dev/null 2>&1; then
  echo "Port $LOCAL_PORT is already in use, attempting to free it..."
  lsof -ti:$LOCAL_PORT | xargs kill -9 > /dev/null 2>&1
fi

# Setup forwarding
echo "Setting up ArgoCD connection..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP "pkill -f 'kubectl.*port-forward'" > /dev/null 2>&1 || true
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP "kubectl port-forward -n $NAMESPACE svc/$SERVICE $LOCAL_PORT:$REMOTE_PORT --address 0.0.0.0 > /dev/null 2>&1 &"

# Start tunnel
PASSWORD=$(cat /tmp/argocd-admin-password.txt 2>/dev/null || echo "Not available - check with kubectl")
echo ""
echo "=========================================="
echo "  ArgoCD Access Information"
echo "=========================================="
echo "URL: https://localhost:$LOCAL_PORT"
echo "Username: admin"
echo "Password: $PASSWORD"
echo ""
echo "Press Ctrl+C to close the connection"
echo "=========================================="

echo "Starting SSH tunnel..."
ssh -i "$SSH_KEY" -L $LOCAL_PORT:localhost:$LOCAL_PORT -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP
EOF

      # Replace the placeholder with the actual IP
      sed -i "s/CONTROL_PLANE_IP_PLACEHOLDER/$CONTROL_PLANE_IP/g" ~/argocd-ssh-tunnel.sh
      chmod 755 ~/argocd-ssh-tunnel.sh
      
      # Create a simple instructions file
      cat > /tmp/argocd-access-instructions.txt << EOF
=====================================================
                ACCESS ARGOCD
=====================================================

A script has been created at ~/argocd-ssh-tunnel.sh

To access ArgoCD:
1. Run: ~/argocd-ssh-tunnel.sh
2. Visit https://localhost:8081 in your browser
3. Username: admin
4. Password: $(cat /tmp/argocd-admin-password.txt 2>/dev/null || echo "Not available yet")

=====================================================
EOF

      # Display instructions
      echo "ArgoCD access script created at: ~/argocd-ssh-tunnel.sh"
      echo "Run the script to connect, then visit: https://localhost:8081"
      echo "Username: admin"
      echo "Password: $(cat /tmp/argocd-admin-password.txt 2>/dev/null || echo "Not available yet")"
    EOT
  }
}

# Add cleanup resources for proper port forwarding termination during terraform destroy
resource "terraform_data" "argocd_port_forward_cleanup" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [null_resource.argocd_direct_access]
  
  # Use only one trigger to avoid issues
  triggers_replace = {
    argocd_access_id = null_resource.argocd_direct_access[0].id
  }
  
  # Empty provisioner for creation - this ensures nothing runs during apply
  provisioner "local-exec" {
    command = "echo 'ArgoCD SSH tunnel cleanup will happen during destroy'"
  }
  
  # Add proper cleanup during destroy operations
  provisioner "local-exec" {
    when = destroy
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      echo "Cleaning up ArgoCD port forwarding..."
      
      # Safely check if there are processes to kill before attempting pkill
      if pgrep -f "ssh.*-L 8081:localhost:8081" >/dev/null; then
        echo "Found SSH tunnel processes, cleaning up..."
        pkill -f "ssh.*-L 8081:localhost:8081" || true
      else
        echo "No SSH tunnel processes found to clean up"
      fi
      
      echo "Cleanup complete."
    EOT
  }
}

# Configure kubectl provider with credentials after waiting for the API to be ready
resource "terraform_data" "kubectl_provider_config" {
  # Use a static count value
  count = 1

  # Ensure this runs after the control plane is available and we've waited for the API
  depends_on = [
    null_resource.wait_for_kubernetes,
    module.k8s-cluster
  ]

  # Trigger updates when control plane details change
  triggers_replace = [
    module.k8s-cluster.control_plane_id
  ]

  # Retrieve and store kubeconfig directly from the control plane
  provisioner "local-exec" {
    command = <<-EOT
      # Wait for instance to appear
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
        echo "No running control plane instance found, exiting early"
        exit 0
      fi
      
      # Get the public IP of the control plane
      PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
      
      if [ "$PUBLIC_IP" == "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo "Control plane instance doesn't have a public IP yet, exiting early"
        exit 0
      fi
      
      echo "Using control plane with IP: $PUBLIC_IP and instance ID: $INSTANCE_ID"
      
      # Wait for SSM to be ready
      echo "Checking if SSM is available on the control plane..."
      if ! aws ssm describe-instance-information --region ${var.region} --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
           --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
        echo "SSM not available yet, exiting early"
        exit 0
      fi
      
      # Retrieve the kubeconfig from the control plane
      echo "Getting kubeconfig from control plane..."
      aws ssm send-command --region ${var.region} --document-name "AWS-RunShellScript" \
        --instance-ids "$INSTANCE_ID" --parameters 'commands=["cat /etc/kubernetes/admin.conf"]' \
        --output text --query "Command.CommandId" > /tmp/command_id.txt
      
      sleep 5
      
      # Get the kubeconfig content
      aws ssm get-command-invocation --region ${var.region} --command-id $(cat /tmp/command_id.txt) \
        --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text > /tmp/kubeconfig_content.yaml
      
      # Only update kubeconfig if we got valid content
      if grep -q "apiVersion: v1" /tmp/kubeconfig_content.yaml; then
        # Update server endpoint in the kubeconfig
        cat /tmp/kubeconfig_content.yaml | sed "s|server:.*|server: https://$PUBLIC_IP:6443|" > ./kubeconfig.yaml
        chmod 600 ./kubeconfig.yaml
        echo "Created kubeconfig.yaml with server endpoint: https://$PUBLIC_IP:6443"
      else
        echo "Failed to retrieve valid kubeconfig, not updating existing file"
      fi
    EOT
  }
}

# Add a data source to ensure kubeconfig is ready - use a different pattern to avoid errors
# We'll use the file() function directly in a local value instead of a data source
locals {
  control_plane_ip = try(
    module.k8s-cluster.control_plane_public_ip,
    "kubernetes.default.svc"
  )
  skip_argocd     = false # Enable ArgoCD deployment
  skip_namespaces = false # Enable namespace creation
  # Check if kubeconfig exists and doesn't contain placeholder
  kubeconfig_exists = fileexists("${path.module}/kubeconfig.yaml")
  # Only consider Kubernetes ready if we have a real kubeconfig (not the placeholder)
  k8s_ready = local.kubeconfig_exists && (
    !strcontains(
      try(file("${path.module}/kubeconfig.yaml"), ""),
      "server: https://placeholder:6443"
    )
  )
  kubeconfig_path = "${path.module}/kubeconfig.yaml"
}

# This ensures the Kubernetes providers are properly initialized before any resources use them
resource "null_resource" "providers_ready" {
  # Use a static count value
  count = 1
  
  # Depend on both the kubeconfig and the wait for Kubernetes resources
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.wait_for_kubernetes
  ]

  triggers = {
    # Track control plane properties to ensure this runs when they change
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }

  # Verify the kubeconfig is accessible
  provisioner "local-exec" {
    command = <<-EOT
      #!/bin/bash
      set -e
      
      # Check if kubeconfig exists
      if [ ! -f "${local.kubeconfig_path}" ]; then
        echo "Kubeconfig doesn't exist yet, creating placeholder"
        exit 0
      fi
      
      echo "Kubeconfig exists at ${local.kubeconfig_path}"
      
      # Get control plane info if available
      INSTANCE_ID=$(aws ec2 describe-instances --region ${var.region} --filters Name=tag:Name,Values=guy-control-plane Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)
      
      if [ "$INSTANCE_ID" != "None" ] && [ ! -z "$INSTANCE_ID" ]; then
        PUBLIC_IP=$(aws ec2 describe-instances --region ${var.region} --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        
        if [ "$PUBLIC_IP" != "None" ] && [ ! -z "$PUBLIC_IP" ]; then
          echo "Checking if kubeconfig contains the real control plane IP..."
          if grep -q "server: https://$PUBLIC_IP:6443" "${local.kubeconfig_path}"; then
            echo "Kubeconfig contains real control plane IP ($PUBLIC_IP)"
          else
            echo "Updating kubeconfig with current IP"
            sed -i '' "s|server:.*|server: https://$PUBLIC_IP:6443|" "${local.kubeconfig_path}" || true
          fi
        fi
      fi
      
      echo "Providers ready with kubeconfig at ${local.kubeconfig_path}"
    EOT
  }
}

# Create Kubernetes namespaces directly with kubectl to avoid provider auth issues
resource "null_resource" "create_namespaces" {
  # Use a static count value based on the skip_namespaces flag
  count = local.skip_namespaces ? 0 : 1

  # Ensure all prerequisites are met
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready,
    null_resource.wait_for_kubernetes
  ]

  # Only trigger after the control plane is actually ready
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    instance_id = module.k8s-cluster.control_plane_id
  }

  # Use local-exec to create namespaces directly with kubectl
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      
      echo -e "\033[1;34m==== 🔍 Attempting to Create Kubernetes Namespaces ====\033[0m"
      
      export KUBECONFIG="${path.module}/kubeconfig.yaml"
      
      # Function to test API server connection with better error messages
      test_api_server() {
        echo -e "\033[0;33m⏱️  Testing Kubernetes API server connection...\033[0m"
        if kubectl get nodes --request-timeout=5s >/dev/null 2>&1; then
          echo -e "\033[0;32m✅ Connected to Kubernetes API server successfully\033[0m"
          return 0
        else
          echo -e "\033[0;33m⚠️  Cannot connect to Kubernetes API server\033[0m"
          return 1
        fi
      }
      
      # Function to display a spinner during wait periods
      spinner() {
        local pid=$1
        local delay=0.5
        local spinstr='|/-\'
        echo -n "   "
        while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
          local temp=$${spinstr#?}
          printf "\r\033[0;33m⏱️  Waiting for API server... %c\033[0m" "$spinstr"
          local spinstr=$temp$${spinstr%"$temp"}
          sleep $$delay
        done
        printf "\r   \033[0;33m⏱️  Continuing...\033[0m                      \n"
      }
      
      # Verify the kubeconfig is valid
      echo -e "\033[0;33m🔍 Validating kubeconfig at $KUBECONFIG\033[0m"
      if grep -q "placeholder" "$KUBECONFIG"; then
        echo -e "\033[0;31m❌ ERROR: Kubeconfig contains placeholder values\033[0m"
        exit 1
      fi
      
      # Try to connect to the API server with retries
      MAX_RETRIES=30
      RETRY_INTERVAL=20
      
      echo -e "\033[0;33m⏱️  Waiting up to 10 minutes for API server to be ready...\033[0m"
      
      for ((i=1; i<=MAX_RETRIES; i++)); do
        if test_api_server; then
          break
        fi
        
        if [ $i -eq $MAX_RETRIES ]; then
          echo -e "\033[0;31m❌ ERROR: Could not connect to API server after 30 attempts. Manual intervention required.\033[0m"
          echo -e "\033[0;33m📋 Troubleshooting tips:\033[0m"
          echo -e "   1. SSH to control plane: ssh ubuntu@${module.k8s-cluster.control_plane_public_ip}"
          echo -e "   2. Check logs: sudo journalctl -u kubelet"
          echo -e "   3. Check status: sudo systemctl status kubelet"
          echo -e "   4. Check pods: sudo kubectl get pods -A"
          exit 1
        else
          echo -e "\033[0;33m⏱️  Retry $i/$MAX_RETRIES - Waiting $RETRY_INTERVAL seconds before next attempt...\033[0m"
          sleep $RETRY_INTERVAL &
          spinner $!
        fi
      done
      
      echo -e "\033[1;34m==== 🚀 Creating Kubernetes Namespaces ====\033[0m"
      
      # Create dev namespace
      echo -e "\033[0;33m🔨 Creating dev namespace...\033[0m"
      kubectl create namespace dev --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      # Create prod namespace
      echo -e "\033[0;33m🔨 Creating prod namespace...\033[0m"
      kubectl create namespace prod --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      # Create argocd namespace
      echo -e "\033[0;33m🔨 Creating argocd namespace...\033[0m"
      kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply --validate=false -f -
      
      echo -e "\033[0;32m✅ Namespaces created successfully!\033[0m"
      echo -e "\033[1;34m===============================================\033[0m"
    EOT
  }
}

module "k8s-cluster" {
  source                      = "./modules/k8s-cluster"
  region                      = var.region
  cluster_name                = "polybot-cluster"
  vpc_id                      = var.vpc_id
  subnet_ids                  = var.subnet_ids
  control_plane_instance_type = "t3.medium"
  worker_instance_type        = "t3.medium"
  worker_count                = 2
  route53_zone_id             = var.route53_zone_id
  key_name                    = var.key_name
  control_plane_ami           = var.control_plane_ami
  worker_ami                  = var.worker_ami
  rebuild_control_plane       = false # Set to true only when you need to force a rebuild

  addons = [
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/storage-class.yaml",
    "https://raw.githubusercontent.com/scholzj/terraform-aws-kubernetes/master/addons/autoscaler.yaml"
  ]

  # Start with the initialization resource that creates a valid kubeconfig
  depends_on = [terraform_data.init_environment, terraform_data.deployment_information]
}

# Install EBS CSI Driver using local-exec only
resource "null_resource" "install_ebs_csi_driver" {
  # Use a static count value
  count = 1
  
  # Only run after we have a valid kubeconfig
  depends_on = [
    module.k8s-cluster, 
    null_resource.wait_for_kubernetes, 
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready
  ]
  
  # Only run when needed, based on resource changes
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    instance_id = module.k8s-cluster.control_plane_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "Checking if kubeconfig is valid before installing EBS CSI Driver..."
      KUBECONFIG="${local.kubeconfig_path}"
      
      if [ ! -f "$KUBECONFIG" ]; then
        echo "Kubeconfig file not found, skipping installation"
        exit 0
      fi
      
      # Check if kubeconfig contains placeholder values
      if grep -q "placeholder" "$KUBECONFIG"; then
        echo "Kubeconfig contains placeholder values, skipping installation"
        exit 0
      fi
      
      # Check if we can connect to the Kubernetes API
      if ! kubectl --kubeconfig="$KUBECONFIG" get nodes >/dev/null 2>&1; then
        echo "Cannot connect to Kubernetes cluster, skipping installation"
        exit 0
      fi
      
      # Install EBS CSI Driver using kubectl
      echo "Creating kube-system namespace if it doesn't exist..."
      kubectl --kubeconfig="$KUBECONFIG" create namespace kube-system --dry-run=client -o yaml | kubectl --kubeconfig="$KUBECONFIG" apply -f -
      
      echo "Creating EBS CSI Driver service account..."
      cat <<EOF | kubectl --kubeconfig="$KUBECONFIG" apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebs-csi-controller-sa
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: "${module.k8s-cluster.control_plane_iam_role_arn}"
EOF
      
      echo "Installing EBS CSI Driver..."
      kubectl --kubeconfig="$KUBECONFIG" apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=master"
      
      echo "Creating storage class..."
      cat <<EOF | kubectl --kubeconfig="$KUBECONFIG" apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  csi.storage.k8s.io/fstype: ext4
  type: gp2
  encrypted: "true"
EOF
      
      echo "EBS CSI Driver installation completed"
    EOT
  }
}

# Output commands for manual verification and namespace creation
resource "null_resource" "cluster_readiness_info" {
  # Use a static count value
  count = 1

  depends_on = [
    module.k8s-cluster,
    terraform_data.kubectl_provider_config
  ]

  # Only trigger when kubernetes-related resources change
  triggers = {
    # Track changes to the control plane or kubeconfig
    control_plane_id = try(module.k8s-cluster.control_plane_id, "none")
    kubeconfig_status = fileexists("${path.module}/kubeconfig.yaml") ? filemd5("${path.module}/kubeconfig.yaml") : "not_exists"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      echo "---------------------------------------------------------"
      echo "KUBERNETES CLUSTER DEPLOYMENT INFORMATION"
      echo "---------------------------------------------------------"
      echo "Kubernetes control plane IP: ${try(module.k8s-cluster.control_plane_public_ip, "Not available yet")}"
      echo "Kubeconfig file: ${local.kubeconfig_path}"
      echo ""
      echo "To manually verify the cluster and create namespaces, run:"
      echo "export KUBECONFIG=${local.kubeconfig_path}"
      echo "kubectl get nodes"
      echo "kubectl create namespace dev --dry-run=client -o yaml | kubectl apply --validate=false -f -"
      echo "kubectl create namespace prod --dry-run=client -o yaml | kubectl apply --validate=false -f -"
      echo "kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply --validate=false -f -"
      echo ""
      echo "When cluster is verified as working, set skip_namespaces = false in locals"
      echo "---------------------------------------------------------"
    EOT
  }
}

terraform {
  # Standard configuration without experimental features
}

# Display important information at the start of deployment
resource "terraform_data" "deployment_information" {
  # Run only on first apply or when Terraform files change
  triggers_replace = {
    module_hash = filemd5("${path.module}/main.tf") 
    variables_hash = filemd5("${path.module}/variables.tf")
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      # Save the start time for later tracking
      date +%s > /tmp/tf_start_time.txt
      
      echo -e "\033[1;34m========================================================\033[0m"
      echo -e "\033[1;34m     🚀 Polybot Kubernetes Deployment Started 🚀\033[0m"
      echo -e "\033[1;34m========================================================\033[0m"
      echo -e "\033[0;33m⏱️  This deployment takes approximately 10 minutes.\033[0m"
      echo -e "\033[0;33m⏱️  Progress indicators will be displayed throughout.\033[0m"
      echo -e "\033[0;33m⏱️  Colorful status updates will show deployment stages.\033[0m"
      echo -e "\033[0;33m⏱️  The first 5 minutes are AWS resources creation.\033[0m"
      echo -e "\033[0;33m⏱️  The next 5 minutes are Kubernetes initialization.\033[0m"
      echo -e "\033[0;32m➡️  Beginning infrastructure deployment now...\033[0m"
      
      # No background processes to avoid blocking terraform
    EOT
  }
}

# Final progress information and timing resource
resource "terraform_data" "deployment_completion_information" {
  depends_on = [
    module.k8s-cluster,
    module.polybot_dev,
    module.polybot_prod
  ]

  # Run when actual infrastructure components change
  triggers_replace = {
    cluster_id = try(module.k8s-cluster.control_plane_id, "none")
    dev_id = try(module.polybot_dev.polybot_s3_id, "none") 
    prod_id = try(module.polybot_prod.polybot_s3_id, "none")
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      # Simple completion message - no time tracking to avoid complexity
      echo -e "\033[1;34m========================================================\033[0m"
      echo -e "\033[1;32m     ✅ Polybot Kubernetes Deployment Complete! ✅\033[0m"
      echo -e "\033[1;34m========================================================\033[0m"
    EOT
  }
}

# Special resource to clean up Kubernetes state
resource "terraform_data" "kubernetes_state_clean" {
  # Use deterministic triggers for cleanup
  triggers_replace = {
    # We only need this to run during destroy operations, but with a stable hash
    kubeconfig_status = fileexists("${path.module}/kubeconfig.yaml") ? filemd5("${path.module}/kubeconfig.yaml") : "not_exists"
    module_hash = filemd5("${path.module}/main.tf")
  }

  # This will only be executed during destroy operations
  provisioner "local-exec" {
    when = destroy
    command = <<-EOT
      echo "Removing Kubernetes-dependent resources from state if needed..."
      terraform state rm null_resource.wait_for_kubernetes[0] || true
      terraform state rm null_resource.install_ebs_csi_driver[0] || true
      terraform state rm null_resource.install_argocd[0] || true
      terraform state rm null_resource.create_namespaces[0] || true
      terraform state rm null_resource.providers_ready[0] || true
      terraform state rm terraform_data.kubectl_provider_config[0] || true
      echo "Kubernetes resources cleaned up from state."
    EOT
  }
}

# Add a separate cleanup for any remaining files
resource "terraform_data" "final_cleanup" {
  count = 1
  
  # This will run last during destroy
  depends_on = [
    module.k8s-cluster,
    module.polybot_dev,
    module.polybot_prod
  ]
  
  # Use deterministic triggers that relate to the resources we're cleaning up
  triggers_replace = {
    cluster_id = try(module.k8s-cluster.control_plane_id, "none")
    dev_id = try(module.polybot_dev.polybot_s3_id, "none")
    prod_id = try(module.polybot_prod.polybot_s3_id, "none")
  }
  
  # Only remove files during destroy, don't try to kill processes
  provisioner "local-exec" {
    when = destroy
    # Just echo a message instead of doing anything that could cause termination
    command = "echo 'Cleaning up temporary files...'"
  }
}

# Development environment resources
module "polybot_dev" {
  source                = "./modules/polybot"
  region                = var.region
  route53_zone_id       = var.route53_zone_id
  alb_dns_name          = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id           = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment           = "dev"
  telegram_token        = var.telegram_token_dev
  aws_access_key_id     = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username       = var.docker_username
  docker_password       = var.docker_password
}

# Production environment resources
module "polybot_prod" {
  source                = "./modules/polybot"
  region                = var.region
  route53_zone_id       = var.route53_zone_id
  alb_dns_name          = try(module.k8s-cluster.alb_dns_name, "dummy-dns-name")
  alb_zone_id           = try(module.k8s-cluster.alb_zone_id, "dummy-zone-id")
  environment           = "prod"
  telegram_token        = var.telegram_token_prod
  aws_access_key_id     = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  docker_username       = var.docker_username
  docker_password       = var.docker_password
}


