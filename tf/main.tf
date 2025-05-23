provider "aws" {
  region = var.region
  # Note: If explicit deny issues persist, consider this alternative approach
  # Uncomment and set role_arn to a role with appropriate permissions
  # assume_role {
  #   role_arn = "arn:aws:iam::${var.account_id}:role/terraform-deployer-role"
  # }
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
  
  depends_on = [
    module.k8s-cluster,
    terraform_data.init_environment
  ]
  
  triggers = {
    control_plane_id = try(module.k8s-cluster.control_plane_id, "none")
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      # Define key path with better fallback logic and early validation
      KEY_PATH=""
      if [ -n "${var.key_name}" ]; then
        # Try home directory first
        if [ -f "$HOME/.ssh/${var.key_name}.pem" ]; then
          KEY_PATH="$HOME/.ssh/${var.key_name}.pem"
        # Then try current directory
        elif [ -f "${path.module}/${var.key_name}.pem" ]; then
          KEY_PATH="${path.module}/${var.key_name}.pem"
        else
          echo "WARNING: Specified key ${var.key_name}.pem not found in $HOME/.ssh or ${path.module}"
        fi
      fi
      
      # If key_name wasn't specified or wasn't found, use the generated key
      if [ -z "$KEY_PATH" ] || [ ! -f "$KEY_PATH" ]; then
        # Try polybot-key.pem in module path first
        if [ -f "${path.module}/polybot-key.pem" ]; then
          KEY_PATH="${path.module}/polybot-key.pem"
        # Then try generated key if it exists
        elif [ -f "${path.module}/generated-ssh-key.pem" ]; then
          KEY_PATH="${path.module}/generated-ssh-key.pem"
        else
          echo "ERROR: No valid SSH key found! Cannot continue."
          echo "Looking for key in: "
          echo "  - $HOME/.ssh/${var.key_name}.pem"
          echo "  - ${path.module}/${var.key_name}.pem"
          echo "  - ${path.module}/polybot-key.pem"
          echo "  - ${path.module}/generated-ssh-key.pem"
          exit 0  # Don't fail Terraform, just log the error
        fi
      fi
      
      echo "Using SSH key: $KEY_PATH"
      chmod 600 "$KEY_PATH" || echo "Warning: Could not set permissions on key"
      
      # Define variables
      CONTROL_PLANE_IP="${try(module.k8s-cluster.control_plane_public_ip, "")}"
      MAX_RETRIES=60  # Increased from 30
      RETRY_INTERVAL=20
      
      # Verify control plane IP is available
      if [ -z "$CONTROL_PLANE_IP" ]; then
        echo "Error: No running control plane instance found"
        exit 0  # Don't fail, let Terraform handle retries
      fi
      
      echo "Control plane IP: $CONTROL_PLANE_IP"
      echo "Waiting for Kubernetes API to become available..."
      
      # Try to connect to the Kubernetes API with retries
      for ((i=1; i<=MAX_RETRIES; i++)); do
        echo "Attempt $i/$MAX_RETRIES: Testing SSH connectivity..."
        
        # Test SSH connectivity first with better timeout and debugging
        if ssh -i "$KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes -v ubuntu@$CONTROL_PLANE_IP "echo SSH connection successful"; then
          echo "SSH connection successful!"
          
          # Now check if Kubernetes API is responding
          if ssh -i "$KEY_PATH" -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP "sudo kubectl get nodes --request-timeout=5s"; then
            echo "Kubernetes API is responding!"
            
            # Copy kubeconfig and fix permissions
            echo "Copying kubeconfig from control plane..."
            scp -i "$KEY_PATH" -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP:/home/ubuntu/.kube/config "${path.module}/kubeconfig.yaml" || \
            scp -i "$KEY_PATH" -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP:/etc/kubernetes/admin.conf "${path.module}/kubeconfig.yaml"
            
            chmod 600 "${path.module}/kubeconfig.yaml"
            
            # Update kubeconfig with correct IP
            echo "Updating kubeconfig with control plane public IP..."
            sed -i.bak "s/https:\/\/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/https:\/\/$CONTROL_PLANE_IP/g" "${path.module}/kubeconfig.yaml" || \
            sed -i "s/https:\/\/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/https:\/\/$CONTROL_PLANE_IP/g" "${path.module}/kubeconfig.yaml"
            
            echo "Kubernetes is ready and kubeconfig is updated"
            exit 0
          else
            echo "Kubernetes API not ready yet, will retry..."
          fi
        else
          echo "SSH connection failed, will retry..."
        fi
        
        sleep $RETRY_INTERVAL
      done
      
      echo "Warning: Maximum retries reached. Kubernetes API might not be ready yet."
      exit 0  # Don't fail, let Terraform continue
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
  
  # Only run when ArgoCD changes or kubeconfig changes - don't reference kubeconfig directly
  triggers = {
    argocd_install = null_resource.install_argocd[0].id
    kubeconfig = terraform_data.kubectl_provider_config[0].id
    time = timestamp()  # Ensure this runs when needed, since kubeconfig changes during apply
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
      
      # Create a simplified SSH tunnel script
      cat > ~/argocd-ssh-tunnel.sh << 'EOFBASIC'
#!/bin/bash
# ArgoCD SSH Tunnel Script - Generated by Terraform

# Configuration 
SSH_KEY="$HOME/polybot-key.pem"
CONTROL_PLANE_IP="CONTROL_PLANE_IP_PLACEHOLDER"
LOCAL_PORT=8081
REMOTE_PORT=443
ARGOCD_NAMESPACE="argocd"
ARGOCD_SERVICE="argocd-server"
ARGOCD_LABEL="app.kubernetes.io/name=argocd-server"
TIMEOUT_SECONDS=300

# Cleanup function for proper termination
function cleanup() {
  echo "Cleaning up connections..."
  
  # Kill local SSH tunnel
  if pgrep -f "ssh.*-L $LOCAL_PORT:localhost:$LOCAL_PORT" > /dev/null; then
    echo "Terminating local SSH tunnel..."
    pkill -f "ssh.*-L $LOCAL_PORT:localhost:$LOCAL_PORT" > /dev/null 2>&1
  fi
  
  # Kill remote kubectl port-forward
  echo "Terminating remote port forwarding..."
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP \
    "pkill -f 'kubectl.*port-forward'" > /dev/null 2>&1 || true
    
  echo "Tunnel closed successfully."
  exit 0
}

# Register cleanup for all termination scenarios
trap cleanup EXIT INT TERM

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v ssh &> /dev/null; then
  echo "SSH client not found. Please install it."
  exit 1
fi

if ! command -v lsof &> /dev/null; then
  echo "lsof not found. Port checking will be limited."
fi

# Check SSH key
if [ ! -f "$SSH_KEY" ]; then
  echo "SSH key not found at $SSH_KEY"
  exit 1
fi

chmod 600 "$SSH_KEY"

# Check if control plane is reachable
echo "Checking connection to control plane ($CONTROL_PLANE_IP)..."
if ! ping -c 1 -W 2 $CONTROL_PLANE_IP > /dev/null 2>&1; then
  echo "Control plane not responding to ping (may be normal if ICMP is blocked)."
fi

# Check if we can SSH to the control plane
if ! ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
  ubuntu@$CONTROL_PLANE_IP "echo Connected" > /dev/null 2>&1; then
  echo "Cannot SSH to control plane. Check your SSH key and network connectivity."
  exit 1
fi

# Check and free local port if needed
echo "Checking local port $LOCAL_PORT..."
if lsof -ti:$LOCAL_PORT > /dev/null 2>&1; then
  echo "Port $LOCAL_PORT is already in use, attempting to free it..."
  lsof -ti:$LOCAL_PORT | xargs kill -9 > /dev/null 2>&1
  sleep 1
  
  if lsof -ti:$LOCAL_PORT > /dev/null 2>&1; then
    echo "Could not free port $LOCAL_PORT. Please close applications using it or change the port."
    exit 1
  fi
  echo "Port $LOCAL_PORT freed successfully."
else
  echo "Local port $LOCAL_PORT is available."
fi

# Check remote port forwarding and clean up if needed
echo "Checking remote port forwarding..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP \
  "if pgrep -f 'kubectl.*port-forward' > /dev/null; then pkill -f 'kubectl.*port-forward'; echo 'Killed existing port-forward'; fi" \
  > /dev/null 2>&1

# Wait for ArgoCD pod to be ready
echo "Checking if ArgoCD pod is ready..."
READY_STATUS=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP \
  "kubectl get pod -n $ARGOCD_NAMESPACE -l $ARGOCD_LABEL -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready\")].status}'" 2>/dev/null)

if [ "$READY_STATUS" != "True" ]; then
  echo "ArgoCD pod not ready. Waiting up to $TIMEOUT_SECONDS seconds..."
  
  START_TIME=$(date +%s)
  while true; do
    ELAPSED_TIME=$(( $(date +%s) - START_TIME ))
    if [ $ELAPSED_TIME -ge $TIMEOUT_SECONDS ]; then
      echo "Timed out waiting for ArgoCD pod to become ready."
      echo "Continuing anyway, but ArgoCD might not be accessible yet."
      break
    fi
    
    READY_STATUS=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP \
      "kubectl get pod -n $ARGOCD_NAMESPACE -l $ARGOCD_LABEL -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready\")].status}'" 2>/dev/null)
    
    if [ "$READY_STATUS" = "True" ]; then
      echo "ArgoCD pod is ready!"
      break
    fi
    
    echo "Waiting for ArgoCD pod to be ready... ($ELAPSED_TIME/$TIMEOUT_SECONDS seconds)"
    sleep 5
  done
else
  echo "ArgoCD pod is already ready!"
fi

# Setup port forwarding
echo "Setting up port forwarding on control plane..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP \
  "kubectl port-forward -n $ARGOCD_NAMESPACE svc/$ARGOCD_SERVICE $LOCAL_PORT:$REMOTE_PORT --address 0.0.0.0 > /dev/null 2>&1 &"

sleep 2

# Check if port forwarding is active on the remote machine
PF_CHECK=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$CONTROL_PLANE_IP \
  "pgrep -f 'kubectl.*port-forward.*$ARGOCD_SERVICE' || echo 'none'")

if [ "$PF_CHECK" = "none" ]; then
  echo "Failed to set up port forwarding on control plane."
  exit 1
fi

echo "Port forwarding is active on control plane (PID: $PF_CHECK)."

# Get password for display
PASSWORD=$(cat /tmp/argocd-admin-password.txt 2>/dev/null || echo "Not available - check with kubectl")

# Start SSH tunnel
echo "Starting SSH tunnel to ArgoCD..."

echo ""
echo "==========================================="
echo "       ArgoCD Access Information           "
echo "==========================================="
echo "URL:      https://localhost:$LOCAL_PORT"
echo "Username: admin"
echo "Password: $PASSWORD"
echo ""
echo "Press Ctrl+C to close the connection"
echo "==========================================="
echo ""

# Start SSH tunnel in foreground mode with good options
ssh -i "$SSH_KEY" \
  -L $LOCAL_PORT:localhost:$LOCAL_PORT \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=no \
  -N \
  ubuntu@$CONTROL_PLANE_IP

# The cleanup function will handle termination
echo "SSH tunnel closed."
EOFBASIC

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
  control_plane_instance_type = "t3.medium"  # Reverted back to original type
  worker_instance_type        = "t3.medium"  # Reverted back to original type
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
  
  # Only run after we have a valid kubeconfig and the service-linked role is created
  depends_on = [
    module.k8s-cluster, 
    null_resource.wait_for_kubernetes, 
    terraform_data.kubectl_provider_config,
    null_resource.providers_ready,
    terraform_data.ebs_service_role_setup,
    null_resource.verify_ebs_role
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
      
      # Clean up old EBS CSI driver files if they exist
      echo "Cleaning up any old EBS CSI Driver installations..."
      kubectl --kubeconfig="$KUBECONFIG" delete -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=master" --ignore-not-found=true || true
      sleep 5
      
      # Install EBS CSI Driver using kubectl
      echo "Creating kube-system namespace if it doesn't exist..."
      kubectl --kubeconfig="$KUBECONFIG" create namespace kube-system --dry-run=client -o yaml | kubectl --kubeconfig="$KUBECONFIG" apply -f -
      
      # Check for required AWS role before proceeding
      echo "Verifying AWS role for EBS CSI Driver..."
      aws sts get-caller-identity >/dev/null || {
        echo "⚠️ AWS CLI not configured properly. Make sure your AWS credentials are valid."
        echo "Continuing anyway as the EBS CSI driver may still work if the role exists in AWS."
      }
      
      # Check if the EBS service role exists without requiring creation permissions
      if ! aws iam get-role --role-name AWSServiceRoleForEBS >/dev/null 2>&1; then
        echo "⚠️ Warning: EBS service role not found. Volume provisioning may fail."
        echo "Consider creating it manually with: aws iam create-service-linked-role --aws-service-name ec2.amazonaws.com"
      else
        echo "✅ EBS service role exists. Proceeding with installation."
      fi
      
      echo "Creating EBS CSI Driver service account..."
      cat <<EOF | kubectl --kubeconfig="$KUBECONFIG" apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebs-csi-controller-sa
  namespace: kube-system
EOF
      
      echo "Installing EBS CSI Driver..."
      kubectl --kubeconfig="$KUBECONFIG" apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=master" || {
        echo "⚠️ Error installing EBS CSI Driver. This may be a permissions issue."
        echo "You may need to manually create the service role or grant the required permissions."
        echo "Continuing deployment, but dynamic volume provisioning may not work."
      }
      
      echo "EBS CSI Driver installation completed. Now creating storage classes..."
    EOT
  }
}

# Add the storage class resource after the EBS CSI driver resource
# Look for the end of the install_ebs_csi_driver resource and add after it

resource "null_resource" "create_storage_classes" {
  count = 1
  
  depends_on = [
    null_resource.install_ebs_csi_driver
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "Cleaning up any existing storage classes to avoid conflicts..."
      # Check if NGINX Ingress is already installed
      if kubectl get ns ingress-nginx &>/dev/null && kubectl get deployment -n ingress-nginx ingress-nginx-controller &>/dev/null; then
        echo "NGINX Ingress Controller already installed, skipping installation"
        exit 0
      fi
      
      echo "Creating ingress-nginx namespace..."
      kubectl create namespace ingress-nginx --dry-run=client -o yaml | kubectl apply -f -
      
      echo "Installing NGINX Ingress Controller..."
      kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/aws/deploy.yaml
      
      # Wait for the Ingress Controller to be ready - increase timeout
      echo "Waiting for NGINX Ingress Controller to be ready (may take up to 10 minutes)..."
      for i in {1..20}; do
        if kubectl -n ingress-nginx get deployment ingress-nginx-controller | grep -q "1/1"; then
          echo "NGINX Ingress Controller is ready!"
          break
        fi
        echo "Waiting for NGINX Ingress Controller to be ready, attempt $i/20..."
        sleep 30
      done
      
      echo "NGINX Ingress Controller installation complete"
    EOT
  }
}

# Now let's set up ArgoCD applications for polybot and its dependencies
resource "null_resource" "configure_argocd_apps" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.install_argocd,
    # null_resource.install_nginx_ingress,  # Commented out since this resource no longer exists
    null_resource.configure_argocd_repositories
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
    argocd_install = null_resource.install_argocd[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Create MongoDB namespace
      echo "Creating MongoDB namespace..."
      kubectl create namespace mongodb --dry-run=client -o yaml | kubectl apply -f -
      
      # Create ArgoCD application manifests directory
      mkdir -p /tmp/argocd-apps
      
      # Create persistent volume provisioning
      echo "Creating storage class for EBS..."
      
      # Check if the storage class already exists
      if kubectl get storageclass ebs-sc &>/dev/null; then
        echo "Storage class ebs-sc already exists, removing it first to avoid parameter update errors..."
        kubectl delete storageclass ebs-sc --wait=false
        sleep 5  # Give Kubernetes some time to process the deletion
      fi
      
      # Create the storage class with replace if it exists
      kubectl apply -f - --force --grace-period=0 <<EOF
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
EOF
      
      # Create MongoDB ArgoCD application
      cat > /tmp/argocd-apps/mongodb-app.yaml << 'EOF'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: mongodb
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://charts.bitnami.com/bitnami
    chart: mongodb
    targetRevision: 13.6.0
    helm:
      values: |
        architecture: replicaset
        replicaCount: 3
        auth:
          enabled: true
          rootPassword: mongopassword
          username: polybot
          password: polybot
          database: polybot
        persistence:
          enabled: true
          storageClass: "ebs-sc"
          size: 8Gi
  destination:
    server: https://kubernetes.default.svc
    namespace: mongodb
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
EOF
      
      # Create NGINX deployment instead of using private repo
      cat > /tmp/argocd-apps/nginx-app.yaml << 'EOF'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: nginx-app
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://charts.bitnami.com/bitnami
    chart: nginx
    targetRevision: 15.0.2
    helm:
      values: |
        service:
          type: ClusterIP
        replicaCount: 1
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
EOF
      
      # Apply ArgoCD applications
      echo "Applying ArgoCD applications..."
      kubectl apply -f /tmp/argocd-apps/mongodb-app.yaml
      kubectl apply -f /tmp/argocd-apps/nginx-app.yaml
      
      echo "Deleting old applications that had repository errors..."
      kubectl delete application -n argocd polybot yolo5 --ignore-not-found
      
      echo "ArgoCD applications configured. They will start syncing automatically."
      echo "Note: For Polybot and Yolo5, you'll need to provide your own GitHub credentials."
    EOT
  }
}

# Modify Calico/Tigera installation to be more robust
resource "null_resource" "install_calico" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.providers_ready,
    null_resource.wait_for_kubernetes,
    module.kubernetes_resources.null_resource.improved_disk_cleanup,
    terraform_data.kubectl_provider_config
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # First check if worker nodes have disk pressure
      echo "Checking node status before Calico installation..."
      NODES_WITH_PRESSURE=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="DiskPressure")].status}{"\n"}{end}' | grep True || echo "")
      
      if [ ! -z "$NODES_WITH_PRESSURE" ]; then
        echo "Some nodes have disk pressure, running cleanup before Calico installation..."
        # Delete tigera-operator namespace if it exists to ensure clean slate
        kubectl delete namespace tigera-operator --ignore-not-found=true
        # Delete evicted pods
        kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.status.reason=="Evicted") | .metadata.namespace + " " + .metadata.name' | while read ns name; do 
          kubectl delete pod -n $ns $name || true
        done
        echo "Cleaned up evicted pods"
        sleep 30
      fi
      
      # Check if Calico is already installed
      if kubectl get ns tigera-operator &>/dev/null; then
        echo "Tigera operator namespace exists, checking if operator is functional..."
        if kubectl -n tigera-operator get pods | grep -q "Running"; then
          echo "Calico already installed and running, skipping installation"
          exit 0
        else
          echo "Tigera operator exists but pods aren't running, cleaning up..."
          kubectl delete namespace tigera-operator
          sleep 30
        fi
      fi
      
      echo "Installing Tigera Calico operator with simplified approach..."
      # Create namespace first
      kubectl create namespace tigera-operator --dry-run=client -o yaml | kubectl apply -f -
      
      # Download the official operator YAML but remove the long annotations that cause the error
      curl -s https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml | \
      grep -v "_description:" | \
      kubectl apply -f -
      
      echo "Waiting 60 seconds for operator to initialize..."
      sleep 60
      
      echo "Checking if operator is running..."
      if ! kubectl -n tigera-operator get pods | grep -q "Running"; then
        echo "Operator isn't running yet, will continue but installation may fail"
      fi
      
      echo "Installing Calico custom resources with minimal configuration..."
      cat <<EOF | kubectl apply -f -
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    ipPools:
    - blockSize: 26
      cidr: 192.168.0.0/16
      encapsulation: VXLANCrossSubnet
      natOutgoing: Enabled
      nodeSelector: all()
  # Add resource recommendations to avoid resource pressure
  componentResources:
  - componentName: Node
    resourceRequirements:
      limits:
        cpu: 500m
        memory: 512Mi
      requests:
        cpu: 100m
        memory: 256Mi
  - componentName: Typha
    resourceRequirements:
      limits:
        cpu: 300m
        memory: 256Mi
      requests:
        cpu: 100m
        memory: 128Mi
EOF
      
      echo "Calico installation initiated with minimal config."
      echo "Waiting for Calico to be ready (this may take a few minutes)..."
      for i in {1..30}; do
        if kubectl get pods -n calico-system | grep -q "Running"; then
          echo "Calico pods are starting to run. Continuing deployment."
          break
        fi
        echo "Waiting for Calico pods to start... Attempt $i/30"
        sleep 20
      done
      
      echo "Note: Full Calico startup can take several minutes. Check with: kubectl get pods -A"
    EOT
  }
}

# Configure ArgoCD with repository credentials
resource "null_resource" "configure_argocd_repositories" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.install_argocd,
    null_resource.argocd_direct_access
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      # Create the repository configuration secret
      echo "Configuring public Helm repository access..."
      
      kubectl -n argocd apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: helm-repos
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  name: bitnami
  url: https://charts.bitnami.com/bitnami
EOF
      
      echo "ArgoCD repositories configured."
    EOT
  }
}

# Add this resource after the null_resource.fix_argocd_connectivity resource
resource "null_resource" "cleanup_worker_nodes" {
  # Skip this resource since it's duplicated in the kubernetes_resources module
  count = 0  # Set to 0 to disable as we're using the module version instead

  # Remove dependency on fix_argocd_connectivity
  depends_on = [null_resource.install_ebs_csi_driver]

  provisioner "local-exec" {
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="./kubeconfig.yaml"
      
      echo "Cleaning up evicted pods..."
      kubectl get pods --all-namespaces | grep Evicted | awk '{print $2 " --namespace=" $1}' | xargs -L1 kubectl delete pod || true
      
      echo "Setting up node disk cleanup job..."
      cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: node-cleanup
  namespace: kube-system
spec:
  schedule: "0 */6 * * *"  # Run every 6 hours
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          tolerations:
          - key: node-role.kubernetes.io/master
            effect: NoSchedule
          - key: node-role.kubernetes.io/control-plane
            effect: NoSchedule
          containers:
          - name: cleanup
            image: ubuntu:20.04
            resources:
              requests:
                memory: "128Mi"
                cpu: "100m"
              limits:
                memory: "256Mi"
                cpu: "200m"
            command:
            - /bin/sh
            - -c
            - |
              apt-get update && apt-get install -y docker.io
              echo "Cleaning up Docker system..."
              docker system prune -af
              echo "Clearing logs..."
              find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
              echo "Clearing journal logs..."
              journalctl --vacuum-time=1d
              echo "Clearing temp files..."
              rm -rf /tmp/*
              echo "Node cleanup completed"
            securityContext:
              privileged: true
            volumeMounts:
            - name: var-log
              mountPath: /var/log
            - name: var-lib-docker
              mountPath: /var/lib/docker
            - name: run
              mountPath: /run
            - name: tmp 
              mountPath: /tmp
          volumes:
          - name: var-log
            hostPath:
              path: /var/log
          - name: var-lib-docker
            hostPath:
              path: /var/lib/docker
          - name: run
            hostPath:
              path: /run
          - name: tmp
            hostPath:
              path: /tmp
          restartPolicy: OnFailure
          hostNetwork: true
          hostPID: true
EOF
      
      # Execute a disk cleanup job immediately - fix find command syntax
      echo "Running immediate disk cleanup on worker nodes..."
      cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: disk-cleanup-now
  namespace: kube-system
spec:
  ttlSecondsAfterFinished: 100
  activeDeadlineSeconds: 300  # Add 5-minute timeout to prevent job from hanging
  template:
    spec:
      tolerations:
      - operator: Exists
      containers:
      - name: cleanup
        image: ubuntu:20.04
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        command:
        - /bin/sh
        - -c
        - |
          apt-get update && apt-get install -y docker.io
          echo "Emergency cleanup - freeing disk space..."
          docker system prune -af
          find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
          find /var/log -type f -size +10M -delete
          journalctl --vacuum-time=1d
          rm -rf /tmp/*
          echo "Emergency cleanup completed"
        securityContext:
          privileged: true
        volumeMounts:
        - name: var-log
          mountPath: /var/log
        - name: var-lib-docker
          mountPath: /var/lib/docker
        - name: run
          mountPath: /run
        - name: tmp 
          mountPath: /tmp
      volumes:
      - name: var-log
        hostPath:
          path: /var/log
      - name: var-lib-docker
        hostPath:
          path: /var/lib/docker
      - name: run
        hostPath:
          path: /run
      - name: tmp
        hostPath:
          path: /tmp
      restartPolicy: Never
      hostNetwork: true
      hostPID: true
EOF
      
      # Increase timeout for cleanup job
      echo "Waiting for emergency disk cleanup to complete (max 3 minutes)..."
      kubectl -n kube-system wait --for=condition=complete job/disk-cleanup-now --timeout=180s || true
      
      # Force continue even if job hasn't completed
      echo "Continuing deployment whether cleanup is done or not..."
      kubectl get nodes
      
      echo "Cleanup job created successfully."
    EOT
  }
}

# Create MongoDB directly without ArgoCD, but with simpler implementation
resource "null_resource" "deploy_mongodb_directly" {
  count = local.skip_argocd ? 0 : 1
  
  depends_on = [
    null_resource.install_ebs_csi_driver,
    module.kubernetes_resources.null_resource.improved_disk_cleanup,
    null_resource.install_calico
  ]
  
  triggers = {
    kubeconfig_id = terraform_data.kubectl_provider_config[0].id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${local.kubeconfig_path}"
      
      echo "Creating MongoDB namespace if it doesn't exist..."
      kubectl create namespace mongodb --dry-run=client -o yaml | kubectl apply -f -
      
      echo "Checking if MongoDB is already deployed..."
      if kubectl -n mongodb get statefulset mongodb &>/dev/null; then
        echo "MongoDB is already deployed, skipping creation"
      else
        echo "Ensuring correct storage class exists for MongoDB..."
        if ! kubectl get storageclass mongodb-sc &>/dev/null; then
          echo "Creating MongoDB storage class..."
          kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: mongodb-sc
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  csi.storage.k8s.io/fstype: ext4
  type: gp2
EOF
        else
          echo "MongoDB storage class already exists, checking if it needs to be updated..."
          # Check if the existing storage class has the correct parameters
          if ! kubectl get storageclass mongodb-sc -o yaml | grep -q "csi.storage.k8s.io/fstype: ext4"; then
            echo "Storage class needs updating, deleting and recreating..."
            kubectl delete storageclass mongodb-sc --wait=false
            sleep 5  # Give Kubernetes some time to process the deletion
            kubectl apply -f - --force --grace-period=0 <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: mongodb-sc
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  csi.storage.k8s.io/fstype: ext4
  type: gp2
EOF
          else
            echo "MongoDB storage class has correct parameters, skipping update"
          fi
        fi
        
        echo "Creating MongoDB StatefulSet directly..."
        kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: mongodb-config
  namespace: mongodb
data:
  mongo.conf: |
    storage:
      dbPath: /data/db
    net:
      bindIp: 0.0.0.0
    replication:
      replSetName: rs0
---
apiVersion: v1
kind: Secret
metadata:
  name: mongodb-secret
  namespace: mongodb
type: Opaque
data:
  MONGO_INITDB_ROOT_USERNAME: YWRtaW4=
  MONGO_INITDB_ROOT_PASSWORD: cGFzc3dvcmQ=
---
apiVersion: v1
kind: Service
metadata:
  name: mongodb-headless
  namespace: mongodb
  labels:
    app: mongodb
spec:
  clusterIP: None
  selector:
    app: mongodb
  ports:
  - port: 27017
    targetPort: 27017
---
apiVersion: v1
kind: Service
metadata:
  name: mongodb
  namespace: mongodb
  labels:
    app: mongodb
spec:
  selector:
    app: mongodb
  ports:
  - port: 27017
    targetPort: 27017
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mongodb
  namespace: mongodb
spec:
  serviceName: mongodb-headless
  replicas: 1
  selector:
    matchLabels:
      app: mongodb
  template:
    metadata:
      labels:
        app: mongodb
    spec:
      containers:
      - name: mongodb
        image: mongo:4.4
        resources:
          limits:
            cpu: "0.5"
            memory: "512Mi"
          requests:
            cpu: "0.2"
            memory: "256Mi"
        env:
        - name: MONGO_INITDB_ROOT_USERNAME
          valueFrom:
            secretKeyRef:
              name: mongodb-secret
              key: MONGO_INITDB_ROOT_USERNAME
        - name: MONGO_INITDB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mongodb-secret
              key: MONGO_INITDB_ROOT_PASSWORD
        ports:
        - containerPort: 27017
        volumeMounts:
        - name: data
          mountPath: /data/db
        - name: config
          mountPath: /config
        command:
        - "mongod"
        - "--config=/config/mongo.conf"
        # Add readiness probe
        readinessProbe:
          exec:
            command:
            - mongo
            - --eval
            - "db.adminCommand('ping')"
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 6
      volumes:
      - name: config
        configMap:
          name: mongodb-config
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "mongodb-sc"
      resources:
        requests:
          storage: 1Gi
EOF
      fi
      
      # Wait for MongoDB pod to start
      echo "Waiting for MongoDB pod to start (this may take a few minutes)..."
      kubectl -n mongodb wait --for=condition=ready pod/mongodb-0 --timeout=600s || true
      
      # The initialization job is only necessary if statefulset exists but isn't initialized
      echo "Checking if MongoDB needs initialization..."
      POD_STATUS=$(kubectl -n mongodb get pods -l app=mongodb -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "Not Found")
      
      if [ "$POD_STATUS" == "Running" ]; then
        echo "Creating MongoDB initialization job..."
        kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: mongodb-init
  namespace: mongodb
spec:
  ttlSecondsAfterFinished: 100
  template:
    spec:
      containers:
      - name: mongo-init
        image: mongo:4.4
        command:
        - /bin/bash
        - -c
        - |
          echo "Waiting for MongoDB to be ready..."
          sleep 10
          mongo --host mongodb-0.mongodb-headless.mongodb.svc.cluster.local:27017 -u admin -p password --authenticationDatabase admin --eval "rs.initiate({_id: 'rs0', members: [{_id: 0, host: 'mongodb-0.mongodb-headless.mongodb.svc.cluster.local:27017'}]})" || true
          mongo --host mongodb-0.mongodb-headless.mongodb.svc.cluster.local:27017 -u admin -p password --authenticationDatabase admin --eval "db.getSiblingDB('polybot').createUser({user: 'polybot', pwd: 'polybot', roles: [{role: 'readWrite', db: 'polybot'}]})" || true
          echo "MongoDB initialized successfully"
      restartPolicy: OnFailure
EOF
      fi
      
      echo "MongoDB deployment completed. Monitor status with: kubectl -n mongodb get pods"
    EOT
  }
}

# Instead of creating a service-linked role directly (which may fail due to permissions),
# use a terraform_data resource to check for or create the role using the AWS CLI
resource "terraform_data" "ebs_service_role_setup" {
  # This doesn't depend on other resources to avoid circular dependencies
  # It's meant to run early in the process

  triggers_replace = {
    # Only run once per deployment
    run_id = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    # Use on_failure = continue to ensure this doesn't stop the deployment
    on_failure = continue
    command = <<-EOT
      #!/bin/bash
      echo "Checking for AWS EBS service role..."
      
      # Check if the role already exists
      if aws iam get-role --role-name AWSServiceRoleForEBS 2>/dev/null; then
        echo "✅ EBS service role already exists, no action needed."
        exit 0
      fi
      
      echo "⚠️ EBS service role not found, attempting to create it..."
      
      # Try to create the role, but continue even if it fails
      if aws iam create-service-linked-role --aws-service-name ec2.amazonaws.com 2>/dev/null; then
        echo "✅ Successfully created EBS service role."
      else
        echo "⚠️ Could not create service role for EBS. This might be due to insufficient permissions."
        echo "⚠️ EBS volume provisioning might fail later. Manual role creation may be required."
        echo "⚠️ Run: aws iam create-service-linked-role --aws-service-name ec2.amazonaws.com"
      fi
    EOT
  }
}

# Alternative EBS role check that doesn't require role creation permissions
resource "null_resource" "verify_ebs_role" {
  depends_on = [
    terraform_data.ebs_service_role_setup
  ]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "Checking if EBS service-linked role exists..."
      if aws iam get-role --role-name AWSServiceRoleForEBS 2>/dev/null; then
        echo "EBS service-linked role already exists."
      else
        echo "Warning: EBS service-linked role may not exist. This is often created automatically by AWS."
        echo "If you encounter volume provisioning issues, create it manually with:"
        echo "aws iam create-service-linked-role --aws-service-name ec2.amazonaws.com"
      fi
    EOT
  }
}

# Use the kubernetes-resources module for all Kubernetes-specific resources
module "kubernetes_resources" {
  source = "./modules/kubernetes-resources"
  
  # Required parameters
  region            = var.region
  kubeconfig_path   = local.kubeconfig_path
  module_path       = path.module
  key_name          = var.key_name
  
  # Optional parameters with defaults
  enable_resources    = true
  skip_mongodb        = false
  
  # Resource dependencies
  kubeconfig_trigger_id = terraform_data.kubectl_provider_config[0].id
  kubernetes_dependency = null_resource.wait_for_kubernetes
  ebs_csi_dependency    = null_resource.install_ebs_csi_driver
  control_plane_id      = module.k8s-cluster.control_plane_id
  
  # Ensure this module runs after the necessary resources
  depends_on = [
    terraform_data.kubectl_provider_config,
    null_resource.install_ebs_csi_driver,
    null_resource.wait_for_kubernetes,
    terraform_data.ebs_service_role_setup,
    null_resource.verify_ebs_role
  ]
}

# Add display information at the start of deployment
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
    EOT
  }
}


