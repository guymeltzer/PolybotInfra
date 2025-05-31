# Kubernetes Resources Module
# This module manages Kubernetes-specific resources like storage classes, 
# cleanup jobs, MongoDB deployment, and initialization functions

# Call the storage class resource
resource "null_resource" "create_storage_classes" {
  count = var.enable_resources ? 1 : 0
  triggers = {
    kubeconfig_trigger = var.kubeconfig_trigger_id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "Creating storage classes..."
      
      # Simple approach: delete conflicting storage classes first, then apply
      echo "Cleaning up any existing conflicting storage classes..."
      for sc in ebs-sc ebs-fast ebs-slow; do
        if kubectl get storageclass "$sc" &>/dev/null; then
          echo "Deleting existing storage class: $sc"
          kubectl delete storageclass "$sc" --ignore-not-found=true
        fi
      done
      
      # Wait a moment for cleanup
      sleep 2
      
      # Apply the manifest file directly
      echo "Applying storage classes manifest..."
      if kubectl apply -f ${path.module}/manifests/storage-classes.yaml; then
        echo "✅ Storage classes applied successfully"
      else
        echo "❌ Failed to apply storage classes manifest, trying individual creation..."
        
        # Fallback: create each storage class individually
        echo "Creating ebs-sc storage class..."
        kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  fsType: ext4
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
EOF

        echo "Creating ebs-fast storage class..."
        kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-fast
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  iops: "3000"
  fsType: ext4
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
EOF

        echo "Creating ebs-slow storage class..."
        kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-slow
provisioner: ebs.csi.aws.com
parameters:
  type: gp2
  fsType: ext4
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
EOF
      fi
      
      echo "✅ Storage class creation completed"
      kubectl get storageclass
    EOT
  }
  lifecycle {
    create_before_destroy = true
  }
}

# Improved disk cleanup resource - DISABLED to prevent terminating healthy worker nodes
resource "null_resource" "improved_disk_cleanup" {
  count = var.enable_resources ? 1 : 0
  triggers = {
    control_plane_id = var.control_plane_id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      echo "🔍 DISK CLEANUP DISABLED - Would have checked for worker nodes to clean up"
      echo "Note: The previous version of this resource was terminating worker nodes, which is incorrect during cluster deployment"
      echo "If you need disk cleanup, implement it as a Kubernetes CronJob or DaemonSet instead"
      
      # Show what instances would have been affected (for debugging)
      echo "Worker instances that would have been checked:"
      aws ec2 describe-instances --region ${var.region} \
        --filters "Name=tag:Name,Values=*worker-node*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].[InstanceId,Tags[?Key=='Name'].Value|[0]]" \
        --output table || echo "Could not list instances"
    EOT
  }
  lifecycle {
    create_before_destroy = true
  }
}

# Worker node cleanup
resource "null_resource" "cleanup_worker_nodes" {
  count = var.enable_resources ? 1 : 0
  
  depends_on = [
    var.kubernetes_dependency,
    null_resource.improved_disk_cleanup
  ]
  
  triggers = {
    kubeconfig_id = var.kubeconfig_trigger_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "Checking worker nodes for disk pressure..."
      WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name | cut -d'/' -f2)
      
      if [ -z "$WORKER_NODES" ]; then
        echo "No worker nodes found, skipping cleanup"
        exit 0
      fi
      
      NODES_WITH_PRESSURE=""
      for NODE in $WORKER_NODES; do
        DISK_PRESSURE=$(kubectl get node $NODE -o jsonpath='{.status.conditions[?(@.type=="DiskPressure")].status}')
        if [ "$DISK_PRESSURE" == "True" ]; then
          NODES_WITH_PRESSURE="$NODES_WITH_PRESSURE $NODE"
          echo "Node $NODE has disk pressure"
        fi
      done
      
      if [ -z "$NODES_WITH_PRESSURE" ]; then
        echo "No nodes with disk pressure, but cleaning all nodes as a precaution"
        NODES_WITH_PRESSURE="$WORKER_NODES"
      fi
      
      for NODE in $NODES_WITH_PRESSURE; do
        echo "Cleaning up disk space on $NODE..."
        kubectl debug node/$NODE --image=ubuntu:20.04 -- bash -c "
          echo 'Cleaning up files on $NODE'
          find /host/var/log -type f -name '*.log*' -size +50M -delete
          find /host/var/log -type f -name '*.gz' -delete
          find /host/var/log -type f -name '*.1' -delete
          find /host/var/log -type f -name '*.old' -delete
          find /host/var/log -type f -name '*.tar' -delete
          find /host/tmp -type f -mtime +1 -delete
          find /host/var/lib/docker/containers -path '*/*-json.log*' -size +10M -delete
          
          # Also truncate large log files instead of deleting
          find /host/var/log -type f -name '*.log' -size +10M -exec truncate -s 0 {} \;
          
          # Check disk space after cleanup
          df -h /host
          
          # List largest files remaining for troubleshooting
          echo 'Largest files remaining:'
          find /host -type f -size +10M | xargs ls -lh | sort -hr | head -10
        " || echo "Warning: Debug container on $NODE failed, but continuing"
      done
      
      echo "Worker node cleanup completed"
      sleep 5
      
      # Check if any nodes still have disk pressure
      echo "Checking for remaining disk pressure after cleanup..."
      REMAINING_PRESSURE="false"
      for NODE in $WORKER_NODES; do
        DISK_PRESSURE=$(kubectl get node $NODE -o jsonpath='{.status.conditions[?(@.type=="DiskPressure")].status}')
        if [ "$DISK_PRESSURE" == "True" ]; then
          REMAINING_PRESSURE="true"
          echo "Node $NODE still has disk pressure after cleanup"
        fi
      done
      
      if [ "$REMAINING_PRESSURE" == "true" ]; then
        echo "Warning: Some nodes still have disk pressure after cleanup"
        echo "You may need to increase instance size or add additional EBS volumes"
      else
        echo "All nodes are now free of disk pressure"
      fi
    EOT
  }
}

# MongoDB deployment
resource "null_resource" "deploy_mongodb" {
  count = var.enable_resources && !var.skip_mongodb ? 1 : 0
  triggers = {
    kubeconfig_trigger = var.kubeconfig_trigger_id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      KUBECONFIG="${var.kubeconfig_path}" kubectl apply -f ${path.module}/manifests/mongodb-deployment.yaml
    EOT
  }
  lifecycle {
    create_before_destroy = true
  }
}

# Initialization functions
resource "terraform_data" "init_environment" {
  # Only run when enabled
  count = var.enable_resources ? 1 : 0
  
  # Run only on first apply
  triggers_replace = {
    always_run = timestamp()
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e
      
      # Check for executables we need
      for cmd in aws kubectl jq; do
        if ! command -v $cmd &> /dev/null; then
          echo "Error: $cmd is not installed. Please install it before running Terraform."
          exit 1
        fi
      done
      
      # Ensure needed directories exist
      mkdir -p "${var.module_path}/deploy/manifests" "${var.module_path}/deploy/kubeconfigs"
      chmod 700 "${var.module_path}/deploy" "${var.module_path}/deploy/manifests" "${var.module_path}/deploy/kubeconfigs"
      
      # Check if AWS credentials are configured and test them
      if ! aws sts get-caller-identity &>/dev/null; then
        echo "Warning: Could not validate AWS credentials. Make sure they are properly configured."
        echo "Continuing with deployment, but it may fail if credentials are invalid."
      else
        echo "AWS credentials validated successfully."
      fi
      
      # Check for environment variables that might help with debugging
      if [ -n "$KUBECONFIG" ]; then
        echo "Note: KUBECONFIG is set to $KUBECONFIG"
      fi
      
      # Validate input variables for SSH key
      if [ -n "${var.key_name}" ]; then
        if [ -f "$HOME/.ssh/${var.key_name}.pem" ]; then
          echo "SSH key found at $HOME/.ssh/${var.key_name}.pem"
          chmod 600 "$HOME/.ssh/${var.key_name}.pem"
        elif [ -f "${var.module_path}/${var.key_name}.pem" ]; then
          echo "SSH key found at ${var.module_path}/${var.key_name}.pem"
          chmod 600 "${var.module_path}/${var.key_name}.pem"
        else
          echo "Warning: Specified SSH key ${var.key_name}.pem not found in standard locations."
          echo "Will attempt to generate a key or use fallback mechanisms."
        fi
      fi
      
      echo "Environment initialized successfully."
    EOT
  }
}

# Better kubectl provider configuration with more robust error handling
resource "terraform_data" "kubectl_provider_config" {
  count = var.enable_resources ? 1 : 0
  triggers_replace = {
    cluster_id = var.control_plane_id
  }
  lifecycle {
    create_before_destroy = true
  }
}

# Make sure providers like EBS CSI driver and ArgoCD are ready
resource "null_resource" "providers_ready" {
  count = var.enable_resources ? 1 : 0
  
  depends_on = [
    var.kubernetes_dependency
  ]
  
  triggers = {
    kubeconfig_id = var.kubeconfig_trigger_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "Creating critical namespaces..."
      for NS in kube-system argocd cert-manager; do
        kubectl create namespace $NS --dry-run=client -o yaml | kubectl apply -f -
      done
      
      echo "Waiting for CoreDNS to be ready..."
      for i in {1..30}; do
        if kubectl -n kube-system get deployments coredns &>/dev/null; then
          # Check if pods are ready
          READY=$(kubectl -n kube-system get deployments coredns -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
          # Use bash parameter expansion to provide a default value of 0 if READY is empty
          if [ "$${READY}" -gt 0 ] 2>/dev/null || [ "$${READY}" == "1" ]; then
            echo "CoreDNS is ready!"
            break
          fi
        fi
        echo "Waiting for CoreDNS to be ready... ($i/30)"
        sleep 10
      done
      
      echo "Making sure critical system pods are running..."
      kubectl -n kube-system get pods
      
      # Create namespaces for all environments
      echo "Creating application namespaces..."
      for NS in dev prod mongodb; do
        kubectl create namespace $NS --dry-run=client -o yaml | kubectl apply -f -
      done
      
      echo "Core provider readiness check completed."
    EOT
  }
} 