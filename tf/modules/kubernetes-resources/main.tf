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

# Proper disk cleanup using Kubernetes DaemonSet (replaces the destructive instance termination approach)
resource "null_resource" "install_disk_cleanup_daemonset" {
  count = var.enable_resources ? 1 : 0
  
  depends_on = [
    var.kubernetes_dependency,
    var.ebs_csi_dependency
  ]
  
  triggers = {
    kubeconfig_id = var.kubeconfig_trigger_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "🧹 Installing proper disk cleanup DaemonSet..."
      
      # Create a DaemonSet that runs disk cleanup on all worker nodes
      kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: disk-cleanup
  namespace: kube-system
  labels:
    app: disk-cleanup
spec:
  selector:
    matchLabels:
      app: disk-cleanup
  template:
    metadata:
      labels:
        app: disk-cleanup
    spec:
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
      hostPID: true
      hostNetwork: true
      containers:
      - name: disk-cleanup
        image: alpine:3.18
        command: ["/bin/sh"]
        args:
        - -c
        - |
          set -e
          echo "Starting disk cleanup on node: $NODE_NAME"
          
          # Function to clean disk space
          cleanup_disk() {
            echo "=== Disk Cleanup Started at $(date) ==="
            
            # Show disk usage before cleanup
            echo "Disk usage before cleanup:"
            df -h /host
            
            # Clean container logs (Docker/containerd)
            echo "Cleaning container logs..."
            find /host/var/lib/docker/containers -name "*.log" -type f -size +10M -exec truncate -s 10M {} \; 2>/dev/null || true
            find /host/var/lib/containerd -name "*.log" -type f -size +10M -exec truncate -s 10M {} \; 2>/dev/null || true
            
            # Clean system logs
            echo "Cleaning system logs..."
            find /host/var/log -name "*.log.*" -type f -mtime +3 -delete 2>/dev/null || true
            find /host/var/log -name "*.gz" -type f -mtime +3 -delete 2>/dev/null || true
            find /host/var/log -name "*.old" -type f -mtime +1 -delete 2>/dev/null || true
            
            # Truncate large current log files
            find /host/var/log -name "*.log" -type f -size +100M -exec truncate -s 50M {} \; 2>/dev/null || true
            
            # Clean temporary files
            echo "Cleaning temporary files..."
            find /host/tmp -type f -mtime +1 -delete 2>/dev/null || true
            find /host/var/tmp -type f -mtime +1 -delete 2>/dev/null || true
            
            # Clean package caches
            echo "Cleaning package caches..."
            rm -rf /host/var/cache/apt/archives/*.deb 2>/dev/null || true
            rm -rf /host/var/cache/yum/* 2>/dev/null || true
            
            # Clean old journal logs (systemd)
            echo "Cleaning old journal logs..."
            chroot /host journalctl --vacuum-time=3d 2>/dev/null || true
            chroot /host journalctl --vacuum-size=100M 2>/dev/null || true
            
            # Show disk usage after cleanup
            echo "Disk usage after cleanup:"
            df -h /host
            
            echo "=== Disk Cleanup Completed at $(date) ==="
          }
          
          # Run cleanup immediately
          cleanup_disk
          
          # Then run cleanup every 6 hours
          while true; do
            sleep 21600  # 6 hours
            cleanup_disk
          done
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
        - name: host-var-log
          mountPath: /host/var/log
        - name: host-var-lib-docker
          mountPath: /host/var/lib/docker
          readOnly: false
        - name: host-var-lib-containerd
          mountPath: /host/var/lib/containerd
          readOnly: false
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: host-var-log
        hostPath:
          path: /var/log
      - name: host-var-lib-docker
        hostPath:
          path: /var/lib/docker
      - name: host-var-lib-containerd
        hostPath:
          path: /var/lib/containerd
      nodeSelector:
        kubernetes.io/os: linux
EOF

      echo "⏳ Waiting for disk cleanup DaemonSet to be ready..."
      kubectl -n kube-system rollout status daemonset/disk-cleanup --timeout=180s || {
        echo "⚠️  Disk cleanup DaemonSet not ready within timeout, but continuing..."
        kubectl -n kube-system get daemonset disk-cleanup -o wide
        kubectl -n kube-system get pods -l app=disk-cleanup -o wide
      }
      
      echo "✅ Disk cleanup DaemonSet installed successfully"
      echo "ℹ️  Disk cleanup will run every 6 hours on all nodes"
    EOT
  }
  
  lifecycle {
    create_before_destroy = true
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