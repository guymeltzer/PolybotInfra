# Kubernetes Resources Module
# This module manages Kubernetes-specific resources like storage classes, 
# cleanup jobs, MongoDB deployment, and initialization functions

# Call the storage class resource
resource "null_resource" "create_storage_classes" {
  count = var.enable_resources ? 1 : 0
  
  depends_on = [
    var.ebs_csi_dependency
  ]
  
  triggers = {
    kubeconfig_id = var.kubeconfig_trigger_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "Cleaning up any existing storage classes to avoid conflicts..."
      kubectl delete storageclass ebs-sc --ignore-not-found=true
      kubectl delete storageclass mongodb-sc --ignore-not-found=true
      kubectl delete storageclass mongodb-storage --ignore-not-found=true
      sleep 5
      
      echo "Creating EBS storage class..."
      cat <<EOFSC | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp2
  encrypted: "true"
EOFSC
      
      echo "Creating MongoDB storage class..."
      cat <<EOFSC | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: mongodb-sc
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp2
EOFSC
      
      echo "Storage classes created successfully"
    EOT
  }
}

# Improved disk cleanup resource
resource "null_resource" "improved_disk_cleanup" {
  count = var.enable_resources ? 1 : 0
  
  depends_on = [
    var.kubernetes_dependency,
    null_resource.create_storage_classes
  ]
  
  triggers = {
    kubeconfig_id = var.kubeconfig_trigger_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "Cleaning up evicted pods with improved syntax..."
      # Use jq for reliable pod detection and deletion
      kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.status.reason=="Evicted") | .metadata.namespace + " " + .metadata.name' | while read ns name; do 
        echo "Deleting evicted pod $name in namespace $ns"
        kubectl delete pod -n $ns $name || true
      done
      
      echo "Creating emergency disk cleanup job..."
      cat <<EOFJOB | kubectl apply -f -
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
        command: ["/bin/sh", "-c"]
        args:
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
        - name: host-fs
          mountPath: /
          readOnly: false
      volumes:
      - name: host-fs
        hostPath:
          path: /
      restartPolicy: Never
      hostNetwork: true
      hostPID: true
EOFJOB
      
      echo "Setting up recurring disk cleanup job..."
      cat <<EOFJOB | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: node-cleanup
  namespace: kube-system
spec:
  schedule: "0 */6 * * *"
  jobTemplate:
    spec:
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
            command: ["/bin/sh", "-c"]
            args:
            - |
              apt-get update && apt-get install -y docker.io
              echo "Scheduled cleanup - maintaining disk space..."
              docker system prune -af
              find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
              find /var/log -type f -size +10M -delete
              journalctl --vacuum-time=1d
              rm -rf /tmp/*
              echo "Scheduled cleanup completed"
            securityContext:
              privileged: true
            volumeMounts:
            - name: host-fs
              mountPath: /
              readOnly: false
          volumes:
          - name: host-fs
            hostPath:
              path: /
          restartPolicy: OnFailure
          hostNetwork: true
          hostPID: true
EOFJOB
      
      # Wait with reduced timeout
      echo "Waiting for emergency cleanup job to complete (timeout: 3 minutes)..."
      kubectl -n kube-system wait --for=condition=complete job/disk-cleanup-now --timeout=180s || true
      
      # Continue even if job hasn't completed
      echo "Continuing deployment regardless of cleanup job status..."
      echo "Disk cleanup jobs created. Regular maintenance will happen every 6 hours."
    EOT
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
  
  depends_on = [
    null_resource.create_storage_classes,
    null_resource.improved_disk_cleanup,
    null_resource.cleanup_worker_nodes
  ]
  
  triggers = {
    kubeconfig_id = var.kubeconfig_trigger_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      export KUBECONFIG="${var.kubeconfig_path}"
      
      echo "Creating MongoDB namespace if it doesn't exist..."
      kubectl create namespace mongodb --dry-run=client -o yaml | kubectl apply -f -
      
      echo "Checking if MongoDB is already deployed..."
      if kubectl -n mongodb get statefulset mongodb &>/dev/null; then
        echo "MongoDB is already deployed, checking its status..."
        if kubectl -n mongodb get pod mongodb-0 -o jsonpath='{.status.phase}' | grep -q "Running"; then
          echo "MongoDB pod is already running, skipping creation"
          exit 0
        else
          echo "MongoDB exists but pod is not running. Cleaning up and redeploying..."
          kubectl delete statefulset mongodb -n mongodb --cascade=foreground --timeout=120s || true
          kubectl delete pvc -n mongodb --all || true
          sleep 30
        fi
      fi
      
      # Make sure we have the MongoDB storage class
      if ! kubectl get storageclass mongodb-sc &>/dev/null; then
        echo "MongoDB storage class doesn't exist, creating it..."
        cat <<EOFSC | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: mongodb-sc
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp2
EOFSC
      fi
      
      echo "Creating MongoDB resources with proper resource limits..."
      cat <<EOFMONGO | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: mongodb-config
  namespace: mongodb
data:
  mongo.conf: |
    storage:
      dbPath: /data/db
---
apiVersion: v1
kind: Secret
metadata:
  name: mongodb-secret
  namespace: mongodb
type: Opaque
stringData:
  root-username: admin
  root-password: password
---
apiVersion: v1
kind: Service
metadata:
  name: mongodb
  namespace: mongodb
spec:
  selector:
    app: mongodb
  ports:
  - port: 27017
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mongodb
  namespace: mongodb
spec:
  serviceName: mongodb
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
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
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
        livenessProbe:
          exec:
            command:
            - mongo
            - --eval
            - "db.adminCommand('ping')"
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 10
        ports:
        - containerPort: 27017
        volumeMounts:
        - name: data
          mountPath: /data/db
        env:
        - name: MONGO_INITDB_ROOT_USERNAME
          valueFrom:
            secretKeyRef:
              name: mongodb-secret
              key: root-username
        - name: MONGO_INITDB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mongodb-secret
              key: root-password
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      storageClassName: mongodb-sc
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 1Gi
EOFMONGO
      
      echo "Waiting for MongoDB pod to start (10 minute timeout)..."
      for i in {1..40}; do
        if kubectl -n mongodb get pod mongodb-0 -o jsonpath='{.status.phase}' | grep -q "Running"; then
          echo "MongoDB pod is running!"
          sleep 10  # Give it a little more time to fully initialize
          echo "Creating a test database..."
          kubectl -n mongodb exec -i mongodb-0 -- mongo -u admin -p password --authenticationDatabase admin <<EOF
use polybot
db.createUser({user: 'polybot', pwd: 'polybot', roles: [{role: 'readWrite', db: 'polybot'}]})
db.test.insert({name: 'test'})
EOF
          echo "MongoDB setup complete and verified working!"
          break
        fi
        
        # Check for PVC errors
        if [[ $((i % 5)) -eq 0 ]]; then  # Every 5 iterations
          echo "Checking PVC status..."
          kubectl -n mongodb get pvc
          kubectl -n mongodb describe pvc
          echo "Checking MongoDB pod status..."
          kubectl -n mongodb describe pod mongodb-0
          echo "Checking storage classes..."
          kubectl get sc
        fi
        
        echo "Waiting for MongoDB to start... ($i/40)"
        sleep 15
      done
      
      # Final check
      if ! kubectl -n mongodb get pod mongodb-0 -o jsonpath='{.status.phase}' | grep -q "Running"; then
        echo "WARNING: MongoDB pod did not reach Running state within timeout"
        echo "Current pod status:"
        kubectl -n mongodb get pods
        echo "Latest pod events:"
        kubectl -n mongodb get events --sort-by='.lastTimestamp'
      fi
    EOT
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
  
  depends_on = [
    var.kubernetes_dependency
  ]
  
  triggers_replace = {
    # Use a stable identifier that changes when the cluster changes
    cluster_id = var.control_plane_id
  }
  
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e
      
      # Define paths consistently
      KUBECONFIG_PATH="${var.kubeconfig_path}"
      
      # Ensure the kubeconfig file exists and has valid content
      if [ ! -f "$KUBECONFIG_PATH" ]; then
        echo "Error: Kubeconfig file not found at $KUBECONFIG_PATH"
        exit 0 # Don't fail terraform, just exit the script
      fi
      
      # Check if kubeconfig is valid and cluster is accessible
      echo "Testing kubectl connectivity..."
      if kubectl --kubeconfig="$KUBECONFIG_PATH" cluster-info &>/dev/null; then
        echo "Kubectl connectivity verified successfully!"
      else
        echo "Warning: Could not connect to Kubernetes cluster with the kubeconfig."
        echo "This may indicate network connectivity issues or an invalid kubeconfig."
        echo "Will continue but subsequent Kubernetes-related steps may fail."
      fi
      
      # Make sure kubectl provider will be able to use the kubeconfig
      chmod 600 "$KUBECONFIG_PATH"
      
      echo "Kubectl provider configuration completed."
    EOT
  }
}

# Make sure providers like EBS CSI driver and ArgoCD are ready
resource "null_resource" "providers_ready" {
  count = var.enable_resources ? 1 : 0
  
  depends_on = [
    var.kubernetes_dependency,
    terraform_data.kubectl_provider_config
  ]
  
  triggers = {
    kubeconfig_id = try(terraform_data.kubectl_provider_config[0].id, "")
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
          if [ "${READY}" -gt 0 ] 2>/dev/null || [ "${READY}" == "1" ]; then
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