// tf/main.tf

provider "aws" {
  region = var.region
}

provider "local" {}

// Create an initial, minimal, valid placeholder kubeconfig.
// This helps prevent errors if providers try to read it before it's fully populated.
resource "local_file" "initial_kubeconfig" {
  content  = <<-EOT
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://placeholder.invalid:6443 # Must be a valid URI
    insecure-skip-tls-verify: true # Or a dummy CA
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
users:
- name: kubernetes-admin
  user: # Add dummy auth if needed for schema validation by provider
    # client-certificate-data: cGxhY2Vob2xkZXI= # base64encoded "placeholder"
    # client-key-data: cGxhY2Vob2xkZXI=         # base64encoded "placeholder"
EOT
  filename = "${path.module}/kubeconfig.yml"
  file_permission = "0600"
}

// Kubernetes, Helm, and kubectl providers will use this path.
// They will re-evaluate the config once its content changes.
provider "kubernetes" {
  config_path = local_file.initial_kubeconfig.filename
  // insecure = true // Keep if you are not embedding CA, or ensure CA is correctly fetched
}

provider "helm" {
  kubernetes {
    config_path = local_file.initial_kubeconfig.filename
    // insecure = true
  }
}

provider "kubectl" {
  config_path      = local_file.initial_kubeconfig.filename
  load_config_file = true // This ensures it reloads the config
  // insecure      = true
}

module "k8s-cluster" {
  source                      = "./modules/k8s-cluster"
  region                      = var.region
  cluster_name                = "polybot-cluster" // Example, pass as variable if needed
  vpc_id                      = var.vpc_id        // Assuming these come from your root vars or another module
  subnet_ids                  = var.subnet_ids
  control_plane_instance_type = "t3.medium"
  worker_instance_type        = "t3.medium"
  worker_count                = 1 // Start with 1 for testing
  route53_zone_id             = var.route53_zone_id
  key_name                    = var.key_name
  control_plane_ami           = var.control_plane_ami
  worker_ami                  = var.worker_ami
  s3_bucket_name              = "polybot-tfstate-bucket" // Or pass as variable

  // Pass the kubeadm token to the module if needed by its user_data template
  kubeadm_token = module.k8s-cluster.generated_kubeadm_token // Assuming module k8s-cluster now outputs this

  depends_on = [local_file.initial_kubeconfig]
}

// This resource now focuses on API readiness and fetching the REAL kubeconfig
resource "null_resource" "wait_for_kubernetes_api_and_fetch_kubeconfig" {
  depends_on = [module.k8s-cluster.control_plane_instance] // Depends on the instance being "up"

  triggers = {
    control_plane_ip = module.k8s-cluster.control_plane_public_ip // Re-run if IP changes
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -e
      echo "Waiting for Kubernetes API server..."
      CP_IP="${module.k8s-cluster.control_plane_public_ip}"
      S3_BUCKET_NAME="polybot-tfstate-bucket" # Should be a variable
      CLUSTER_NAME="polybot-cluster" # Should be a variable, matching k8s-cluster module
      KUBECONFIG_S3_KEY="kubeconfig/$${CLUSTER_NAME}/admin.config"
      LOCAL_KUBECONFIG_PATH="${local_file.initial_kubeconfig.filename}"

      # Wait for API server to be available (max 15 minutes)
      timeout 900 bash -c ' \
        while ! curl -k --silent --fail --connect-timeout 5 https://'$${CP_IP}':6443/healthz; do \
          echo "API server not yet ready, waiting..."; \
          sleep 20; \
        done; \
        echo "Kubernetes API is available!"' || {
          echo "ERROR: Timed out waiting for Kubernetes API at $${CP_IP}:6443"

          echo "Attempting to get logs from control plane via SSM..."
          INSTANCE_ID=$(aws ec2 describe-instances --region "${var.region}" --filters "Name=tag:Name,Values=k8s-control-plane" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text || echo "INSTANCE_ID_NOT_FOUND")
          if [ "$INSTANCE_ID" != "INSTANCE_ID_NOT_FOUND" ]; then
            aws ssm send-command \
              --instance-ids "$INSTANCE_ID" \
              --document-name "AWS-RunShellScript" \
              --comment "Get k8s-control-plane-init.log" \
              --parameters commands="cat /var/log/k8s-control-plane-init.log | tail -n 200" \
              --cloud-watch-output-config CloudWatchOutputEnabled=true \
              --output text --query "Command.CommandId" || echo "Failed to send SSM command for init log"

            aws ssm send-command \
              --instance-ids "$INSTANCE_ID" \
              --document-name "AWS-RunShellScript" \
              --comment "Get kubelet logs" \
              --parameters commands="journalctl -u kubelet -n 50 --no-pager" \
              --cloud-watch-output-config CloudWatchOutputEnabled=true \
              --output text --query "Command.CommandId" || echo "Failed to send SSM command for kubelet log"
            echo "Check SSM Command history in AWS Console for instance $INSTANCE_ID and region ${var.region} for detailed logs."
          else
            echo "Could not get instance ID for SSM."
          fi
          exit 1
        }

      echo "Fetching kubeconfig from S3: s3://$${S3_BUCKET_NAME}/$${KUBECONFIG_S3_KEY}"
      aws s3 cp "s3://$${S3_BUCKET_NAME}/$${KUBECONFIG_S3_KEY}" "$${LOCAL_KUBECONFIG_PATH}" --region "${var.region}" || {
        echo "ERROR: Failed to download kubeconfig from S3."
        exit 1
      }
      echo "Kubeconfig downloaded to $${LOCAL_KUBECONFIG_PATH}"
      chmod 600 "$${LOCAL_KUBECONFIG_PATH}"
      
      # Verify kubectl can use it (optional, but good)
      if command -v kubectl &> /dev/null; then
        echo "Testing kubectl with downloaded kubeconfig..."
        KUBECONFIG="$${LOCAL_KUBECONFIG_PATH}" kubectl get nodes || echo "WARNING: kubectl get nodes failed with the new config."
      fi
      EOT
  }
}

// Ensure Kubernetes resources depend on the kubeconfig being ready
resource "kubernetes_namespace" "dev" {
  metadata {
    name = "dev"
  }
  depends_on = [null_resource.wait_for_kubernetes_api_and_fetch_kubeconfig]
}

resource "kubernetes_namespace" "prod" {
  metadata {
    name = "prod"
  }
  depends_on = [null_resource.wait_for_kubernetes_api_and_fetch_kubeconfig]
}

// EBS CSI Driver
resource "helm_release" "aws_ebs_csi_driver" {
  // count = fileexists(local_file.initial_kubeconfig.filename) ? 1 : 0 # No longer needed if provider handles it
  name       = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  namespace  = "kube-system"
  version    = "2.23.0"

  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.k8s-cluster.control_plane_iam_role_arn // Or a dedicated IAM role for the CSI driver SA
  }
  values = [<<EOF
storageClasses:
  - name: ebs-sc
    annotations:
      storageclass.kubernetes.io/is-default-class: "true"
    provisioner: ebs.csi.aws.com # Ensure this matches the driver
    volumeBindingMode: WaitForFirstConsumer
    parameters:
      csi.storage.k8s.io/fstype: xfs
      type: gp2 # Or gp3
      encrypted: "true"
EOF
  ]
  depends_on = [null_resource.wait_for_kubernetes_api_and_fetch_kubeconfig, kubernetes_namespace.prod] // Ensure namespaces exist if driver needs them
  timeout    = 600
}

// ArgoCD Module (and other K8s resources)
module "argocd" {
  // count = fileexists(local_file.initial_kubeconfig.filename) ? 1 : 0
  source         = "./modules/argocd"
  git_repo_url   = var.git_repo_url

  providers = {
    kubernetes = kubernetes
    helm       = helm
    kubectl    = kubectl
  }
  depends_on     = [helm_release.aws_ebs_csi_driver] // ArgoCD might need storage or just depends on cluster being ready
}

// Polybot Modules
module "polybot_dev" {
  // ... your existing config ...
  depends_on = [module.argocd] // If polybot app is deployed by ArgoCD
}

module "polybot_prod" {
  // ... your existing config ...
  depends_on = [module.argocd]
}