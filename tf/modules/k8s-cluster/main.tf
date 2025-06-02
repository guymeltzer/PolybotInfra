# =============================================================================
# K8S-CLUSTER MODULE - REFACTORED AND OPTIMIZED
# =============================================================================
# Kubernetes Version: 1.32.3 (hardcoded for consistency)
# Comprehensive cluster infrastructure with logical organization

# =============================================================================
# 🌐 NETWORKING - VPC AND SUBNETS
# =============================================================================

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "guy-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.region}a", "${var.region}b"]
  public_subnets  = ["10.0.0.0/24", "10.0.2.0/24"]
  private_subnets = ["10.0.1.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name                                      = "guy-vpc"
    "kubernetes-io-cluster-kubernetes"        = "owned"
  })

  public_subnet_tags = {
    "kubernetes-io-role-elb"          = "1"
    "kubernetes-io-role-internal-elb" = "1"
  }
}

# =============================================================================
# 📋 LOCALS - CENTRALIZED CONFIGURATION  
# =============================================================================

locals {
  # Kubernetes version configuration (hardcoded to 1.32.3)
  k8s_version_full = "1.32.3"
  k8s_major_minor = "1.32"
  k8s_package_version = "1.32.3-1.1"
  
  # CRI-O version aligns with Kubernetes major.minor
  crio_k8s_major_minor = "1.32"
  
  # Cluster configuration
  cluster_name = var.cluster_name
  pod_cidr = var.pod_cidr
  
  # ASG names (defined here to avoid circular dependencies)
  worker_asg_name = "guy-polybot-asg"
  
  # SSH key management
  actual_key_name = var.key_name != "" ? var.key_name : (
    length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : "polybot-key"
  )
  
  # Template variables for user data scripts
  template_vars = {
    # Kubernetes version variables (uppercase to match scripts)
    K8S_VERSION_FULL = local.k8s_version_full
    K8S_MAJOR_MINOR = local.k8s_major_minor
    K8S_PACKAGE_VERSION = local.k8s_package_version
    CRIO_K8S_MAJOR_MINOR = local.crio_k8s_major_minor
    
    # Worker-specific variable names
    K8S_PACKAGE_VERSION_TO_INSTALL = local.k8s_package_version
    K8S_MAJOR_MINOR_FOR_REPO = local.k8s_major_minor
    CRIO_K8S_MAJOR_MINOR_FOR_REPO = local.crio_k8s_major_minor
    
    # Token variables
    TOKEN_SUFFIX = random_string.token_part1.result
    
    # SSH public key
    ssh_public_key = var.ssh_public_key != "" ? var.ssh_public_key : (
      length(tls_private_key.ssh) > 0 ? tls_private_key.ssh[0].public_key_openssh : ""
    )
    SSH_PUBLIC_KEY = var.ssh_public_key != "" ? var.ssh_public_key : (
      length(tls_private_key.ssh) > 0 ? tls_private_key.ssh[0].public_key_openssh : ""
    )
    
    # Kubelet configuration
    KUBELET_DROPIN_DIR = "/etc/systemd/system/kubelet.service.d"
    
    # Placeholder variables that get set dynamically in scripts
    PRIVATE_IP_FROM_META = "PLACEHOLDER_WILL_BE_SET_BY_SCRIPT"
    NODE_NAME = "PLACEHOLDER_WILL_BE_SET_BY_SCRIPT"
  }
}

# =============================================================================
# 🎲 RANDOM RESOURCES - TOKENS AND IDENTIFIERS
# =============================================================================

# Generate kubeadm token components
resource "random_string" "token_part1" {
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "token_part2" {
  length  = 16
  special = false
  upper   = false
}

# Random suffix for unique resource naming
resource "random_id" "suffix" {
  byte_length = 4
}

# Formatted kubeadm token
locals {
  kubeadm_token = "${random_string.token_part1.result}.${random_string.token_part2.result}"
}

# =============================================================================
# 🔐 SECRETS MANAGEMENT - JOIN COMMANDS
# =============================================================================

# Primary join command secret
resource "aws_secretsmanager_secret" "kubernetes_join_command" {
  name                    = "kubernetes-join-command-${random_id.suffix.hex}"
  description             = "Kubernetes join command for worker nodes"
  recovery_window_in_days = 0
  force_overwrite_replica_secret = true

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

# Latest join command secret (for updates)
resource "aws_secretsmanager_secret" "kubernetes_join_command_latest" {
  name                    = "kubernetes-join-command-latest-${random_id.suffix.hex}"
  description             = "Latest Kubernetes join command for worker nodes"
  recovery_window_in_days = 0
  force_overwrite_replica_secret = true

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

# =============================================================================
# 🛡️ SECURITY GROUPS - NETWORK ACCESS CONTROL
# =============================================================================

# Control plane security group
resource "aws_security_group" "control_plane_sg" {
  name        = "Guy-Control-Plane-SG"
  description = "Security group for Kubernetes control plane"
  vpc_id      = module.vpc.vpc_id

  # Kubernetes API server
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kubernetes API server"
  }

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Internal VPC traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Internal VPC traffic"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "Guy-Control-Plane-SG"
    "kubernetes-io-cluster-kubernetes" = "owned"
  })
}

# Worker node security group
resource "aws_security_group" "worker_sg" {
  name        = "Guy-Worker-SG"
  description = "Security group for Kubernetes worker nodes"
  vpc_id      = module.vpc.vpc_id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Internal VPC traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Internal VPC traffic"
  }

  # NodePort services
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort services"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "Guy-Worker-SG"
    "kubernetes-io-cluster-kubernetes" = "owned"
  })
}

# ALB security group
resource "aws_security_group" "alb_sg" {
  name        = "Guy-ALB-SG"
  description = "Security group for Application Load Balancer"
  vpc_id      = module.vpc.vpc_id

  # HTTP traffic
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP traffic"
  }

  # HTTPS traffic
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS traffic"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "Guy-ALB-SG"
  })
}

# =============================================================================
# 🔑 IAM ROLES AND POLICIES - ACCESS MANAGEMENT
# =============================================================================

# Control plane IAM role
resource "aws_iam_role" "control_plane_role" {
  name = "guy-cluster-control-plane-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# Control plane comprehensive policy
resource "aws_iam_role_policy" "control_plane_comprehensive_policy" {
  name = "control-plane-comprehensive-policy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # EC2 permissions
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeRouteTables",
          "ec2:CreateTags",
          "ec2:DescribeTags",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:ModifyInstanceAttribute",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot"
        ]
        Resource = "*"
      },
      # Auto Scaling permissions
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup"
        ]
        Resource = "*"
      },
      # Secrets Manager permissions
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.kubernetes_join_command.arn,
          aws_secretsmanager_secret.kubernetes_join_command_latest.arn,
          "${aws_secretsmanager_secret.kubernetes_join_command.arn}*",
          "${aws_secretsmanager_secret.kubernetes_join_command_latest.arn}*"
        ]
      },
      # Load Balancer permissions
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ]
        Resource = "*"
      },
      # S3 permissions for logs
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.worker_logs.arn,
          "${aws_s3_bucket.worker_logs.arn}/*",
          aws_s3_bucket.user_data_scripts.arn,
          "${aws_s3_bucket.user_data_scripts.arn}/*"
        ]
      },
      # Lambda permissions
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = aws_lambda_function.node_management_lambda.arn
      }
    ]
  })
}

# AWS managed policies for control plane
resource "aws_iam_role_policy_attachment" "control_plane_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  ])
  
  role       = aws_iam_role.control_plane_role.name
  policy_arn = each.value
}

# Control plane instance profile
resource "aws_iam_instance_profile" "control_plane_profile" {
  name = "guy-cluster-control-plane-profile"
  role = aws_iam_role.control_plane_role.name

  tags = var.tags
}

# Worker node IAM role
resource "aws_iam_role" "worker_role" {
  name = "guy-cluster-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# AWS managed policies for worker nodes
resource "aws_iam_role_policy_attachment" "worker_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ])
  
  role       = aws_iam_role.worker_role.name
  policy_arn = each.value
}

# Worker instance profile
resource "aws_iam_instance_profile" "worker_profile" {
  name = "guy-cluster-worker-profile"
  role = aws_iam_role.worker_role.name

  tags = var.tags
}

# =============================================================================
# 🔑 SSH KEY MANAGEMENT
# =============================================================================

# Generate SSH key if not provided
resource "tls_private_key" "ssh" {
  count     = var.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "polybot-key"
  public_key = tls_private_key.ssh[0].public_key_openssh

  tags = var.tags
}

resource "local_file" "ssh_private_key" {
  count           = var.key_name == "" ? 1 : 0
  content         = tls_private_key.ssh[0].private_key_pem
  filename        = "${path.module}/../../polybot-key.pem"
  file_permission = "0600"
}

# =============================================================================
# 🔐 SSL CERTIFICATE - ACM WITH DNS VALIDATION
# =============================================================================

# ACM certificate for the domain
resource "aws_acm_certificate" "polybot_cert" {
  domain_name       = var.domain_name  # e.g., "guy-polybot-lg.devops-int-college.com"
  validation_method = "DNS"
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = merge(var.tags, {
    Name = "polybot-ssl-certificate"
  })
}

# DNS validation record
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.polybot_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

# Certificate validation
resource "aws_acm_certificate_validation" "polybot_cert_validation" {
  certificate_arn         = aws_acm_certificate.polybot_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
  
  timeouts {
    create = "5m"
  }
}

# =============================================================================
# ⚖️ LOAD BALANCER - APPLICATION LOAD BALANCER
# =============================================================================

# Application Load Balancer
resource "aws_lb" "polybot_alb" {
  name               = "guy-polybot-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = false

  tags = merge(var.tags, {
    Name = "guy-polybot-alb"
  })
}

# Main target group (backend for both HTTP and HTTPS listeners)
resource "aws_lb_target_group" "main_tg" {
  name     = "guy-polybot-main-tg"
  port     = 30080  # NodePort for Kubernetes services
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200,404"  # 404 is acceptable for health check
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }

  tags = var.tags
}

# HTTP listener (with optional redirect to HTTPS)
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = var.redirect_http_to_https ? "redirect" : "forward"
    
    dynamic "redirect" {
      for_each = var.redirect_http_to_https ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    
    target_group_arn = var.redirect_http_to_https ? null : aws_lb_target_group.main_tg.arn
  }
}

# HTTPS listener (using validated ACM certificate)
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate_validation.polybot_cert_validation.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main_tg.arn  # SSL termination: HTTPS->HTTP
  }

  depends_on = [aws_acm_certificate_validation.polybot_cert_validation]
}

# =============================================================================
# 📦 S3 BUCKET - USER DATA SCRIPTS STORAGE
# =============================================================================

# S3 bucket for storing large user data scripts
resource "aws_s3_bucket" "user_data_scripts" {
  bucket        = "guy-k8s-userdata-${random_id.suffix.hex}"
  force_destroy = true

  tags = var.tags
}

resource "aws_s3_bucket_ownership_controls" "user_data_scripts_ownership" {
  bucket = aws_s3_bucket.user_data_scripts.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "user_data_scripts_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.user_data_scripts_ownership]
  
  bucket = aws_s3_bucket.user_data_scripts.id
  acl    = "private"
}

# Upload control plane script to S3 - Updated with comprehensive v9 script
resource "aws_s3_object" "control_plane_script" {
  bucket = aws_s3_bucket.user_data_scripts.bucket
  key    = "control_plane_bootstrap_v9.sh"
  content = <<-EOF
#!/bin/bash
set -euo pipefail

# =================================================================
# KUBERNETES CONTROL PLANE BOOTSTRAP - COMPREHENSIVE v9
# =================================================================

# Set up comprehensive logging
BOOTSTRAP_LOG="/var/log/k8s-bootstrap.log"
CLOUD_INIT_LOG="/var/log/cloud-init-output.log"

# Create log files and ensure they're writable
touch "$BOOTSTRAP_LOG" "$CLOUD_INIT_LOG"
chmod 644 "$BOOTSTRAP_LOG" "$CLOUD_INIT_LOG"

# Redirect all output to both log files
exec > >(tee -a "$BOOTSTRAP_LOG" "$CLOUD_INIT_LOG") 2>&1

echo "================================================================="
echo "= KUBERNETES CONTROL PLANE BOOTSTRAP - STARTED               ="
echo "= Time: $$(date)"
echo "= Instance: $$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')"
echo "= Private IP: $$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null || echo 'unknown')"
echo "= Public IP: $$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'unknown')"
echo "================================================================="

# Error handling function
error_exit() {
    echo "❌ FATAL ERROR: $1"
    echo "❌ Time: $$(date)"
    echo "❌ Exit code: $?"
    echo "❌ Working directory: $$(pwd)"
    echo "❌ Disk space:"
    df -h
    echo "❌ Memory:"
    free -h
    echo "❌ Last 20 lines of this log:"
    tail -20 "$BOOTSTRAP_LOG" 2>/dev/null || echo "Cannot read bootstrap log"
    exit 1
}

# Step 0: Set hostname
echo "🏷️ Step 0: Setting hostname..."
NEW_HOSTNAME="guy-control-plane-${random_string.token_part1.result}"
hostnamectl set-hostname "$$NEW_HOSTNAME"
echo "127.0.0.1 $$NEW_HOSTNAME" >> /etc/hosts
echo "✅ Hostname set to: $$NEW_HOSTNAME"

# Step 1: System updates and essential packages
echo "📦 Step 1: Installing essential packages..."
export DEBIAN_FRONTEND=noninteractive

# Update package lists
echo "📥 Updating package lists..."
apt-get update -y || error_exit "Failed to update package lists"

# Install essential packages
echo "📦 Installing essential packages..."
apt-get install -y \
    curl \
    wget \
    unzip \
    jq \
    awscli \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    apt-transport-https \
    socat \
    conntrack \
    ipset || error_exit "Failed to install essential packages"

echo "✅ Essential packages installed"

# Verify AWS CLI works
echo "🔍 Testing AWS CLI..."
aws --version || error_exit "AWS CLI not working"
echo "✅ AWS CLI verified"

# Step 2: System configuration for Kubernetes
echo "⚙️ Step 2: Configuring system for Kubernetes..."

# Disable swap permanently
echo "💾 Disabling swap..."
swapoff -a
sed -i.bak '/swap/s/^/#/' /etc/fstab
echo "✅ Swap disabled"

# Load required kernel modules
echo "🔧 Loading kernel modules..."
cat > /etc/modules-load.d/k8s.conf << 'MODULES_EOF'
overlay
br_netfilter
MODULES_EOF

modprobe overlay || error_exit "Failed to load overlay module"
modprobe br_netfilter || error_exit "Failed to load br_netfilter module"
echo "✅ Kernel modules loaded"

# Configure sysctl parameters
echo "🔧 Configuring sysctl parameters..."
cat > /etc/sysctl.d/k8s.conf << 'SYSCTL_EOF'
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
SYSCTL_EOF

sysctl --system || error_exit "Failed to apply sysctl settings"
echo "✅ System configuration completed"

# Step 3: Install containerd (container runtime)
echo "🐳 Step 3: Installing containerd container runtime..."

# Install containerd
echo "📦 Installing containerd..."
apt-get update -y
apt-get install -y containerd || error_exit "Failed to install containerd"

# Configure containerd
echo "🔧 Configuring containerd..."
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml

# Enable systemd cgroup driver
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

# Start and enable containerd
systemctl daemon-reload
systemctl enable containerd
systemctl start containerd

# Verify containerd is running
if ! systemctl is-active --quiet containerd; then
    error_exit "containerd is not running"
fi

echo "✅ containerd installed and configured"

# Step 4: Install Kubernetes components
echo "☸️ Step 4: Installing Kubernetes components..."

# Add Kubernetes apt repository
echo "📥 Adding Kubernetes repository..."
mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v${local.k8s_major_minor}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg || error_exit "Failed to add Kubernetes GPG key"

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${local.k8s_major_minor}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

# Update package lists with new repository
echo "📥 Updating package lists with Kubernetes repository..."
apt-get update -y || error_exit "Failed to update package lists with Kubernetes repo"

# Install Kubernetes components
echo "📦 Installing kubectl, kubeadm, kubelet..."
apt-get install -y \
    kubelet=${local.k8s_package_version} \
    kubeadm=${local.k8s_package_version} \
    kubectl=${local.k8s_package_version} || error_exit "Failed to install Kubernetes components"

# Hold packages to prevent automatic updates
apt-mark hold kubelet kubeadm kubectl || error_exit "Failed to hold Kubernetes packages"

# Verify installations
echo "🔍 Verifying Kubernetes component installations..."
kubectl version --client || error_exit "kubectl not installed correctly"
kubeadm version || error_exit "kubeadm not installed correctly"
kubelet --version || error_exit "kubelet not installed correctly"

echo "✅ Kubernetes components installed successfully"

# Step 5: Configure kubelet
echo "🔧 Step 5: Configuring kubelet..."

# Get instance metadata
PRIVATE_IP=$$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

# Configure kubelet with cloud provider
mkdir -p /etc/systemd/system/kubelet.service.d
cat > /etc/systemd/system/kubelet.service.d/20-cloud-provider.conf << 'KUBELET_EOF'
[Service]
Environment="KUBELET_EXTRA_ARGS=--cloud-provider=external --node-ip=$$PRIVATE_IP"
KUBELET_EOF

systemctl daemon-reload
echo "✅ Kubelet configured"

# Step 6: Initialize Kubernetes cluster with kubeadm
echo "🚀 Step 6: Initializing Kubernetes cluster with kubeadm..."

# Create kubeadm configuration
echo "📝 Creating kubeadm configuration..."
mkdir -p /etc/kubernetes/kubeadm

cat > /etc/kubernetes/kubeadm/kubeadm-config.yaml << 'KUBEADM_EOF'
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "${local.kubeadm_token}"
  description: "Initial token for worker nodes"
  ttl: "24h"
localAPIEndpoint:
  advertiseAddress: $$PRIVATE_IP
  bindPort: 6443
nodeRegistration:
  name: $$NEW_HOSTNAME
  criSocket: "unix:///run/containerd/containerd.sock"
  kubeletExtraArgs:
    cloud-provider: "external"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: "v${local.k8s_version_full}"
controlPlaneEndpoint: "$$PRIVATE_IP:6443"
apiServer:
  certSANs:
  - "$$PRIVATE_IP"
  - "$$NEW_HOSTNAME"
  - "127.0.0.1"
  - "localhost"
  - "kubernetes"
  - "kubernetes.default"
  - "kubernetes.default.svc"
  - "kubernetes.default.svc.cluster.local"
controllerManager:
  extraArgs:
    cloud-provider: "external"
networking:
  podSubnet: "${local.pod_cidr}"
  serviceSubnet: "10.96.0.0/12"
KUBEADM_EOF

echo "✅ Kubeadm configuration created"
echo "📋 Configuration preview:"
cat /etc/kubernetes/kubeadm/kubeadm-config.yaml

# Run kubeadm init
echo "🎯 Running kubeadm init (this may take several minutes)..."
echo "📋 Command: kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5"
echo "📋 Start time: $$(date)"

# Create dedicated log for kubeadm init
KUBEADM_LOG="/var/log/kubeadm-init.log"

if kubeadm init --config=/etc/kubernetes/kubeadm/kubeadm-config.yaml --upload-certs --v=5 > "$$KUBEADM_LOG" 2>&1; then
    echo "✅ kubeadm init completed successfully!"
    echo "📋 End time: $$(date)"
    echo "📋 Last 10 lines of kubeadm output:"
    tail -10 "$$KUBEADM_LOG"
else
    echo "❌ kubeadm init FAILED!"
    echo "📋 End time: $$(date)"
    echo "📋 Full kubeadm output:"
    cat "$$KUBEADM_LOG"
    error_exit "kubeadm init failed"
fi

# Verify admin.conf was created
if [ ! -f /etc/kubernetes/admin.conf ]; then
    error_exit "admin.conf was not created by kubeadm init"
fi

echo "✅ admin.conf verified: $$(stat -c%s /etc/kubernetes/admin.conf) bytes"

# Step 7: Set up kubeconfig for root and ubuntu users
echo "🔧 Step 7: Setting up kubeconfig..."

# Set up for root
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config
chmod 600 /root/.kube/config

# Set up for ubuntu user
mkdir -p /home/ubuntu/.kube
cp -i /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
chown ubuntu:ubuntu /home/ubuntu/.kube/config
chmod 600 /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

echo "✅ Kubeconfig configured for root and ubuntu users"

# Step 8: Test cluster access
echo "🔍 Step 8: Testing cluster access..."
export KUBECONFIG=/etc/kubernetes/admin.conf

if kubectl cluster-info; then
    echo "✅ Cluster access verified"
    kubectl get nodes
else
    error_exit "Cannot access Kubernetes cluster"
fi

# Step 9: Install CNI (Calico)
echo "🌐 Step 9: Installing Calico CNI..."

if kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml; then
    echo "✅ Calico CNI installation initiated"
else
    echo "⚠️ Calico installation failed, but continuing..."
fi

# Step 10: Store join command in AWS Secrets Manager
echo "🔐 Step 10: Storing join command in AWS Secrets Manager..."

# Generate fresh join command
JOIN_COMMAND=$$(kubeadm token create --print-join-command)

if [ -n "$$JOIN_COMMAND" ]; then
    echo "📤 Storing join command in secrets..."
    
    # Store in both secrets
    aws secretsmanager put-secret-value \
        --secret-id "${aws_secretsmanager_secret.kubernetes_join_command.name}" \
        --secret-string "$$JOIN_COMMAND" \
        --region "${var.region}" || echo "⚠️ Failed to store in primary secret"
        
    aws secretsmanager put-secret-value \
        --secret-id "${aws_secretsmanager_secret.kubernetes_join_command_latest.name}" \
        --secret-string "$$JOIN_COMMAND" \
        --region "${var.region}" || echo "⚠️ Failed to store in latest secret"
        
    echo "✅ Join command stored in AWS Secrets Manager"
else
    echo "⚠️ Failed to generate join command"
fi

# Final status report
echo "================================================================="
echo "= KUBERNETES CONTROL PLANE BOOTSTRAP - COMPLETED             ="
echo "= Time: $$(date)"
echo "= Status: SUCCESS"
echo "================================================================="
echo "📊 Final verification:"
echo "   ✅ kubectl: $$(kubectl version --client --short 2>/dev/null)"
echo "   ✅ kubeadm: $$(kubeadm version -o short 2>/dev/null)"
echo "   ✅ kubelet: $$(systemctl is-active kubelet)"
echo "   ✅ containerd: $$(systemctl is-active containerd)"
echo "   ✅ admin.conf: $$([ -f /etc/kubernetes/admin.conf ] && echo 'EXISTS' || echo 'MISSING')"
echo "    Logs available at: $$BOOTSTRAP_LOG"
echo "   📁 Kubeadm logs at: $$KUBEADM_LOG"
echo "================================================================="
EOF

  tags = var.tags
}

# =============================================================================
# 📦 S3 BUCKET - WORKER LOGS STORAGE
# =============================================================================

# S3 bucket for worker logs
resource "aws_s3_bucket" "worker_logs" {
  bucket        = "guy-polybot-logs"
  force_destroy = true

  tags = var.tags
}

resource "aws_s3_bucket_ownership_controls" "worker_logs_ownership" {
  bucket = aws_s3_bucket.worker_logs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "worker_logs_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.worker_logs_ownership]
  
  bucket = aws_s3_bucket.worker_logs.id
  acl    = "private"
}

# =============================================================================
# 🖥️ CONTROL PLANE - KUBERNETES MASTER NODE
# =============================================================================

# Control plane instance
resource "aws_instance" "control_plane" {
  ami                    = var.control_plane_ami
  instance_type          = var.control_plane_instance_type
  key_name               = local.actual_key_name
  vpc_security_group_ids = [aws_security_group.control_plane_sg.id]
  subnet_id              = module.vpc.public_subnets[0]
  iam_instance_profile   = aws_iam_instance_profile.control_plane_profile.name

  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    
    tags = merge(var.tags, {
      Name = "guy-control-plane-root"
    })
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    
    # =================================================================
    # S3 BOOTSTRAP SCRIPT FETCHER - CONTROL PLANE v1
    # =================================================================
    
    echo "========================================================="
    echo "= S3 BOOTSTRAP SCRIPT FETCHER - STARTING              ="
    echo "= Time: $(date)                                         ="
    echo "= Instance: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')"
    echo "========================================================="
    
    # Set up basic logging
    FETCHER_LOG="/var/log/s3-bootstrap-fetcher.log"
    exec > >(tee -a "$FETCHER_LOG") 2>&1
    
    # Error handling
    error_exit() {
        echo "❌ FETCHER ERROR: $1"
        echo "❌ Time: $(date)"
        exit 1
    }
    
    # Install minimal required packages
    echo "📦 Installing minimal required packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || error_exit "Failed to update package list"
    apt-get install -y curl awscli || error_exit "Failed to install curl and awscli"
    
    # Verify AWS CLI
    aws --version || error_exit "AWS CLI not working"
    
    # Download bootstrap script from S3
    echo "📥 Downloading bootstrap script from S3..."
    SCRIPT_PATH="/tmp/control_plane_bootstrap.sh"
    S3_BUCKET="${aws_s3_bucket.user_data_scripts.bucket}"
    S3_KEY="${aws_s3_object.control_plane_script.key}"
    REGION="${var.region}"
    
    echo "📍 S3 Location: s3://$S3_BUCKET/$S3_KEY"
    echo "🌍 Region: $REGION"
    
    # Download with retries
    for attempt in {1..5}; do
        echo "📥 Download attempt $attempt/5..."
        if aws s3 cp "s3://$S3_BUCKET/$S3_KEY" "$SCRIPT_PATH" --region "$REGION"; then
            echo "✅ Script downloaded successfully"
            break
        else
            echo "⚠️ Download attempt $attempt failed"
            if [ $attempt -eq 5 ]; then
                error_exit "Failed to download bootstrap script after 5 attempts"
            fi
            sleep 10
        fi
    done
    
    # Verify script was downloaded
    if [ ! -f "$SCRIPT_PATH" ]; then
        error_exit "Bootstrap script not found at $SCRIPT_PATH"
    fi
    
    # Check script size
    SCRIPT_SIZE=$(stat -c%s "$SCRIPT_PATH")
    echo "📊 Script size: $SCRIPT_SIZE bytes"
    
    if [ $SCRIPT_SIZE -lt 1000 ]; then
        error_exit "Downloaded script too small ($SCRIPT_SIZE bytes), likely corrupted"
    fi
    
    # Make script executable
    chmod +x "$SCRIPT_PATH" || error_exit "Failed to make script executable"
    
    # Execute the bootstrap script
    echo "🚀 Executing bootstrap script..."
    echo "📋 Command: $SCRIPT_PATH"
    echo "📋 Start time: $(date)"
    
    if "$SCRIPT_PATH"; then
        echo "✅ Bootstrap script completed successfully!"
        echo "📋 End time: $(date)"
    else
        error_exit "Bootstrap script execution failed"
    fi
    
    echo "========================================================="
    echo "= S3 BOOTSTRAP SCRIPT FETCHER - COMPLETED             ="
    echo "= Time: $(date)                                         ="
    echo "========================================================="
    EOF
  )

  tags = merge(var.tags, {
    Name = "guy-control-plane"
    Role = "control-plane"
    "kubernetes-io-cluster-${local.cluster_name}" = "owned"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# 🤖 WORKER NODES - AUTO SCALING GROUP
# =============================================================================

# Worker launch template
resource "aws_launch_template" "worker_lt" {
  name_prefix   = "guy-worker-lt-"
  image_id      = var.worker_ami
  instance_type = var.worker_instance_type
  key_name      = local.actual_key_name

  vpc_security_group_ids = [aws_security_group.worker_sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.worker_profile.name
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags = "enabled"
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_type = "gp3"
      volume_size = 20
      encrypted   = true
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/worker_user_data.sh", merge(local.template_vars, {
    cluster_name                = local.cluster_name
    region                     = var.region
    join_command_secret_id     = aws_secretsmanager_secret.kubernetes_join_command_latest.id
    JOIN_COMMAND_LATEST_SECRET = aws_secretsmanager_secret.kubernetes_join_command_latest.name
    control_plane_endpoint     = "https://$${aws_instance.control_plane.private_ip}:6443"
    s3_bucket                  = aws_s3_bucket.worker_logs.bucket
    worker_asg_name            = local.worker_asg_name
    K8S_VERSION_TO_INSTALL     = local.k8s_package_version
  })))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name = "guy-worker-node"
      Role = "worker"
      "kubernetes-io-cluster-${local.cluster_name}" = "owned"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Worker auto scaling group
resource "aws_autoscaling_group" "worker_asg" {
  name                = local.worker_asg_name
  vpc_zone_identifier = module.vpc.public_subnets
  target_group_arns   = [aws_lb_target_group.main_tg.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = 2
  max_size         = 10
  desired_capacity = var.desired_worker_nodes

  launch_template {
    id      = aws_launch_template.worker_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = local.worker_asg_name
    propagate_at_launch = false
  }

  tag {
    key                 = "kubernetes-io-cluster-${local.cluster_name}"
    value               = "owned"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes       = [desired_capacity]
  }
}

# =============================================================================
# ⏳ CLUSTER INITIALIZATION - WAIT FOR CONTROL PLANE
# =============================================================================

# Wait for control plane to be ready
resource "null_resource" "wait_for_control_plane" {
  depends_on = [aws_instance.control_plane]

  triggers = {
    control_plane_id = aws_instance.control_plane.id
    wait_version = "v2-simplified"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      echo "⏳ Waiting for control plane to be ready..."
      echo "Instance ID: ${aws_instance.control_plane.id}"
      echo "Public IP: ${aws_instance.control_plane.public_ip}"
      
      # Wait for instance to be running
      aws ec2 wait instance-running \
        --instance-ids ${aws_instance.control_plane.id} \
        --region ${var.region}
      
      # Wait for SSM agent to be online
      for i in {1..30}; do
        if aws ssm describe-instance-information \
           --region ${var.region} \
           --filters "Key=InstanceIds,Values=${aws_instance.control_plane.id}" \
           --query "InstanceInformationList[0].PingStatus" \
           --output text 2>/dev/null | grep -q "Online"; then
          echo "✅ Control plane SSM agent is online"
          break
        fi
        echo "⏳ Waiting for SSM agent... ($i/30)"
        sleep 10
      done
      
      echo "✅ Control plane is ready for kubeadm initialization"
    EOT
  }
}

# =============================================================================
# 🔄 JOIN COMMAND MANAGEMENT - TOKEN UPDATES
# =============================================================================

# Join command update resource
resource "null_resource" "update_join_command" {
  depends_on = [
    aws_instance.control_plane,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
    null_resource.wait_for_control_plane
  ]

  triggers = {
    control_plane_ip = aws_instance.control_plane.public_ip
    control_plane_id = aws_instance.control_plane.id
    update_version = "v4-syntax-fixed"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      echo "🔄 Join Command Management v4 - Syntax Fixed"
      echo "============================================"
      
      # Skip if explicitly disabled
      if [[ "$${SKIP_JOIN_COMMAND_UPDATE:-false}" == "true" ]]; then
        echo "SKIP_JOIN_COMMAND_UPDATE is set, skipping update"
        exit 0
      fi
      
      echo "📡 Control Plane: ${aws_instance.control_plane.public_ip}"
      echo "🔑 Secrets: ${aws_secretsmanager_secret.kubernetes_join_command_latest.id}"
      
      # Upload logs for troubleshooting with proper command substitution escaping
      TIMESTAMP=$$(date +"%Y%m%d%H%M%S")
      LOG_MESSAGE="Join command update completed at $$(date)"
      S3_KEY="logs/join-command-$${TIMESTAMP}.log"
      
      echo "$$LOG_MESSAGE" | aws s3 cp - "s3://${aws_s3_bucket.worker_logs.bucket}/$$S3_KEY" --region "${var.region}" || true
      
      echo "✅ Join command management completed"
    EOT
  }
}

# =============================================================================
# 🔧 LAMBDA FUNCTIONS - NODE MANAGEMENT AUTOMATION
# =============================================================================

# Lambda function code file
resource "local_file" "lambda_function_code" {
  filename = "${path.module}/lambda_code.py"
  content = <<EOF
import json
import boto3
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Enhanced Node Management Lambda for Kubernetes cluster
    Handles ASG lifecycle events and token refresh
    """
    
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        return {
            'statusCode': 200,
            'body': json.dumps('Node management completed successfully')
        }
        
    except Exception as e:
        logger.error(f"Error in lambda handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }
EOF
}

# Create Lambda ZIP file using archive_file data source
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = local_file.lambda_function_code.filename
  output_path = "${path.module}/lambda_function.zip"
  
  depends_on = [local_file.lambda_function_code]
}

# Lambda IAM role
resource "aws_iam_role" "node_management_lambda_role" {
  name = "guy-node-management-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

# Lambda IAM policy document (using data source for proper interpolation)
data "aws_iam_policy_document" "node_management_lambda_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeTags"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue"
    ]
    resources = [
      aws_secretsmanager_secret.kubernetes_join_command.arn,
      aws_secretsmanager_secret.kubernetes_join_command_latest.arn
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]
    resources = ["${aws_s3_bucket.worker_logs.arn}/*"]
  }
}

# Lambda IAM policy
resource "aws_iam_policy" "node_management_lambda_policy" {
  name   = "guy-node-management-lambda-policy"
  policy = data.aws_iam_policy_document.node_management_lambda_policy.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "node_management_lambda_policy_attach" {
  role       = aws_iam_role.node_management_lambda_role.name
  policy_arn = aws_iam_policy.node_management_lambda_policy.arn
}

# Lambda function for node management
resource "aws_lambda_function" "node_management_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "guy-node-management"
  role            = aws_iam_role.node_management_lambda_role.arn
  handler         = "lambda_code.lambda_handler"
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      CLUSTER_NAME = local.cluster_name
      REGION = var.region
      JOIN_COMMAND_SECRET_ID = aws_secretsmanager_secret.kubernetes_join_command_latest.id
      S3_BUCKET = aws_s3_bucket.worker_logs.bucket
    }
  }

  tags = var.tags
}

# =============================================================================
# 📡 MONITORING AND AUTOMATION - SNS AND CLOUDWATCH
# =============================================================================

# SNS topic for lifecycle events
resource "aws_sns_topic" "lifecycle_topic" {
  name = "guy-asg-lifecycle-topic"
  
  tags = var.tags
}

resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.lifecycle_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.node_management_lambda.arn
}

resource "aws_lambda_permission" "sns_permission" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.node_management_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.lifecycle_topic.arn
}

# CloudWatch event for token refresh
resource "aws_cloudwatch_event_rule" "token_refresh_rule" {
  name                = "guy-token-refresh-rule"
  description         = "Trigger token refresh every 6 hours"
  schedule_expression = "rate(6 hours)"
  
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "token_refresh_target" {
  rule      = aws_cloudwatch_event_rule.token_refresh_rule.name
  target_id = "TokenRefreshTarget"
  arn       = aws_lambda_function.node_management_lambda.arn
}

resource "aws_lambda_permission" "eventbridge_permission" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.node_management_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.token_refresh_rule.arn
}

# =============================================================================
# 🔄 ASG LIFECYCLE HOOKS - GRACEFUL NODE MANAGEMENT
# =============================================================================

# ASG lifecycle hook IAM role
resource "aws_iam_role" "asg_lifecycle_hook_role" {
  name = "guy-asg-lifecycle-hook-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "autoscaling.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "asg_sns_publish_policy" {
  name = "asg-sns-publish-policy"
  role = aws_iam_role.asg_lifecycle_hook_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.lifecycle_topic.arn
      }
    ]
  })
}

# Scale up lifecycle hook
resource "aws_autoscaling_lifecycle_hook" "scale_up_hook" {
  name                   = "guy-scale-up-hook"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 120  # Reduced from 600 to 120 seconds
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"

  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}

# Scale down lifecycle hook
resource "aws_autoscaling_lifecycle_hook" "scale_down_hook" {
  name                   = "guy-scale-down-hook"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 90   # Reduced from 300 to 90 seconds for faster termination
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"

  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}

# Worker script hash for tracking changes
resource "terraform_data" "worker_script_hash" {
  input = md5(file("${path.module}/worker_user_data.sh"))
  
  triggers_replace = {
    rebuild = var.rebuild_workers ? timestamp() : "static"
  }
}

# Progress reporter for worker nodes
resource "terraform_data" "worker_progress" {
  depends_on = [aws_instance.control_plane]
  triggers_replace = {
    timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      echo -e "\\033[0;32m➡️  Step 2/4: Control Plane Ready, Configuring Worker Nodes...\\033[0m"
    EOT
  }
}

# Force update ASG when worker script changes
resource "terraform_data" "force_asg_update" {
  input = terraform_data.worker_script_hash.id
  
  triggers_replace = [
    aws_launch_template.worker_lt.latest_version,
    var.rebuild_workers
  ]
}

# Automatic cluster health assessment to determine if ASG recreation is needed
resource "terraform_data" "cluster_health_assessment" {
  triggers_replace = {
    # Check cluster health whenever these change
    control_plane_id = aws_instance.control_plane.id
    asg_name = local.worker_asg_name
    assessment_version = "v1"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      echo "🔍 Assessing cluster health to determine ASG cleanup needs..."
      
      # Default to no cleanup needed
      echo "false" > /tmp/asg_cleanup_needed.txt
      echo "healthy" > /tmp/cluster_health_status.txt
      
      # Check if control plane is accessible
      CONTROL_PLANE_IP="${aws_instance.control_plane.public_ip}"

      # Try to get kubeconfig and check cluster state
      if aws ssm describe-instance-information --region ${var.region} \
         --filters "Key=InstanceIds,Values=${aws_instance.control_plane.id}" \
         --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
        
        echo "📡 Control plane accessible via SSM, checking cluster state..."
        
        # Get kubeconfig
        COMMAND_ID=$(aws ssm send-command --region ${var.region} \
          --document-name "AWS-RunShellScript" \
          --instance-ids "${aws_instance.control_plane.id}" \
          --parameters 'commands=["cat /etc/kubernetes/admin.conf"]' \
          --output text --query "Command.CommandId")
        
        sleep 10
        
        KUBECONFIG_CONTENT=$(aws ssm get-command-invocation --region ${var.region} \
          --command-id "$COMMAND_ID" --instance-id "${aws_instance.control_plane.id}" \
          --query "StandardOutputContent" --output text 2>/dev/null)
        
        if [[ -n "$KUBECONFIG_CONTENT" ]] && echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion"; then
          echo "✅ Got valid kubeconfig, analyzing cluster health..."
          
          # Create temporary kubeconfig
          echo "$KUBECONFIG_CONTENT" | sed "s|server:.*|server: https://$CONTROL_PLANE_IP:6443|" > /tmp/health_kubeconfig.yaml
          chmod 600 /tmp/health_kubeconfig.yaml
          
          # Check cluster state
          if KUBECONFIG=/tmp/health_kubeconfig.yaml kubectl get nodes >/dev/null 2>&1; then
            echo "📋 Cluster accessible, checking node health..."
            
            # Get node counts
            TOTAL_NODES=$(KUBECONFIG=/tmp/health_kubeconfig.yaml kubectl get nodes --no-headers | wc -l)
            READY_NODES=$(KUBECONFIG=/tmp/health_kubeconfig.yaml kubectl get nodes --no-headers | grep -c " Ready " || echo "0")
            NOTREADY_NODES=$(KUBECONFIG=/tmp/health_kubeconfig.yaml kubectl get nodes --no-headers | grep -c " NotReady " || echo "0")
            WORKER_NODES=$(KUBECONFIG=/tmp/health_kubeconfig.yaml kubectl get nodes --no-headers | grep -c -v "control-plane" || echo "0")
            READY_WORKERS=$(KUBECONFIG=/tmp/health_kubeconfig.yaml kubectl get nodes --no-headers | grep " Ready " | grep -c -v "control-plane" || echo "0")
            
            echo "   Total nodes: $TOTAL_NODES"
            echo "   Ready nodes: $READY_NODES"
            echo "   NotReady nodes: $NOTREADY_NODES"
            echo "   Worker nodes: $WORKER_NODES"
            echo "   Ready workers: $READY_WORKERS"
            
            # Get current ASG desired capacity
            ASG_DESIRED=$(aws autoscaling describe-auto-scaling-groups \
              --region ${var.region} \
              --auto-scaling-group-names "${local.worker_asg_name}" \
              --query "AutoScalingGroups[0].DesiredCapacity" \
              --output text 2>/dev/null || echo "0")
            
            echo "   ASG desired capacity: $ASG_DESIRED"
            
            # Determine if cleanup is needed based on multiple criteria
            CLEANUP_NEEDED=false
            HEALTH_STATUS="healthy"
            
            # Criteria 1: More than 2 NotReady nodes (indicates stuck nodes)
            if [[ "$NOTREADY_NODES" -gt 2 ]]; then
              echo "❌ Too many NotReady nodes ($NOTREADY_NODES) - cleanup needed"
              CLEANUP_NEEDED=true
              HEALTH_STATUS="too_many_notready_nodes"
            fi
            
            # Criteria 2: No Ready workers but ASG shows desired capacity > 0
            if [[ "$READY_WORKERS" -eq 0 ]] && [[ "$ASG_DESIRED" -gt 0 ]]; then
              echo "❌ No Ready workers but ASG has desired capacity $ASG_DESIRED - cleanup needed"
              CLEANUP_NEEDED=true
              HEALTH_STATUS="no_ready_workers"
            fi
            
            # Criteria 3: Worker count significantly different from ASG desired capacity
            WORKER_DEFICIT=$((ASG_DESIRED - READY_WORKERS))
            if [[ "$WORKER_DEFICIT" -gt 1 ]] && [[ "$ASG_DESIRED" -gt 0 ]]; then
              echo "❌ Worker deficit too large: need $ASG_DESIRED, have $READY_WORKERS ready - cleanup needed"
              CLEANUP_NEEDED=true
              HEALTH_STATUS="worker_deficit"
            fi
            
            # Output results
            if [[ "$CLEANUP_NEEDED" == "true" ]]; then
              echo "true" > /tmp/asg_cleanup_needed.txt
              echo "$HEALTH_STATUS" > /tmp/cluster_health_status.txt
              echo "🔧 DECISION: ASG cleanup and recreation needed"
              echo "   Reason: $HEALTH_STATUS"
            else
              echo "false" > /tmp/asg_cleanup_needed.txt
              echo "healthy" > /tmp/cluster_health_status.txt
              echo "✅ DECISION: Cluster is healthy, no ASG cleanup needed"
            fi
            
          else
            echo "❌ Cannot connect to Kubernetes API - assuming unhealthy"
            echo "true" > /tmp/asg_cleanup_needed.txt
            echo "api_unreachable" > /tmp/cluster_health_status.txt
          fi
          
          # Cleanup temp kubeconfig
          rm -f /tmp/health_kubeconfig.yaml
          
        else
          echo "❌ Could not get valid kubeconfig"
          echo "true" > /tmp/asg_cleanup_needed.txt
          echo "kubeconfig_unavailable" > /tmp/cluster_health_status.txt
        fi
        
      else
        echo "ℹ️ Control plane not accessible via SSM yet - assuming first run"
        echo "false" > /tmp/asg_cleanup_needed.txt
        echo "control_plane_not_ready" > /tmp/cluster_health_status.txt
      fi
      
      CLEANUP_DECISION=$(cat /tmp/asg_cleanup_needed.txt)
      HEALTH_STATUS=$(cat /tmp/cluster_health_status.txt)
      
      echo ""
      echo "📊 Health Assessment Results:"
      echo "   Cleanup needed: $CLEANUP_DECISION"
      echo "   Health status: $HEALTH_STATUS"
      echo ""
    EOT
  }

  depends_on = [aws_instance.control_plane]
}

