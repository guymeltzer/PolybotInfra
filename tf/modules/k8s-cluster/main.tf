# =============================================================================
# K8S-CLUSTER MODULE - REFACTORED AND OPTIMIZED
# =============================================================================
# Kubernetes Version: Defined by local.k8s_version_full
# Comprehensive cluster infrastructure with logical organization

# =============================================================================
# 🌐 NETWORKING - VPC AND SUBNETS
# =============================================================================

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0" # Consider pinning to a more specific minor version for stability

  name = "${var.cluster_name}-vpc" # Using var.cluster_name for VPC name
  cidr = "10.0.0.0/16"          # Consider making this a variable

  azs             = ["${var.region}a", "${var.region}b"] # Assumes 2 AZs, make this configurable if needed
  public_subnets  = ["10.0.0.0/24", "10.0.2.0/24"]     # Consider making these configurable
  private_subnets = ["10.0.1.0/24"]                   # Consider making these configurable

  enable_nat_gateway   = true
  single_nat_gateway   = true # For cost savings in dev; for HA, set to false
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name                                      = "${var.cluster_name}-vpc"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned" # Standard EKS tag, good practice
  })

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    "kubernetes.io/role/elb"                    = "1"
    # "kubernetes.io/role/internal-elb" = "1" # Usually for private subnets if used for internal LBs
  }

  private_subnet_tags = { # Added tags for private subnets
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    "kubernetes.io/role/internal-elb"           = "1"
  }
}

# =============================================================================
# 📋 LOCALS - CENTRALIZED CONFIGURATION
# =============================================================================

locals {
  # Kubernetes version configuration
  k8s_version_full    = "1.32.3" # Hardcoded as per user's file, consider making this a variable
  k8s_major_minor     = "1.32"   # Derived from k8s_version_full if it were a var
  k8s_package_version = "${local.k8s_version_full}-1.1" # Ensure this format matches actual package versions

  # CRI-O (if used) or other runtime versions might be defined here
  # crio_k8s_major_minor = local.k8s_major_minor # Example if CRI-O was used

  # Cluster configuration
  calico_version_for_template = "v3.27.3"
  cluster_name = var.cluster_name
  pod_cidr     = var.pod_cidr # Example: "10.244.0.0/16"

  # ASG names
  worker_asg_name = "${var.cluster_name}-workers-asg" # Made dynamic with cluster_name

  # SSH key management
  actual_key_name = var.key_name != "" ? var.key_name : (
    length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : null # Return null if no key generated and none provided
  )

  # Common template variables for user data scripts (control plane and workers)
  # These will be passed to templatefile function
  common_template_vars = {
    K8S_VERSION_FULL    = local.k8s_version_full
    K8S_MAJOR_MINOR     = local.k8s_major_minor
    K8S_PACKAGE_VERSION = local.k8s_package_version
    # CRIO_K8S_MAJOR_MINOR = local.crio_k8s_major_minor # If using CRI-O
    REGION              = var.region
    CLUSTER_NAME        = local.cluster_name
  }

  # Control plane specific template variables
  control_plane_template_vars = merge(local.common_template_vars, {
    HOSTNAME_SUFFIX                 = random_string.hostname_suffix.result # Changed from token_part1 for clarity
    KUBEADM_TOKEN                   = local.kubeadm_token
    POD_CIDR_BLOCK                  = local.pod_cidr
    KUBECONFIG_SECRET_NAME          = aws_secretsmanager_secret.cluster_kubeconfig.name
    JOIN_COMMAND_PRIMARY_SECRET_NAME = aws_secretsmanager_secret.kubernetes_join_command.name
    JOIN_COMMAND_LATEST_SECRET_NAME  = aws_secretsmanager_secret.kubernetes_join_command_latest.name
    CALICO_VERSION                   = local.calico_version_for_template
    # PRIVATE_IP will be determined by the script on the instance itself
  })

  # Worker specific template variables
  worker_template_vars = merge(local.common_template_vars, {
    # JOIN_COMMAND_SECRET_ID and JOIN_COMMAND_LATEST_SECRET are passed directly in launch_template
    # K8S_PACKAGE_VERSION_TO_INSTALL is already K8S_PACKAGE_VERSION
    # K8S_MAJOR_MINOR_FOR_REPO is already K8S_MAJOR_MINOR
    # CRIO_K8S_MAJOR_MINOR_FOR_REPO is already CRIO_K8S_MAJOR_MINOR
    # TOKEN_SUFFIX is not directly used by worker_user_data based on original structure; join token is via SecretsManager
    SSH_PUBLIC_KEY_CONTENT = var.ssh_public_key != "" ? var.ssh_public_key : (
      length(tls_private_key.ssh) > 0 ? tls_private_key.ssh[0].public_key_openssh : ""
    )
    # Control plane endpoint will be passed directly using aws_instance.control_plane.private_ip
  })
}

# =============================================================================
# 🎲 RANDOM RESOURCES - TOKENS AND IDENTIFIERS
# =============================================================================

resource "random_string" "hostname_suffix" { # Renamed for clarity
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "kubeadm_token_part2" { # Renamed for clarity
  length  = 16
  special = false
  upper   = false
}

# Random suffix for unique resource naming where needed (e.g., S3 bucket)
resource "random_id" "unique_suffix" { # Renamed for clarity
  byte_length = 4
}

# Formatted kubeadm token
locals {
  kubeadm_token = "${random_string.hostname_suffix.result}.${random_string.kubeadm_token_part2.result}"
}

# =============================================================================
# 🔐 SECRETS MANAGEMENT - KUBECONFIG & JOIN COMMANDS
# =============================================================================

resource "aws_secretsmanager_secret" "cluster_kubeconfig" {
  name                    = "${local.cluster_name}-kubeconfig-${random_id.unique_suffix.hex}"
  description             = "Kubeconfig for the ${local.cluster_name} Kubernetes cluster, modified for external access."
  recovery_window_in_days = 0 # Set to 0 for immediate deletion if destroy; for prod consider 7-30 days.
  force_overwrite_replica_secret = true # If using replicas

  tags = var.tags
}

resource "aws_secretsmanager_secret" "kubernetes_join_command" {
  name                    = "${local.cluster_name}-join-command-${random_id.unique_suffix.hex}"
  description             = "Kubernetes join command for worker nodes"
  recovery_window_in_days = 0
  force_overwrite_replica_secret = true

  lifecycle {
    create_before_destroy = true # Good for handling updates if name doesn't change often
  }
  tags = var.tags
}

resource "aws_secretsmanager_secret" "kubernetes_join_command_latest" {
  name                    = "${local.cluster_name}-join-command-latest-${random_id.unique_suffix.hex}"
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

resource "aws_security_group" "control_plane_sg" {
  name        = "${var.cluster_name}-cp-sg"
  description = "Security group for Kubernetes control plane (${var.cluster_name})"
  vpc_id      = module.vpc.vpc_id

  # ... other ingress rules (K8s API, SSH, VPC internal) remain the same ...
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kubernetes API server from anywhere"
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [module.vpc.vpc_cidr_block]
    description = "Internal VPC traffic to control plane"
  }

  # Corrected etcd rule: Allows instances within this same SG to communicate on these ports
  ingress {
    from_port   = 2379
    to_port     = 2380
    protocol    = "tcp"
    self        = true # <--- FIX: Allows traffic from other members of this SG
    description = "etcd communication within control_plane_sg"
  }

  # If workers also need to access etcd on the control plane (add this rule if needed):
  # ingress {
  #   from_port       = 2379
  #   to_port         = 2380
  #   protocol        = "tcp"
  #   security_groups = [aws_security_group.worker_sg.id] # Allow from worker SG
  #   description     = "etcd communication from workers to control plane"
  # }

  # ... egress rule remains the same ...
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
  tags = merge(var.tags, { Name = "${var.cluster_name}-cp-sg" })
}

resource "aws_security_group" "worker_sg" {
  name        = "${var.cluster_name}-worker-sg"
  description = "Security group for Kubernetes worker nodes (${var.cluster_name})"
  vpc_id      = module.vpc.vpc_id

  # ... SSH ingress rule remains the same ...
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Corrected rule for internal cluster traffic
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.control_plane_sg.id] # Allows from control plane
    description     = "Traffic from Control Plane SG"
  }
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true # <--- FIX: Allows traffic from other workers in this same SG
    description = "Worker-to-worker traffic within worker_sg"
  }

  # ... NodePort and Kubelet API ingress rules remain the same ...
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort services"
  }
  ingress {
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.control_plane_sg.id]
    description     = "Kubelet API"
  }

  # ... egress rule remains the same ...
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
  tags = merge(var.tags, { Name = "${var.cluster_name}-worker-sg" })
}

resource "aws_security_group" "alb_sg" {
  name        = "${var.cluster_name}-alb-sg"
  description = "Security group for Application Load Balancer (${var.cluster_name})"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow HTTP from anywhere
    description = "HTTP traffic"
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow HTTPS from anywhere
    description = "HTTPS traffic"
  }
  egress { # ALB needs to talk to instances on NodePorts
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    security_groups = [aws_security_group.worker_sg.id] # Allow ALB to reach worker NodePorts
    description = "Outbound to worker NodePorts"
  }
  # Add any other necessary egress, e.g., to internet if health checks need it
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all other outbound (review if too permissive)"
  }
  tags = merge(var.tags, { Name = "${var.cluster_name}-alb-sg" })
}

# =============================================================================
# 🔑 IAM ROLES AND POLICIES - ACCESS MANAGEMENT
# =============================================================================

resource "aws_iam_role" "control_plane_role" {
  name = "${var.cluster_name}-cp-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = var.tags
}

data "aws_iam_policy_document" "control_plane_inline_policy_doc" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances", "ec2:DescribeTags", "ec2:CreateTags", # Basic EC2 info, tagging
      "ec2:AttachVolume", "ec2:DetachVolume", "ec2:DescribeVolumes", # For EBS CSI
      # Add more specific EC2 permissions if needed by cloud controller manager
    ]
    resources = ["*"] # Consider restricting if possible
  }
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue", # For workers to get join token (if CP distributes)
      "secretsmanager:PutSecretValue"  # For CP to store kubeconfig and join token
    ]
    resources = [
      aws_secretsmanager_secret.cluster_kubeconfig.arn, # New kubeconfig secret
      aws_secretsmanager_secret.kubernetes_join_command.arn,
      aws_secretsmanager_secret.kubernetes_join_command_latest.arn
    ]
  }
  statement { # For S3 user_data script fetching & log uploads
    effect = "Allow"
    actions = [
      "s3:GetObject" # For fetching the main bootstrap script
    ]
    resources = ["${aws_s3_bucket.user_data_scripts.arn}/${aws_s3_object.control_plane_script.key}"]
  }
  statement { # For log uploads from bootstrap script
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    # This was your S3 bucket for worker logs, assuming CP also logs here or its own dedicated one
    resources = ["${aws_s3_bucket.worker_logs.arn}/*"]
  }
  statement { # For AWS Load Balancer Controller (if used and runs on CP)
    effect = "Allow"
    actions = [
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags",
      "ec2:GetCoipPoolUsage", # Conditional
      "ec2:DescribeCoipPools", # Conditional
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:DeleteRule",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyRule",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:SetWebAcl", # Conditional
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
      "iam:CreateServiceLinkedRole", # Potentially needed once
      "iam:GetServerCertificate", # For ACM/IAM certs if used with ALB
      "iam:ListServerCertificates",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "waf-regional:GetWebACLForResource", # Conditional
      "waf-regional:GetWebACL", # Conditional
      "waf-regional:AssociateWebACL", # Conditional
      "waf-regional:DisassociateWebACL", # Conditional
      "wafv2:GetWebACL", # Conditional
      "wafv2:GetWebACLForResource", # Conditional
      "wafv2:AssociateWebACL", # Conditional
      "wafv2:DisassociateWebACL", # Conditional
      "shield:DescribeProtection", # Conditional
      "shield:GetSubscriptionState", # Conditional
      "shield:DeleteProtection", # Conditional
      "shield:CreateProtection", # Conditional
      "shield:DescribeSubscription", # Conditional
      "shield:ListProtections" # Conditional
    ]
    resources = ["*"] # These are broad, typical for ALB controller
  }
  # Your original comprehensive policy had Lambda invoke, removing unless CP EC2 calls Lambda directly
  # statement {
  #   Effect = "Allow"
  #   Action = [
  #     "lambda:InvokeFunction",
  #     "lambda:GetFunction",
  #     "lambda:ListFunctions"
  #   ]
  #   Resource = aws_lambda_function.node_management_lambda.arn # This implies lambda is defined in this module
  # }
}

resource "aws_iam_role_policy" "control_plane_inline_policy" { # Renamed from comprehensive
  name   = "${var.cluster_name}-cp-inline-policy"
  role   = aws_iam_role.control_plane_role.id
  policy = data.aws_iam_policy_document.control_plane_inline_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "control_plane_ssm_policy" {
  role       = aws_iam_role.control_plane_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "control_plane_cloudwatch_policy" {
  role       = aws_iam_role.control_plane_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Added EBS CSI Driver Policy for control plane (needed if it runs csi-provisioner or attacher)
resource "aws_iam_role_policy_attachment" "control_plane_ebs_csi_policy" {
  role       = aws_iam_role.control_plane_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy" # Corrected ARN
}


resource "aws_iam_instance_profile" "control_plane_profile" {
  name = "${var.cluster_name}-cp-profile"
  role = aws_iam_role.control_plane_role.name
  tags = var.tags
}

resource "aws_iam_role" "worker_role" {
  name = "${var.cluster_name}-worker-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "worker_eks_policies" { # Renamed for clarity
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy", # Covers CNI pod permissions
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", # For pulling images from ECR
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy" # For worker nodes to interact with EBS CSI
  ])
  role       = aws_iam_role.worker_role.name
  policy_arn = each.value
}

# Add S3 read for worker_logs if workers need to fetch anything or for consistency (though less common)
data "aws_iam_policy_document" "worker_s3_logs_policy_doc" {
  statement {
    actions = [
      "s3:GetObject", # If workers fetch from it
      "s3:PutObject", # If workers directly upload logs (less common, usually via Fluentd/CW agent)
      "s3:ListBucket" # If needed
    ]
    resources = [
      aws_s3_bucket.worker_logs.arn,
      "${aws_s3_bucket.worker_logs.arn}/*",
    ]
  }
}
resource "aws_iam_role_policy" "worker_s3_logs_policy" {
  name   = "${var.cluster_name}-worker-s3-logs-policy"
  role   = aws_iam_role.worker_role.id
  policy = data.aws_iam_policy_document.worker_s3_logs_policy_doc.json
}

# Worker nodes need Secrets Manager access to retrieve join commands
data "aws_iam_policy_document" "worker_secrets_manager_policy_doc" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [
      aws_secretsmanager_secret.kubernetes_join_command.arn,
      aws_secretsmanager_secret.kubernetes_join_command_latest.arn
    ]
  }
}

resource "aws_iam_role_policy" "worker_secrets_manager_policy" {
  name   = "${var.cluster_name}-worker-secrets-manager-policy"
  role   = aws_iam_role.worker_role.id
  policy = data.aws_iam_policy_document.worker_secrets_manager_policy_doc.json
}

# Worker nodes need Secrets Manager access to retrieve polybot application secrets
data "aws_iam_policy_document" "worker_polybot_secrets_policy_doc" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [
      "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:polybot-secrets-*"
    ]
  }
}

resource "aws_iam_role_policy" "worker_polybot_secrets_policy" {
  name   = "${var.cluster_name}-worker-polybot-secrets-policy"
  role   = aws_iam_role.worker_role.id
  policy = data.aws_iam_policy_document.worker_polybot_secrets_policy_doc.json
}

resource "aws_iam_instance_profile" "worker_profile" {
  name = "${var.cluster_name}-worker-profile"
  role = aws_iam_role.worker_role.name
  tags = var.tags
}

# =============================================================================
# 🔑 SSH KEY MANAGEMENT
# =============================================================================

resource "tls_private_key" "ssh" {
  count     = var.key_name == "" ? 1 : 0 # Only create if key_name is not provided
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "${var.cluster_name}-bootstrap-key" # Use cluster_name for uniqueness
  public_key = tls_private_key.ssh[0].public_key_openssh
  tags       = var.tags
}

resource "local_file" "ssh_private_key" {
  count           = var.key_name == "" && length(tls_private_key.ssh) > 0 ? 1 : 0
  content         = tls_private_key.ssh[0].private_key_pem
  filename        = var.ssh_private_key_file_path != "" ? var.ssh_private_key_file_path : "${path.module}/../../${local.actual_key_name}.pem" # Use var if provided
  file_permission = "0600"
}

# =============================================================================
# 🔐 SSL CERTIFICATE - ACM WITH DNS VALIDATION
# =============================================================================

resource "aws_acm_certificate" "polybot_cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
  tags = merge(var.tags, { Name = "${var.cluster_name}-ssl-certificate" })
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.polybot_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  allow_overwrite = true # This might be problematic if other records exist with same name/type
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

resource "aws_acm_certificate_validation" "polybot_cert_validation" {
  certificate_arn         = aws_acm_certificate.polybot_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
  timeouts { create = "10m" } # Increased timeout for DNS propagation
}

# =============================================================================
# ⚖️ LOAD BALANCER - APPLICATION LOAD BALANCER
# =============================================================================

resource "aws_lb" "polybot_alb" {
  name               = "${var.cluster_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = module.vpc.public_subnets # Ensure these are public subnets
  enable_deletion_protection = false # Set to true for production
  tags = merge(var.tags, { Name = "${var.cluster_name}-alb" })
}

resource "aws_lb_target_group" "main_tg" {
  name_prefix = substr("${var.cluster_name}-main-", 0, 6) # Max 32 chars, ensure prefix + random is within limits <-- ADDED CLOSING PARENTHESIS
  port        = 80 # Assuming services in K8s expose HTTP on a NodePort that maps to their internal port
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance" # For NodePort services; use 'ip' for Fargate or direct pod IP routing with CNI support

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3 # Increased from 2 for a bit more tolerance
    interval            = 30
    matcher             = "200" # Be specific. 404 might mean service is up but path is wrong for health.
    path                = var.alb_health_check_path # Make this configurable, e.g., "/healthz" or "/"
    port                = "traffic-port" # Checks the instance on the target group port (e.g., 80 or NodePort)
    protocol            = "HTTP" # Can be HTTPS if instances serve HTTPS directly on NodePort
    timeout             = 10     # Increased timeout
  }
  tags = var.tags
}

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
    # Only specify target_group_arn if not redirecting
    target_group_arn = var.redirect_http_to_https ? null : aws_lb_target_group.main_tg.arn
  }
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.alb_ssl_policy # Make this a variable, e.g., "ELBSecurityPolicy-TLS-1-2-Ext-2018-06"
  certificate_arn   = aws_acm_certificate.polybot_cert.arn # Validation happens before listener creation

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main_tg.arn
  }
  depends_on = [aws_acm_certificate_validation.polybot_cert_validation] # Ensure cert is validated
}

# =============================================================================
# 📦 S3 BUCKET - USER DATA SCRIPTS & WORKER LOGS
# =============================================================================

resource "aws_s3_bucket" "user_data_scripts" {
  bucket        = "${var.cluster_name}-k8s-userdata-${random_id.unique_suffix.hex}"
  force_destroy = true # OK for dev, be cautious in prod
  tags          = var.tags
}
resource "aws_s3_bucket_ownership_controls" "user_data_scripts_ownership" {
  bucket = aws_s3_bucket.user_data_scripts.id
  rule { object_ownership = "BucketOwnerPreferred" }
}
resource "aws_s3_bucket_acl" "user_data_scripts_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.user_data_scripts_ownership]
  bucket     = aws_s3_bucket.user_data_scripts.id
  acl        = "private"
}

# S3 bucket for worker logs (if distinct from other logs)
resource "aws_s3_bucket" "worker_logs" {
  bucket        = "${var.cluster_name}-worker-logs-${random_id.unique_suffix.hex}" # Make name unique
  force_destroy = true # OK for dev
  tags          = var.tags
}
resource "aws_s3_bucket_ownership_controls" "worker_logs_ownership" {
  bucket = aws_s3_bucket.worker_logs.id
  rule { object_ownership = "BucketOwnerPreferred" }
}
resource "aws_s3_bucket_acl" "worker_logs_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.worker_logs_ownership]
  bucket     = aws_s3_bucket.worker_logs.id
  acl        = "private"
}

# Upload control plane script (as a template file) to S3
resource "aws_s3_object" "control_plane_script" {
  bucket  = aws_s3_bucket.user_data_scripts.id # Corrected: use .id for bucket name reference
  key     = "bootstrap_scripts/control_plane_bootstrap_v10.sh" # Versioned key
  content = templatefile("${path.module}/scripts/control_plane_bootstrap.sh.tpl", local.control_plane_template_vars)
  tags    = var.tags
  # ETag will change if content changes, can be used to trigger instance recreation if desired
}

# =============================================================================
# 🖥️ CONTROL PLANE - KUBERNETES MASTER NODE
# =============================================================================

resource "aws_instance" "control_plane" {
  ami                         = var.control_plane_ami
  instance_type               = var.control_plane_instance_type
  key_name                    = local.actual_key_name
  vpc_security_group_ids      = [aws_security_group.control_plane_sg.id]
  subnet_id                   = module.vpc.public_subnets[0] # Assuming first public subnet
  iam_instance_profile        = aws_iam_instance_profile.control_plane_profile.name
  associate_public_ip_address = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Good practice
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.control_plane_root_volume_size # Make this a variable
    encrypted   = true
    tags        = merge(var.tags, { Name = "${var.cluster_name}-cp-root" })
  }

  # User data now fetches the main script from S3
  user_data = base64encode(templatefile("${path.module}/scripts/fetch_and_run.sh.tpl", {
    S3_BUCKET_NAME = aws_s3_bucket.user_data_scripts.id # Or .bucket
    S3_SCRIPT_KEY  = aws_s3_object.control_plane_script.key
    AWS_REGION     = var.region
    EXTRA_ARGS     = "" # Any extra args to pass to the downloaded script
  }))

  tags = merge(var.tags, {
    Name                                           = "${var.cluster_name}-control-plane"
    Role                                           = "control-plane"
    "kubernetes.io_cluster_${local.cluster_name}"  = "owned" # CORRECTED: Slashes replaced with underscores
  })

  lifecycle {
    create_before_destroy = true
    # ignore_changes = [user_data] # Add this if you manage updates by replacing the instance via other triggers (e.g. AMI change)
  }
}

# =============================================================================
# 🤖 WORKER NODES - AUTO SCALING GROUP
# =============================================================================

resource "aws_launch_template" "worker_lt" {
  name_prefix   = "${var.cluster_name}-worker-lt-"
  image_id      = var.worker_ami
  instance_type = var.worker_instance_type
  key_name      = local.actual_key_name # Ensures workers can use the same key

  iam_instance_profile { name = aws_iam_instance_profile.worker_profile.name }

  # Add network configuration to ensure public IP assignment
  network_interfaces {
    associate_public_ip_address = true
    security_groups            = [aws_security_group.worker_sg.id]
    delete_on_termination      = true
  }

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags = "enabled"
  }

  block_device_mappings {
    device_name = "/dev/sda1" # Or your worker AMI's root device
    ebs {
      volume_type           = "gp3"
      volume_size           = var.worker_root_volume_size # Make this a variable
      encrypted             = true
      delete_on_termination = true
    }
  }

  # Ensure worker_user_data.sh is a template file
  user_data = base64encode(templatefile("${path.module}/scripts/worker_user_data.sh.tpl", merge(local.worker_template_vars, {
    # Explicitly pass needed values; many are in local.worker_template_vars
    TF_JOIN_COMMAND_LATEST_SECRET_NAME = aws_secretsmanager_secret.kubernetes_join_command_latest.name
    TF_CONTROL_PLANE_PRIVATE_IP      = aws_instance.control_plane.private_ip # Pass the actual IP
    TF_S3_WORKER_LOGS_BUCKET         = aws_s3_bucket.worker_logs.id # Or .bucket
    TF_WORKER_ASG_NAME               = local.worker_asg_name
    # Other variables like K8S versions are already in local.worker_template_vars
  })))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name                                        = "${var.cluster_name}-worker-node"
      Role                                        = "worker"
      "kubernetes.io_cluster_${local.cluster_name}" = "owned"
    })
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_autoscaling_group" "worker_asg" {
  name                      = local.worker_asg_name
  vpc_zone_identifier       = module.vpc.public_subnets # Workers in public subnets for simplicity; private with NAT for prod
  # target_group_arns         = [aws_lb_target_group.main_tg.arn] # Only if ASG instances are directly registered; usually K8s Service of type LB handles this via NodePorts. This might be for classic ELB or specific setups. If using ALB with NodePort, this is not needed here.
  health_check_type         = "EC2" # "ELB" is only if target_group_arns is used and ELB does health checks. EC2 is more common for ASG itself.
  health_check_grace_period = 300   # Time for instance to boot and join cluster

  min_size                  = var.min_worker_nodes # Use specific min/max vars
  max_size                  = var.max_worker_nodes
  desired_capacity          = var.desired_worker_nodes

  launch_template {
    id      = aws_launch_template.worker_lt.id
    version = "$Latest" # Or specific version: aws_launch_template.worker_lt.latest_version
  }

  # Propagate tags to instances
  dynamic "tag" {
    for_each = merge(var.tags, {
      Name                                        = "${var.cluster_name}-worker-instance" # Instances will get this name
      Role                                        = "worker"
      "kubernetes.io_cluster_${local.cluster_name}" = "owned"
    })
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # ignore_changes       = [desired_capacity] # Only if something else manages desired_capacity (e.g. cluster autoscaler)
  }
  # Suspends processes that might interfere with cluster autoscaler or custom logic
  # suspended_processes = ["AZRebalance", "AlarmNotification", "ScheduledActions"]
}

# =============================================================================
# ⏳ CLUSTER INITIALIZATION HELPERS (MODULE INTERNAL) - MINIMIZE LOCAL-EXEC
# =============================================================================

# This resource primarily serves as a dependency anchor and to output instance details.
# The actual readiness polling is better handled in the root module after kubeconfig is in Secrets Manager.
resource "null_resource" "control_plane_provisioned_signal" {
  triggers = {
    instance_id = aws_instance.control_plane.id
  }
  # No provisioner here; its existence signals the instance resource completed.
}


# The local-exec for update_join_command can remain if it's simple and robust.
# It updates a secret after the control plane is up.
resource "null_resource" "update_join_command" {
  depends_on = [
    aws_instance.control_plane,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
  ]

  triggers = {
    control_plane_id   = aws_instance.control_plane.id
    update_version     = "v14-bash-syntax-corrected" # Fixed bash variable syntax
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      set -e

      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }
      
      log_header "🔄 Join Command Management v12 (simplified - control plane handles initial setup)"

      if [[ "${var.skip_token_verification}" == "true" ]]; then
        log_info "SKIP_JOIN_COMMAND_UPDATE is true, skipping update."
        exit 0
      fi

      LATEST_SECRET_ID="${aws_secretsmanager_secret.kubernetes_join_command_latest.name}"
      REGION_NAME="${var.region}"

      log_subheader "🔍 Verifying join command availability"
      log_step "Verifying join command is available in Secrets Manager"
      log_info "Secret ID: $${BOLD}$LATEST_SECRET_ID$${RESET}"
      log_info "Region: $${BOLD}$REGION_NAME$${RESET}"
      
      JOIN_COMMAND=$(aws secretsmanager get-secret-value \
        --secret-id "$LATEST_SECRET_ID" \
        --region "$REGION_NAME" \
        --query SecretString --output text 2>/dev/null || echo "")

      if [[ -n "$JOIN_COMMAND" ]] && echo "$JOIN_COMMAND" | grep -q "kubeadm join"; then
        log_success "Join command is available in Secrets Manager"
        log_success "Join command management completed successfully"
      else
        log_warning "Join command not yet available, but control plane bootstrap should handle this"
        log_success "Proceeding (control plane will generate join command)"
      fi
    EOT
  }
}


# =============================================================================
# 🔧 LAMBDA FUNCTIONS (Placeholder - content seems mostly okay, review IAM and triggers)
# =============================================================================
# Note: The Lambda and its associated resources (IAM, S3 for code, SNS, CloudWatch Events)
# are complex and depend on the specific logic within lambda_code.py.
# The IAM policy data.aws_iam_policy_document.node_management_lambda_policy looks reasonable.
# Ensure the lambda_code.py is correctly packaged by data.archive_file.lambda_zip.

# This was identified as problematic, assuming lambda_code.py is a source file you provide
# =============================================================================
# 🔧 LAMBDA FUNCTIONS - NODE MANAGEMENT AUTOMATION
# =============================================================================

# Data source to get current AWS account ID for more specific IAM policy resources
data "aws_caller_identity" "current" {}

# The archive_file data source now directly references your Python script.
# IMPORTANT: Ensure modules/k8s-cluster/scripts/lambda_code.py exists and contains
#            the Python code I helped you adapt in the previous step.
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/scripts/lambda_code.py" # Directly uses your .py file
  output_path = "${path.module}/lambda_function.zip"    # Temporary path for the generated zip
}

resource "aws_iam_role" "node_management_lambda_role" {
  name = "${var.cluster_name}-node-mgmt-lambda-role" # Using var.cluster_name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = var.tags
}

data "aws_iam_policy_document" "node_management_lambda_policy_doc" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.cluster_name}-node-management:*"]
  }
  statement {
    effect    = "Allow"
    actions   = [
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances"
      # Add "autoscaling:SetDesiredCapacity" if your Lambda might adjust ASG size
    ]
    resources = ["*"] # Consider scoping this down if possible, e.g., to specific ASG ARNs
  }
  statement {
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeTags"]
    resources = ["*"] # Broad, but often needed for instance inspection
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
    resources = [ # Be specific with secret ARNs
      aws_secretsmanager_secret.kubernetes_join_command.arn,
      aws_secretsmanager_secret.kubernetes_join_command_latest.arn
      # Add any other secrets the Lambda needs to access
    ]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"] # If Lambda writes/reads from S3
    resources = ["${aws_s3_bucket.worker_logs.arn}/*"] # Example for worker_logs bucket
  }

  # ===> ADDED/MODIFIED SSM PERMISSIONS <===
  statement {
    effect  = "Allow"
    actions = ["ssm:SendCommand"]
    resources = [
      # Permission to send to the specific control plane instance
      "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.control_plane.id}",
      # Permission to use the AWS-RunShellScript document
      "arn:aws:ssm:${var.region}::document/AWS-RunShellScript"
    ]
  }
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"] # GetCommandInvocation result doesn't have a specific resource ARN to scope to easily other than "*"
  }
}

resource "aws_iam_policy" "node_management_lambda_policy" {
  name   = "${var.cluster_name}-node-mgmt-lambda-policy"
  policy = data.aws_iam_policy_document.node_management_lambda_policy_doc.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "node_management_lambda_policy_attach" {
  role       = aws_iam_role.node_management_lambda_role.name
  policy_arn = aws_iam_policy.node_management_lambda_policy.arn
}

resource "aws_lambda_function" "node_management_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256 # Ensures Lambda updates if code changes
  function_name    = "${var.cluster_name}-node-management"
  role             = aws_iam_role.node_management_lambda_role.arn
  handler          = "lambda_code.lambda_handler" # Assumes your Python file is lambda_code.py and has lambda_handler
  runtime          = "python3.9" # Or your preferred supported Python runtime
  timeout          = 300         # 5 minutes
  memory_size      = 256         # Adjust as needed

  environment {
    variables = {
      REGION                      = var.region
      CLUSTER_NAME                = local.cluster_name # Passed from module's locals
      # This is the secret ID the Lambda will *update* with the latest join token
      JOIN_COMMAND_LATEST_SECRET_ID = aws_secretsmanager_secret.kubernetes_join_command_latest.id
      # This is the specific EC2 instance ID of your control plane
      CONTROL_PLANE_INSTANCE_ID   = aws_instance.control_plane.id
      S3_LOG_BUCKET               = aws_s3_bucket.worker_logs.id # Pass the bucket name/id
      # KUBECONFIG_PATH_ON_CP is implicitly /etc/kubernetes/admin.conf in your Python code
    }
  }
  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.node_management_lambda_policy_attach, data.archive_file.lambda_zip]
}

# Note: The local_file "lambda_function_code" resource that was previously here trying to read
# lambda_code.py has been REMOVED as it was causing errors if the file didn't exist.
# You must now ensure modules/k8s-cluster/scripts/lambda_code.py contains your Python code.

# =============================================================================
# 📡 MONITORING AND AUTOMATION - SNS AND CLOUDWATCH EVENTS
# =============================================================================
# (Assuming the SNS/CloudWatch Event setup is largely as provided and correct for the Lambda)

resource "aws_sns_topic" "lifecycle_topic" {
  name = "${var.cluster_name}-asg-lifecycle-events"
  tags = var.tags
}
resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.lifecycle_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.node_management_lambda.arn
}
resource "aws_lambda_permission" "sns_permission" {
  statement_id  = "AllowExecutionFromSNS-${var.cluster_name}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.node_management_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.lifecycle_topic.arn
}

resource "aws_cloudwatch_event_rule" "token_refresh_rule" {
  name                = "${var.cluster_name}-kubeadm-token-refresh"
  description         = "Trigger Lambda to refresh Kubeadm token for ${var.cluster_name}"
  schedule_expression = "rate(20 hours)" # Kubeadm tokens typically last 24h, refresh before expiry
  tags                = var.tags
}
resource "aws_cloudwatch_event_target" "token_refresh_target" {
  rule      = aws_cloudwatch_event_rule.token_refresh_rule.name
  target_id = "${var.cluster_name}TokenRefreshLambda"
  arn       = aws_lambda_function.node_management_lambda.arn
  # Add input transformer if your lambda expects a specific event format for token refresh
}
resource "aws_lambda_permission" "eventbridge_permission" {
  statement_id  = "AllowExecutionFromEventBridge-${var.cluster_name}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.node_management_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.token_refresh_rule.arn
}

# =============================================================================
# 🔄 ASG LIFECYCLE HOOKS
# =============================================================================

resource "aws_iam_role" "asg_lifecycle_hook_role" {
  name = "${var.cluster_name}-asg-hook-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "autoscaling.amazonaws.com" }
    }]
  })
  tags = var.tags
}
resource "aws_iam_role_policy" "asg_sns_publish_policy" {
  name = "${var.cluster_name}-asg-hook-sns-policy"
  role = aws_iam_role.asg_lifecycle_hook_role.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["sns:Publish"]
      Resource  = aws_sns_topic.lifecycle_topic.arn
    }]
  })
}

resource "aws_autoscaling_lifecycle_hook" "scale_up_hook" {
  name                   = "${var.cluster_name}-scale-up"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name # Ensure ASG is created before this
  default_result         = "CONTINUE" # Or ABANDON if Lambda handles completion
  heartbeat_timeout      = var.asg_scale_up_heartbeat_timeout   # Make this a variable (e.g., 300 seconds)
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}

resource "aws_autoscaling_lifecycle_hook" "scale_down_hook" {
  name                   = "${var.cluster_name}-scale-down"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name
  default_result         = "CONTINUE" # Or ABANDON if Lambda handles completion
  heartbeat_timeout      = var.asg_scale_down_heartbeat_timeout # Make this a variable (e.g., 300 seconds)
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}


# =============================================================================
# HELPER/TRIGGER RESOURCES (Review for necessity and logic)
# =============================================================================

# Worker script hash - ensure worker_user_data.sh.tpl exists in ./scripts/
resource "terraform_data" "worker_script_hash_trigger" {
  input = {
    # Include the filesha256 as one key in the map
    script_content_hash                = filesha256("${path.module}/scripts/worker_user_data.sh.tpl")

    # Add all other key-value pairs that were in your 'triggers' block
    cluster_name                       = local.cluster_name
    region                             = var.region
    join_command_latest_secret_name    = aws_secretsmanager_secret.kubernetes_join_command_latest.name
    control_plane_private_ip           = aws_instance.control_plane.private_ip # Ensure this is defined before being referenced
    s3_worker_logs_bucket              = aws_s3_bucket.worker_logs.id
    worker_asg_name                    = local.worker_asg_name
    k8s_package_version                = local.k8s_package_version
    ssh_public_key_content             = local.worker_template_vars.SSH_PUBLIC_KEY_CONTENT # Ensure local.worker_template_vars.SSH_PUBLIC_KEY_CONTENT is valid
    rebuild_trigger                    = var.rebuild_workers ? timestamp() : "disabled"
    # Add any other variables from your original 'triggers' map
  }
}


# Force ASG update: This terraform_data resource itself doesn't "force" an update.
# Updates to ASG are typically driven by changes in its launch_template or other direct properties.
# If the goal is to roll instances when the user_data content (derived from template) changes,
# you would usually taint the launch template or ASG, or rely on the launch template versioning.
# This resource seems to try and create a dependency.
# Removing the `force_asg_update` resource as its mechanism is unclear and often better handled by
# either a new version of the launch template (if user_data changes in it) or specific ASG update mechanisms.
# If you want to force an ASG rolling update, consider instance_refresh or other AWS tools.


# The `cluster_health_assessment` local-exec is for observability or manual decision making.
# It writes to /tmp files, which Terraform doesn't use directly.
# Its $ escaping should follow the single-$ for shell pattern.
resource "terraform_data" "cluster_health_assessment" {
  depends_on = [
    aws_instance.control_plane,
    null_resource.update_join_command # Wait for join command setup to complete
  ]
  input = {
    control_plane_id = aws_instance.control_plane.id
    asg_name         = local.worker_asg_name
    script_version   = "v6-tls-fix-applied"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      #!/bin/bash
      # Removed set -e to allow graceful error handling during initial setup
      
      # Style Definitions
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      YELLOW='\033[0;33m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      CYAN='\033[0;36m'
      RED='\033[0;31m'
      WHITE='\033[0;37m'

      # Helper Functions for logging
      log_header() { echo -e "\n$${BOLD}$${PURPLE}===== $1 =====$${RESET}"; }
      log_subheader() { echo -e "\n$${BOLD}$${CYAN}--- $1 ---$${RESET}"; }
      log_step() { echo -e "$${BLUE}▶ $1$${RESET}"; }
      log_success() { echo -e "$${GREEN}✅ $1$${RESET}"; }
      log_warning() { echo -e "$${YELLOW}⚠️ $1$${RESET}"; }
      log_error() { echo -e "$${RED}❌ $1$${RESET}"; }
      log_info() { echo -e "💡 $${CYAN}$1$${RESET}"; }
      log_progress() { echo -e "$${YELLOW}⏳ $1...$${RESET}"; }
      log_cmd_output() { echo -e "$${WHITE}$1$${RESET}"; }
      
      log_header "🔍 Assessing cluster health (non-blocking)"

      # Default to no cleanup needed
      # These temp files are local to where Terraform runs, consider if this is the desired outcome
      TMP_CLEANUP_NEEDED_FILE="/tmp/${local.cluster_name}_asg_cleanup_needed.txt"
      TMP_HEALTH_STATUS_FILE="/tmp/${local.cluster_name}_cluster_health_status.txt"
      echo "false" > "$TMP_CLEANUP_NEEDED_FILE"
      echo "healthy" > "$TMP_HEALTH_STATUS_FILE"

      # Terraform interpolations for AWS CLI parameters
      CONTROL_PLANE_PUBLIC_IP_ADDR="${aws_instance.control_plane.public_ip}" # TF interpolation
      CONTROL_PLANE_INSTANCE_ID="${aws_instance.control_plane.id}"         # TF interpolation
      AWS_CLI_REGION="${var.region}"                                       # TF interpolation
      TARGET_ASG_NAME="${local.worker_asg_name}"                           # TF interpolation

      log_subheader "📊 Environment Information"
      # Shell variables derived from TF interpolations
      log_info "Control Plane IP: $${BOLD}$CONTROL_PLANE_PUBLIC_IP_ADDR$${RESET}"
      log_info "Control Plane ID: $${BOLD}$CONTROL_PLANE_INSTANCE_ID$${RESET}"
      log_info "Target ASG Name: $${BOLD}$TARGET_ASG_NAME$${RESET}"

      if ! command -v kubectl &> /dev/null; then
        log_warning "kubectl command could not be found. Health assessment will be skipped."
        echo "unknown_kubectl_unavailable" > "$TMP_HEALTH_STATUS_FILE"
        log_subheader "📊 Health Assessment Results (kubectl unavailable)"
        log_info "Cleanup needed: $(cat $TMP_CLEANUP_NEEDED_FILE)"
        log_info "Health status: $(cat $TMP_HEALTH_STATUS_FILE)"
        exit 0 # Exit gracefully as we can't perform kubectl checks
      fi

      log_subheader "🔐 Retrieving kubeconfig"
      log_step "Attempting to retrieve kubeconfig via AWS Secrets Manager"
      
      # Try to get kubeconfig from Secrets Manager as the primary method
      KUBECONFIG_SECRET_NAME="${aws_secretsmanager_secret.cluster_kubeconfig.name}"
      KUBECONFIG_CONTENT=$(aws secretsmanager get-secret-value \
        --secret-id "$KUBECONFIG_SECRET_NAME" \
        --region "$AWS_CLI_REGION" \
        --query SecretString --output text 2>/dev/null || echo "")
      
      if [[ -n "$KUBECONFIG_CONTENT" ]] && echo "$KUBECONFIG_CONTENT" | grep -q "apiVersion"; then
        log_success "Got valid kubeconfig from Secrets Manager. Creating temporary kubeconfig for health check."
        echo "$KUBECONFIG_CONTENT" > "/tmp/${local.cluster_name}_health_kubeconfig.yaml"
        chmod 600 "/tmp/${local.cluster_name}_health_kubeconfig.yaml"
        export KUBECONFIG="/tmp/${local.cluster_name}_health_kubeconfig.yaml"
      else
        log_warning "Failed to get valid kubeconfig from Secrets Manager."
        log_info "This may be expected during initial cluster setup."
        log_info "The kubeconfig secret might not be populated yet by the control plane."
        echo "unknown_kubeconfig_unavailable" > "$TMP_HEALTH_STATUS_FILE"
        
        log_subheader "📊 Health Assessment Results (kubeconfig unavailable)"
        log_info "Cleanup needed: $(cat $TMP_CLEANUP_NEEDED_FILE)"
        log_info "Health status: $(cat $TMP_HEALTH_STATUS_FILE)"
        log_info "Note: This is non-blocking and expected during initial cluster setup"
        exit 0 # Exit gracefully without failing the deployment
      fi

      # Proceed with kubectl checks if KUBECONFIG is now set and working
      if kubectl --insecure-skip-tls-verify get nodes >/dev/null 2>&1; then
        log_subheader "📋 Cluster accessible via kubectl, checking node health"

        TOTAL_NODES=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | wc -l || echo "0")
        READY_NODES=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "0")
        NOTREADY_NODES=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -c " NotReady " || echo "0")
        WORKER_NODES=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -Ev "(control-plane|master)" | wc -l || echo "0") # Exclude common CP names/roles
        READY_WORKERS=$(kubectl --insecure-skip-tls-verify get nodes --no-headers 2>/dev/null | grep -Ev "(control-plane|master)" | grep -c " Ready " || echo "0")

        log_info "Total nodes: $${BOLD}$TOTAL_NODES$${RESET}"
        log_info "Ready nodes: $${BOLD}$READY_NODES$${RESET}"
        log_info "NotReady nodes: $${BOLD}$NOTREADY_NODES$${RESET}"
        log_info "Worker nodes: $${BOLD}$WORKER_NODES$${RESET}"
        log_info "Ready workers: $${BOLD}$READY_WORKERS$${RESET}"

        ASG_DESIRED_CAPACITY=$(aws autoscaling describe-auto-scaling-groups \
          --region "$AWS_CLI_REGION" \
          --auto-scaling-group-names "$TARGET_ASG_NAME" \
          --query "AutoScalingGroups[0].DesiredCapacity" \
          --output text 2>/dev/null || echo "0")

        log_info "ASG desired capacity: $${BOLD}$ASG_DESIRED_CAPACITY$${RESET}"

        CLEANUP_FLAG=false
        CURRENT_HEALTH_STATUS="healthy"

        # More lenient thresholds for initial setup
        if [[ "$NOTREADY_NODES" -gt 3 ]]; then # Allow more not ready nodes during startup
          log_warning "Warning: $NOTREADY_NODES NotReady nodes detected (allowed during startup)."
          CLEANUP_FLAG=true
          CURRENT_HEALTH_STATUS="too_many_notready_nodes"
        fi

        if [[ "$READY_WORKERS" -eq 0 ]] && [[ "$ASG_DESIRED_CAPACITY" -gt 0 ]] && [[ "$TOTAL_NODES" -gt 1 ]]; then
          log_warning "Warning: No Ready workers, but ASG wants $ASG_DESIRED_CAPACITY and cluster has nodes."
          CLEANUP_FLAG=true
          CURRENT_HEALTH_STATUS="no_ready_workers_despite_asg_demand"
        fi

        WORKER_NODE_DEFICIT=$((ASG_DESIRED_CAPACITY - READY_WORKERS))
        if [[ "$WORKER_NODE_DEFICIT" -gt 2 ]] && [[ "$ASG_DESIRED_CAPACITY" -gt 0 ]]; then # Allow larger deficit during startup
          log_warning "Warning: Worker deficit is $WORKER_NODE_DEFICIT (ASG desires $ASG_DESIRED_CAPACITY, $READY_WORKERS ready)."
          CLEANUP_FLAG=true
          CURRENT_HEALTH_STATUS="significant_worker_deficit"
        fi

        if [[ "$CLEANUP_FLAG" == "true" ]]; then
          echo "true" > "$TMP_CLEANUP_NEEDED_FILE"
          echo "$CURRENT_HEALTH_STATUS" > "$TMP_HEALTH_STATUS_FILE"
          log_warning "OBSERVATION: ASG cleanup might be beneficial later. Reason: $${BOLD}$CURRENT_HEALTH_STATUS$${RESET}"
        else
          echo "false" > "$TMP_CLEANUP_NEEDED_FILE"
          echo "healthy" > "$TMP_HEALTH_STATUS_FILE"
          log_success "OBSERVATION: Cluster appears healthy, no ASG cleanup needed."
        fi
      else
        log_warning "Cannot connect to Kubernetes API using current KUBECONFIG."
        log_info "This may be expected during initial cluster setup."
        echo "api_unreachable_during_setup" > "$TMP_HEALTH_STATUS_FILE"
        echo "false" > "$TMP_CLEANUP_NEEDED_FILE"  # Don't trigger cleanup during initial setup
      fi

      # Cleanup temporary kubeconfig if created
      if [[ -f "/tmp/${local.cluster_name}_health_kubeconfig.yaml" ]]; then
        rm -f "/tmp/${local.cluster_name}_health_kubeconfig.yaml"
      fi

      log_subheader "📊 Health Assessment Results (non-blocking)"
      log_info "Cleanup needed flag: $${BOLD}$(cat $TMP_CLEANUP_NEEDED_FILE)$${RESET}"
      log_info "Health status detail: $${BOLD}$(cat $TMP_HEALTH_STATUS_FILE)$${RESET}"
      log_info "Note: This assessment is informational and doesn't block deployment"
    EOT
  }
}

# Worker progress reporter (simple echo, looks fine)
resource "terraform_data" "worker_progress_reporter" {
  depends_on = [aws_instance.control_plane]
  input = { # RENAMED from triggers
    # If the goal is to re-run on every apply after CP is up:
    timestamp = timestamp()
    # If you only want it to change when the control plane instance itself changes:
    # control_plane_id_trigger = aws_instance.control_plane.id
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      # --- Enhanced Style Definitions ---
      RESET='\033[0m'
      BOLD='\033[1m'
      GREEN='\033[0;32m'
      BLUE='\033[0;34m'
      CYAN='\033[0;36m'
      
      # Enhanced progress message with consistent styling and emojis
      echo -e "$${BOLD}$${GREEN}🚀 Step 2/4: Control Plane Ready, Configuring Worker Nodes$${RESET} $${CYAN}[Module: $${BOLD}${var.cluster_name}$${RESET}$${CYAN}]$${RESET}$${GREEN}...$${RESET}"
    EOT
  }
}

# =============================================================================
# 📤 MODULE OUTPUTS - MOVED TO outputs.tf
# =============================================================================

# Note: All outputs have been moved to outputs.tf for better organization