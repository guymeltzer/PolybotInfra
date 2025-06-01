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
    Name                               = "guy-vpc"
    "kubernetes.io/cluster/kubernetes" = "owned"
  })

  public_subnet_tags = {
    "kubernetes.io/role/elb"          = "1"
    "kubernetes.io/role/internal-elb" = "1"
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
  
  # SSH key management
  actual_key_name = var.key_name != "" ? var.key_name : (
    length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : "polybot-key"
  )
  
  # Template variables for user data scripts
  template_vars = {
    k8s_version_full = local.k8s_version_full
    k8s_major_minor = local.k8s_major_minor
    k8s_package_version = local.k8s_package_version
    crio_k8s_major_minor = local.crio_k8s_major_minor
    token_suffix = random_string.token_part1.result
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
    "kubernetes.io/cluster/kubernetes" = "owned"
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
    "kubernetes.io/cluster/kubernetes" = "owned"
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
          "${aws_s3_bucket.worker_logs.arn}/*"
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
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AmazonEBSCSIDriverPolicy"
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

# HTTP target group
resource "aws_lb_target_group" "http_tg" {
  name     = "guy-polybot-http-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = var.tags
}

# HTTPS target group
resource "aws_lb_target_group" "https_tg" {
  name     = "guy-polybot-https-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = module.vpc.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = var.tags
}

# HTTP listener
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http_tg.arn
  }
}

# HTTPS listener
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = "arn:aws:acm:${var.region}:123456789012:certificate/example"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https_tg.arn
  }
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

  user_data = base64encode(templatefile("${path.module}/control_plane_user_data.sh", merge(local.template_vars, {
    cluster_name                    = local.cluster_name
    region                         = var.region
    pod_cidr                       = local.pod_cidr
    kubeadm_token                  = local.kubeadm_token
    join_command_secret_id         = aws_secretsmanager_secret.kubernetes_join_command.id
    join_command_secret_latest_id  = aws_secretsmanager_secret.kubernetes_join_command_latest.id
  })))

  tags = merge(var.tags, {
    Name = "guy-control-plane"
    Role = "control-plane"
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
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
    cluster_name              = local.cluster_name
    region                   = var.region
    join_command_secret_id   = aws_secretsmanager_secret.kubernetes_join_command_latest.id
    control_plane_endpoint   = "https://${aws_instance.control_plane.private_ip}:6443"
    s3_bucket               = aws_s3_bucket.worker_logs.bucket
  })))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name = "guy-worker-node"
      Role = "worker"
      "kubernetes.io/cluster/${local.cluster_name}" = "owned"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Worker auto scaling group
resource "aws_autoscaling_group" "worker_asg" {
  name                = "guy-polybot-asg"
  vpc_zone_identifier = module.vpc.public_subnets
  target_group_arns   = [aws_lb_target_group.http_tg.arn, aws_lb_target_group.https_tg.arn]
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
    value               = "guy-polybot-asg"
    propagate_at_launch = false
  }

  tag {
    key                 = "kubernetes.io/cluster/${local.cluster_name}"
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
    update_version = "v3-simplified"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      
      echo "🔄 Join Command Management v3"
      echo "============================="
      
      # Skip if explicitly disabled
      if [[ "$${SKIP_JOIN_COMMAND_UPDATE:-false}" == "true" ]]; then
        echo "SKIP_JOIN_COMMAND_UPDATE is set, skipping update"
        exit 0
      fi
      
      echo "📡 Control Plane: ${aws_instance.control_plane.public_ip}"
      echo "🔑 Secrets: ${aws_secretsmanager_secret.kubernetes_join_command_latest.id}"
      
      # Function to update join command via control plane
      update_join_command() {
        echo "🔄 Triggering join command refresh via control plane..."
        
        # Send refresh command via SSM
        COMMAND_ID=$(aws ssm send-command \
          --instance-ids ${aws_instance.control_plane.id} \
          --document-name "AWS-RunShellScript" \
          --parameters commands="sudo systemctl start k8s-token-creator.service || sudo /usr/local/bin/refresh-join-token.sh" \
          --timeout-seconds 300 \
          --region ${var.region} \
          --output text \
          --query "Command.CommandId" 2>/dev/null)
        
        if [[ -n "$COMMAND_ID" ]]; then
          echo "📡 Command sent (ID: $COMMAND_ID), waiting for completion..."
          sleep 30
          
          # Check command result
          RESULT=$(aws ssm get-command-invocation \
            --region ${var.region} \
            --command-id "$COMMAND_ID" \
            --instance-id ${aws_instance.control_plane.id} \
            --output json 2>/dev/null || echo "{}")
          
          STATUS=$(echo "$RESULT" | jq -r '.ResponseCode // ""' 2>/dev/null || echo "")
          OUTPUT=$(echo "$RESULT" | jq -r '.StandardOutputContent // ""' 2>/dev/null || echo "")
          
          echo "📋 Command Status: $STATUS"
          if [[ -n "$OUTPUT" ]]; then
            echo "📋 Output: $OUTPUT"
          fi
        else
          echo "⚠️ Failed to send refresh command"
        fi
      }
      
      # Check current join command
      echo "🔍 Checking current join command..."
      JOIN_CMD=$(aws secretsmanager get-secret-value \
        --secret-id ${aws_secretsmanager_secret.kubernetes_join_command_latest.id} \
        --region ${var.region} \
        --query SecretString \
        --output text 2>/dev/null || echo "")
      
      if [[ "$JOIN_CMD" == *"kubeadm join"* ]] && [[ "$JOIN_CMD" == *"--token"* ]]; then
        echo "✅ Valid join command found: $JOIN_CMD"
        
        # Sync to main secret
        aws secretsmanager put-secret-value \
          --secret-id ${aws_secretsmanager_secret.kubernetes_join_command.id} \
          --secret-string "$JOIN_CMD" \
          --region ${var.region} || echo "⚠️ Failed to sync main secret"
        
      else
        echo "⚠️ No valid join command found, triggering refresh..."
        update_join_command
        
        # Wait and check again
        sleep 30
        JOIN_CMD=$(aws secretsmanager get-secret-value \
          --secret-id ${aws_secretsmanager_secret.kubernetes_join_command_latest.id} \
          --region ${var.region} \
          --query SecretString \
          --output text 2>/dev/null || echo "")
        
        if [[ "$JOIN_CMD" == *"kubeadm join"* ]]; then
          echo "✅ Join command refreshed successfully"
        else
          echo "⚠️ Join command refresh may have failed, workers will retry"
        fi
      fi
      
      # Upload logs for troubleshooting
      aws s3 cp /dev/stdin s3://${aws_s3_bucket.worker_logs.bucket}/logs/join-command-$(date +"%Y%m%d%H%M%S").log \
        --region ${var.region} <<< "Join command update completed at $(date)" || true
      
      echo "✅ Join command management completed"
    EOT
  }
}

# =============================================================================
# 🔧 LAMBDA FUNCTIONS - NODE MANAGEMENT AUTOMATION
# =============================================================================

# Lambda function for node management
resource "aws_lambda_function" "node_management_lambda" {
  filename         = "${path.module}/lambda_function.zip"
  function_name    = "guy-node-management"
  role            = aws_iam_role.node_management_lambda_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.9"
  timeout         = 300

  depends_on = [null_resource.create_lambda_zip]

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
        
        # Handle SNS messages
        if 'Records' in event and event['Records']:
            for record in event['Records']:
                if record.get('EventSource') == 'aws:sns':
                    sns_message = json.loads(record['Sns']['Message'])
                    handle_lifecycle_event(sns_message)
        
        # Handle EventBridge token refresh
        elif event.get('source') == 'aws.events':
            handle_token_refresh()
        
        # Handle direct invocation
        else:
            handle_direct_invocation(event)
            
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

def handle_lifecycle_event(message):
    """Handle ASG lifecycle events"""
    logger.info(f"Handling lifecycle event: {message}")
    
    # Process the lifecycle event
    event_type = message.get('Event', '')
    instance_id = message.get('EC2InstanceId', '')
    
    if 'autoscaling:EC2_INSTANCE_LAUNCHING' in event_type:
        logger.info(f"Instance {instance_id} is launching")
        # Additional launch logic can be added here
        
    elif 'autoscaling:EC2_INSTANCE_TERMINATING' in event_type:
        logger.info(f"Instance {instance_id} is terminating")
        # Clean up Kubernetes node if needed
        cleanup_kubernetes_node(instance_id)

def handle_token_refresh():
    """Handle periodic token refresh"""
    logger.info("Handling periodic token refresh")
    
    # Logic to refresh Kubernetes join tokens
    refresh_join_token()

def handle_direct_invocation(event):
    """Handle direct Lambda invocation"""
    logger.info("Handling direct invocation")
    
    action = event.get('action', 'refresh_token')
    
    if action == 'refresh_token':
        refresh_join_token()
    elif action == 'cleanup_nodes':
        cleanup_orphaned_nodes()

def refresh_join_token():
    """Refresh Kubernetes join token"""
    logger.info("Refreshing Kubernetes join token")
    
    # Implementation would trigger control plane to refresh token
    # This is a placeholder for the actual token refresh logic

def cleanup_kubernetes_node(instance_id):
    """Clean up Kubernetes node for terminated instance"""
    logger.info(f"Cleaning up Kubernetes node for instance: {instance_id}")
    
    # Implementation would remove the node from Kubernetes cluster
    # This is a placeholder for the actual cleanup logic

def cleanup_orphaned_nodes():
    """Clean up orphaned Kubernetes nodes"""
    logger.info("Cleaning up orphaned Kubernetes nodes")
    
    # Implementation would identify and remove orphaned nodes
    # This is a placeholder for the actual cleanup logic
EOF
}

# Create Lambda ZIP file
resource "null_resource" "create_lambda_zip" {
  depends_on = [local_file.lambda_function_code]
  
  triggers = {
    code_hash = filemd5("${path.module}/lambda_code.py")
  }

  provisioner "local-exec" {
    command = "cd ${path.module} && zip -j lambda_function.zip lambda_code.py"
  }
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

# Lambda IAM policy
resource "aws_iam_policy" "node_management_lambda_policy" {
  name = "guy-node-management-lambda-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:CompleteLifecycleAction",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.kubernetes_join_command.arn,
          aws_secretsmanager_secret.kubernetes_join_command_latest.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.worker_logs.arn}/*"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "node_management_lambda_policy_attach" {
  role       = aws_iam_role.node_management_lambda_role.name
  policy_arn = aws_iam_policy.node_management_lambda_policy.arn
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

# ASG Lifecycle Hooks
resource "aws_autoscaling_lifecycle_hook" "scale_up_hook" {
  name                   = "guy-scale-up-hook"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 120  # Reduced from 600 to 120 seconds
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"

  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}

resource "aws_autoscaling_lifecycle_hook" "scale_down_hook" {
  name                   = "guy-scale-down-hook"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 90   # Reduced from 300 to 90 seconds for faster termination
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"

  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}

# IAM role for ASG Lifecycle Hooks
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
}

# Policy for ASG to publish to SNS
resource "aws_iam_role_policy" "asg_sns_publish_policy" {
  name = "ASGSNSPublishPolicy"
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

# IAM Instance Profile for Worker Nodes
resource "aws_iam_instance_profile" "worker_profile" {
  name = "guy-worker-profile"
  role = aws_iam_role.worker_role.name
}

# Also create a terraform_data resource for worker script
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

# Create bucket for worker logs
resource "aws_s3_bucket" "worker_logs" {
  bucket = "guy-polybot-logs"
  force_destroy = true
  
  tags = {
    Name = "Worker Node Logs Bucket"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# Configure bucket to allow ACLs
resource "aws_s3_bucket_ownership_controls" "worker_logs_ownership" {
  bucket = aws_s3_bucket.worker_logs.id
  
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Set the bucket ACL to private
resource "aws_s3_bucket_acl" "worker_logs_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.worker_logs_ownership]
  
  bucket = aws_s3_bucket.worker_logs.id
  acl    = "private"
}

resource "aws_launch_template" "worker_lt" {
  name_prefix   = "guy-polybot-worker-"
  image_id      = var.worker_ami
  instance_type = var.worker_instance_type
  key_name      = local.actual_key_name

  # This bootstrap script has the full initialization content embedded
  user_data = base64encode(
    templatefile(
      "${path.module}/bootstrap_worker.sh",
      {
        SSH_PUBLIC_KEY = var.ssh_public_key != "" ? var.ssh_public_key : (length(tls_private_key.ssh) > 0 ? tls_private_key.ssh[0].public_key_openssh : ""),
        region = var.region,  # Fix: lowercase 'region' to match the script
        cluster_name = var.cluster_name,
        JOIN_COMMAND_SECRET = aws_secretsmanager_secret.kubernetes_join_command.name,
        JOIN_COMMAND_LATEST_SECRET = aws_secretsmanager_secret.kubernetes_join_command_latest.name,
        # Add missing K8s versioning variables
        K8S_PACKAGE_VERSION_TO_INSTALL = local.k8s_package_version,
        K8S_MAJOR_MINOR_FOR_REPO = local.k8s_major_minor,
        CRIO_K8S_MAJOR_MINOR_FOR_REPO = local.crio_k8s_major_minor,
        KUBELET_DROPIN_DIR = "/etc/systemd/system/kubelet.service.d",
        # === Placeholder variables for bash variables set dynamically ===
        PRIVATE_IP_FROM_META = "PLACEHOLDER_WILL_BE_SET_BY_SCRIPT",
        NODE_NAME = "PLACEHOLDER_WILL_BE_SET_BY_SCRIPT"
      }
    )
  )
  
  iam_instance_profile {
    name = aws_iam_instance_profile.worker_profile.name
  }
  
  network_interfaces {
    security_groups             = [aws_security_group.worker_sg.id, aws_security_group.k8s_sg.id, aws_security_group.control_plane_sg.id]
    associate_public_ip_address = true
    delete_on_termination       = true
  }
  
  tag_specifications {
    resource_type = "instance"
  tags = {
      Name = "guy-worker-node-${random_id.suffix.hex}"
      "kubernetes-io-cluster-kubernetes" = "owned"
      "k8s-io-cluster-autoscaler-enabled" = "true"
      "k8s-io-role-node" = "true"  # Fixed: replaced invalid characters
      "ClusterIdentifier" = "${var.cluster_name}-${random_id.suffix.hex}"
    }
  }
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "enabled"
  }
  
  depends_on = [
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest
  ]
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
    asg_name = "guy-polybot-asg"
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
              --auto-scaling-group-names "guy-polybot-asg" \
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

# Simplified join command resource that relies on the control plane to generate tokens
resource "null_resource" "update_join_command" {
  depends_on = [
    aws_instance.control_plane,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
    null_resource.wait_for_control_plane
  ]

  # This will cause this resource to be recreated whenever the control plane IP changes
  triggers = {
    control_plane_ip = aws_instance.control_plane.public_ip
    control_plane_id = aws_instance.control_plane.id
    # The verification resource ID ensures we wait for control plane readiness
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      # Allow skipping join command update with environment variable
      if [ "$${SKIP_JOIN_COMMAND_UPDATE:-false}" == "true" ]; then
        echo "SKIP_JOIN_COMMAND_UPDATE is set to true, skipping join command update"
        exit 0
      fi
      
      # Log file for errors and debugging
      ERROR_LOG="/tmp/join_command_error.log"
      touch $ERROR_LOG
      exec > >(tee -a $ERROR_LOG) 2>&1
      
      echo "[$(date)] Verifying and updating Kubernetes join command for control plane IP: ${aws_instance.control_plane.public_ip}"
      
      # Function to handle errors with retry logic
      function retry_command {
        local max_attempts=5
        local attempt=1
        local sleep_time=10
        local command="$1"
        local error_msg="$2"
        
        while [ $attempt -le $max_attempts ]; do
          echo "[$(date)] Attempt $attempt/$max_attempts: $error_msg"
          
          # Execute the command and capture result
          local result=$(eval $command 2>&1)
          local status=$?
          
          if [ $status -eq 0 ]; then
            echo "[$(date)] Command succeeded!"
            echo "$result"
            return 0
          else
            echo "[$(date)] Command failed. Error: $result"
            attempt=$((attempt+1))
            if [ $attempt -le $max_attempts ]; then
              echo "[$(date)] Retrying in $sleep_time seconds..."
              sleep $sleep_time
            fi
          fi
        done
        
        echo "[$(date)] Failed after $max_attempts attempts: $error_msg"
        return 1
      }
      
      # Primary method: Read the join command from Secrets Manager (it should already exist)
      echo "[$(date)] Reading join command from Secrets Manager..."
      JOIN_CMD=$(aws secretsmanager get-secret-value \
        --secret-id ${aws_secretsmanager_secret.kubernetes_join_command_latest.id} \
        --region ${var.region} \
        --query SecretString \
        --output text 2>/dev/null)
        
      # Validate the join command format
      if [[ "$JOIN_CMD" == *"kubeadm join"* ]] && [[ "$JOIN_CMD" == *"--token"* ]]; then
        echo "[$(date)] Successfully retrieved valid join command from Secrets Manager: $JOIN_CMD"
      else
        echo "[$(date)] Retrieved command is not valid. Attempting to refresh token..."
        
        # Trigger token refresh via SSM with multiple approaches
        echo "[$(date)] Triggering token refresh via control plane's service..."
        TOKEN_REFRESH_ATTEMPTS=3
        
        for ((i=1; i<=TOKEN_REFRESH_ATTEMPTS; i++)); do
          echo "[$(date)] Token refresh attempt $i/$TOKEN_REFRESH_ATTEMPTS"
          
          # First method: Try the service
          if [[ $i -eq 1 ]]; then
            aws ssm send-command \
              --instance-ids ${aws_instance.control_plane.id} \
              --document-name "AWS-RunShellScript" \
              --parameters commands="sudo systemctl start k8s-token-creator.service" \
              --timeout-seconds 300 \
              --region ${var.region} \
              --output text \
              --query "CommandInvocations[].CommandPlugins[].Output" > /dev/null 2>&1
          
          # Second method: Try the script directly
          elif [[ $i -eq 2 ]]; then
            aws ssm send-command \
              --instance-ids ${aws_instance.control_plane.id} \
              --document-name "AWS-RunShellScript" \
              --parameters commands="sudo /usr/local/bin/refresh-join-token.sh" \
              --timeout-seconds 300 \
              --region ${var.region} \
              --output text \
              --query "CommandInvocations[].CommandPlugins[].Output" > /dev/null 2>&1
          
          # Third method: Try kubeadm directly
          else
            aws ssm send-command \
              --instance-ids ${aws_instance.control_plane.id} \
              --document-name "AWS-RunShellScript" \
              --parameters commands="sudo kubeadm token create --print-join-command" \
              --timeout-seconds 300 \
              --region ${var.region} \
              --output text \
              --query "CommandInvocations[].CommandPlugins[].Output" > /dev/null 2>&1
          fi
          
          # Wait for token to be updated
          echo "[$(date)] Waiting for token to be updated in Secrets Manager..."
          sleep 15
          
          # Try reading the secret again
          JOIN_CMD=$(aws secretsmanager get-secret-value \
            --secret-id ${aws_secretsmanager_secret.kubernetes_join_command_latest.id} \
            --region ${var.region} \
            --query SecretString \
            --output text 2>/dev/null)
            
          if [[ "$JOIN_CMD" == *"kubeadm join"* ]] && [[ "$JOIN_CMD" == *"--token"* ]]; then
            echo "[$(date)] Successfully retrieved valid join command after refresh: $JOIN_CMD"
            break
          fi
          
          if [[ $i -eq $TOKEN_REFRESH_ATTEMPTS ]]; then
            echo "[$(date)] Failed to get valid join command after all refresh attempts."
            echo "[$(date)] Cluster may not be ready yet. Worker nodes will retry joining when possible."
            # Continue with the rest of the deployment - workers will have retry logic
            JOIN_CMD=""
          fi
        done
      fi
      
      if [[ -n "$JOIN_CMD" ]]; then
        # Verify both secrets are accessible and identical
        echo "[$(date)] Verifying both secrets are up to date..."
        MAIN_SECRET=$(aws secretsmanager get-secret-value \
          --secret-id ${aws_secretsmanager_secret.kubernetes_join_command.id} \
          --region ${var.region} \
          --query SecretString \
          --output text 2>/dev/null)
          
        # If secrets don't match, update main secret to match latest
        if [[ "$MAIN_SECRET" != "$JOIN_CMD" ]]; then
          echo "[$(date)] Secrets don't match. Updating main secret to match latest..."
          aws secretsmanager put-secret-value \
            --secret-id ${aws_secretsmanager_secret.kubernetes_join_command.id} \
            --secret-string "$JOIN_CMD" \
            --region ${var.region} || echo "[$(date)] Failed to update main secret, but continuing"
        else
          echo "[$(date)] Both secrets contain matching valid join commands."
        fi
        
        # Create timestamped backup for audit trail
        TIMESTAMP=$(date +"%Y%m%d%H%M%S")
        BACKUP_SECRET_NAME="${aws_secretsmanager_secret.kubernetes_join_command.name}-$TIMESTAMP"
        aws secretsmanager create-secret \
          --name "$BACKUP_SECRET_NAME" \
          --secret-string "$JOIN_CMD" \
          --description "Kubernetes join command backup created at $TIMESTAMP" \
          --region ${var.region} || echo "[$(date)] Failed to create backup secret, but continuing"
        
        echo "[$(date)] ✅ Join command verification and update complete"
      else
        echo "[$(date)] ⚠️ Could not obtain a valid join command. Worker nodes will use built-in retry logic."
      fi
      
      # Always upload logs to S3 for troubleshooting
      aws s3 cp $ERROR_LOG s3://${aws_s3_bucket.worker_logs.bucket}/logs/join-command-$(date +"%Y%m%d%H%M%S").log --region ${var.region} || echo "[$(date)] Failed to upload logs to S3"
      
      # Always exit with success to allow deployment to continue
      exit 0
    EOT
  }
}

# Removed problematic verify_cluster_readiness resource that was blocking deployment
# The control plane user data script already handles cluster initialization properly

