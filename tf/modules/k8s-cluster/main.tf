# Ensure log directories exist before any logging resources
resource "null_resource" "create_log_directories" {
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      mkdir -p ../logs
      mkdir -p ../logs/cluster_state
      mkdir -p ../logs/final_state
      mkdir -p ../logs/kubernetes_state
    EOT
  }
}

#DEBUGGABLE: VPC creation debug hook
resource "null_resource" "vpc_debug_pre" {
  triggers = {
    vpc_config = jsonencode({
      vpc_cidr = "10.0.0.0/16"
      region   = var.region
      timestamp = timestamp()
    })
  }
  depends_on = [null_resource.create_log_directories]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"vpc_creation", "status":"start", "region":"${var.region}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Validate region and availability zones
      aws ec2 describe-availability-zones --region "${var.region}" > ../logs/cluster_state/az_validation_${timestamp()}.json 2>&1 || {
        echo '{"stage":"az_validation", "status":"error", "region":"${var.region}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      }
    EOT
    
    on_failure = continue
  }
}

# Fix 1: Update VPC tags with AWS cloud provider integration requirements
module "vpc" {
  depends_on = [null_resource.vpc_debug_pre]
  
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

  map_public_ip_on_launch = true  # Enable auto-assignment of public IPs for public subnets

  tags = {
    Name                                        = "guy-vpc"
    "kubernetes.io-cluster-${var.cluster_name}" = "owned"
    "kubernetes.io-role-elb"                    = "1"
    "DebugEnabled"                              = "true"
  }

  public_subnet_tags = {
    "kubernetes.io-role-elb"                    = "1"
    "kubernetes.io-cluster-${var.cluster_name}" = "owned"
    "kubernetes.io-role-internal-elb"           = ""
  }

  private_subnet_tags = {
    "kubernetes.io-role-internal-elb"           = "1"
    "kubernetes.io-cluster-${var.cluster_name}" = "owned"
  }
}

#DEBUGGABLE: VPC creation validation hook
resource "null_resource" "vpc_debug_post" {
  depends_on = [
    module.vpc,
    null_resource.create_log_directories
  ]
  
  triggers = {
    vpc_id = module.vpc.vpc_id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"vpc_creation", "status":"complete", "vpc_id":"${module.vpc.vpc_id}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Capture VPC details for debugging
      aws ec2 describe-vpcs --vpc-ids "${module.vpc.vpc_id}" --region "${var.region}" > ../logs/cluster_state/vpc_details_${timestamp()}.json 2>&1
      aws ec2 describe-subnets --filters "Name=vpc-id,Values=${module.vpc.vpc_id}" --region "${var.region}" > ../logs/cluster_state/subnet_details_${timestamp()}.json 2>&1
      
      echo '{"stage":"vpc_validation", "status":"complete", "public_subnets":${length(module.vpc.public_subnets)}, "private_subnets":${length(module.vpc.private_subnets)}, "time":"${timestamp()}"}' >> ../logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

# Generate a random suffix for unique resource naming
resource "random_id" "suffix" {
  byte_length = 4
  
  keepers = {
    cluster_name = var.cluster_name
  }
}

# Generate a random token for kubeadm
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

locals {
  kubeadm_token_part1 = random_string.token_part1.result
  kubeadm_token_part2 = random_string.token_part2.result
  kubeadm_token       = "${local.kubeadm_token_part1}.${local.kubeadm_token_part2}"

  token_suffix_for_template = local.kubeadm_token_part1 # For control_plane_user_data.sh

  # === Centralized Kubernetes Versioning ===
  # Used by control_plane_user_data.sh and now also for bootstrap_worker.sh
  k8s_version_for_template           = "1.28.3"
  k8s_major_minor_for_template       = join(".", slice(split(".", local.k8s_version_for_template), 0, 2)) # "1.28"
  k8s_package_version_for_template   = "${local.k8s_version_for_template}-1.1" # "1.28.3-1.1"
  # CRIO versioning typically aligns with Kubernetes major.minor
  crio_k8s_major_minor_for_template  = local.k8s_major_minor_for_template # "1.28"
  # =======================================

  pod_cidr = var.pod_cidr != "" ? var.pod_cidr : "10.244.0.0/16"
  actual_key_name = var.key_name != "" ? var.key_name : (length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : "")
}


# IAM Role Policy Attachments for Control Plane
resource "aws_iam_role_policy_attachment" "control_plane_role_policy_attachment" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonRoute53FullAccess",
    "arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AWSCertificateManagerFullAccess"
  ])

  role       = aws_iam_role.control_plane_role.name
  policy_arn = each.value
}

# IAM Role Policy Attachments for Control Plane - LEGACY
resource "aws_iam_role_policy_attachment" "control_plane_role_policy_attachment_legacy" {
  #VALIDATION: This is duplicate - remove in next iteration
  for_each = toset([])  # Empty set to disable this duplicate

  role       = aws_iam_role.control_plane_role.name
  policy_arn = each.value
}

# IAM Role for Control Plane
resource "aws_iam_role" "control_plane_role" {
  name = "Guy-K8S-ControlPlane-IAM-Role"

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
}

# IAM Inline Policies for Control Plane
resource "aws_iam_role_policy" "control_plane_describe_policy" {
  name = "DescribeResourcesPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:Describe*",
          "ec2:Describe*",
          "secretsmanager:*",
          "ssm:StartSession",
          "ssm:TerminateSession",
          "ssm:ResumeSession",
          "eks:DescribeCluster"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_asg_refresh_policy" {
  name = "ASGRefreshPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:StartInstanceRefresh",
          "autoscaling:DescribeInstanceRefreshes"
        ]
        Resource = "arn:aws:autoscaling:${var.region}:*:autoScalingGroup:*:autoScalingGroupName/guy-polybot-asg"
        Condition = {
          StringEquals = {
            "autoscaling:ResourceTag/Environment" = "k8s-cluster"
          }
        }
      },
      {
        Effect = "Allow"
        Action = "autoscaling:DescribeAutoScalingGroups"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_pass_role_policy" {
  name = "PassRoleAutoScalingPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Statement1"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_ssm_secrets_policy" {
  name = "SSMSecretsManagerPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Statement1"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_autoscaling_policy" {
  name = "AutoscalingFullPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:*",
          "sns:*",
          "ec2:Describe*"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_lambda_policy" {
  name = "LambdaInvokePolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.region}:*:function:generate-join-command"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_instance_management_policy" {
  name = "InstanceManagementPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Statement1"
        Effect = "Allow"
        Action = [
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DescribeAutoScalingGroups",
          "ec2:TerminateInstances",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_run_instances_policy" {
  name = "RunInstancesPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:UpdateAutoScalingGroup",
          "ec2:DescribeLaunchTemplates"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:aws:ec2:*:*:instance/*",
          "arn:aws:ec2:*:*:launch-template/*"
        ]
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:instance-profile/Guy-K8S-Control_Plane-IAM-Role"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_cluster_autoscaler_policy" {
  name = "ClusterAutoscalerPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeScalingActivities",
          "ec2:DescribeImages",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:GetInstanceTypesFromInstanceRequirements",
          "eks:DescribeNodegroup"
        ]
        Resource = ["*"]
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup"
        ]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_loadbalancer_policy" {
  name = "LoadBalancerPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeTags",
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVolumes",
          "ec2:DescribeAvailabilityZones",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyVolume",
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeVpcs",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:AttachLoadBalancerToSubnets",
          "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateLoadBalancerPolicy",
          "elasticloadbalancing:CreateLoadBalancerListeners",
          "elasticloadbalancing:ConfigureHealthCheck",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:DeleteLoadBalancerListeners",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DetachLoadBalancerFromSubnets",
          "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
          "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancerPolicies",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
          "iam:CreateServiceLinkedRole",
          "kms:DescribeKey"
        ]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_launch_template_policy" {
  name = "LaunchTemplatePolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateLaunchTemplateVersion",
          "ec2:ModifyLaunchTemplate",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/Guy-K8S-Control_Plane-IAM-Role"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_eks_policy" {
  name = "EKSListDescribePolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "eks:ListClusters",
          "eks:DescribeCluster"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_secrets_manager_policy" {
  name = "SecretsManagerUpdatePolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:UpdateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${var.region}:*:secret:kubernetes-join-command*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "ssm:SendCommand"
        Resource = [
          "arn:aws:ssm:${var.region}::document/AWS-RunShellScript",
          "arn:aws:ec2:${var.region}:*:instance/*"
        ]
      }
    ]
  })
}

# IAM Instance Profile for Control Plane
resource "aws_iam_instance_profile" "control_plane_profile" {
  name = "Guy-K8S-ControlPlane-Profile"
  role = aws_iam_role.control_plane_role.name
}

# Create a terraform_data resource that tracks changes to the script file
resource "terraform_data" "control_plane_script_hash" {
  input = filesha256("${path.module}/control_plane_user_data.sh")
  
  # Only force rebuild on explicit rebuild flag
  triggers_replace = {
    rebuild = var.rebuild_control_plane ? timestamp() : "stable-hash-${filesha256("${path.module}/control_plane_user_data.sh")}"
  }
}

# Data source to find existing control plane instance
data "aws_instances" "existing_control_plane" {
  filter {
    name   = "tag:Name"
    values = ["guy-control-plane"]
  }
  
  filter {
    name   = "instance-state-name"
    values = ["running", "pending"]
  }
  
  depends_on = [
    module.vpc
  ]
}

# Progress reporter to show what's happening during deployment
resource "terraform_data" "deployment_progress" {
  triggers_replace = {
    # Always run at the beginning of every terraform apply
    timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      echo -e "\\033[1;34m========================================================\\033[0m"
      echo -e "\\033[1;34m     🚀 Starting Kubernetes Cluster Deployment 🚀\\033[0m"
      echo -e "\\033[1;34m========================================================\\033[0m"
      echo -e "\\033[0;32m➡️  Step 1/4: Launching Control Plane Instance...\\033[0m"
    EOT
  }
}

#DEBUGGABLE: Control plane instance creation debug hook
resource "null_resource" "control_plane_instance_debug" {
  depends_on = [
    aws_iam_instance_profile.control_plane_profile,
    aws_security_group.control_plane_sg,
    null_resource.create_log_directories
  ]
  
  triggers = {
    cp_timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"control_plane_instance_creation", "status":"start", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Validate prerequisites
      aws iam get-instance-profile --instance-profile-name control-plane-profile > ../logs/cluster_state/cp_instance_profile_${timestamp()}.json 2>&1
      aws ec2 describe-security-groups --group-ids ${aws_security_group.control_plane_sg.id} --region "${var.region}" > ../logs/cluster_state/cp_sg_${timestamp()}.json 2>&1
      
      echo '{"stage":"control_plane_prerequisites", "status":"validated", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

# Enhanced control plane instance with debug tags and comprehensive dependencies
resource "aws_instance" "control_plane" {
  depends_on = [
    null_resource.control_plane_instance_debug,
    aws_security_group.control_plane_sg,
    aws_iam_instance_profile.control_plane_profile,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
    null_resource.create_log_directories
  ]

  ami                         = var.control_plane_ami
  instance_type               = var.control_plane_instance_type
  key_name                    = local.actual_key_name
  associate_public_ip_address = true  # Add this to ensure public IP assignment
  
  iam_instance_profile   = aws_iam_instance_profile.control_plane_profile.name
  vpc_security_group_ids = [aws_security_group.control_plane_sg.id]
  subnet_id              = var.vpc_id != "" ? var.subnet_ids[0] : module.vpc.public_subnets[0]

  user_data = base64encode(templatefile("${path.module}/control_plane_user_data.sh", {
    token                        = local.kubeadm_token
    token_formatted             = local.kubeadm_token
    step                        = "control_plane_init"
    secret_name                 = aws_secretsmanager_secret.kubernetes_join_command.name
    ssh_public_key              = var.key_name != "" ? "" : tls_private_key.ssh[0].public_key_openssh
    POD_CIDR                    = "10.244.0.0/16"
    JOIN_COMMAND_SECRET         = aws_secretsmanager_secret.kubernetes_join_command.name
    JOIN_COMMAND_LATEST_SECRET  = aws_secretsmanager_secret.kubernetes_join_command_latest.name
    region                      = var.region
    TOKEN_SUFFIX                = local.token_suffix_for_template
    K8S_VERSION_FULL            = local.k8s_version_for_template
    K8S_PACKAGE_VERSION          = local.k8s_package_version_for_template
    K8S_MAJOR_MINOR              = local.k8s_major_minor_for_template
    CRIO_K8S_MAJOR_MINOR         = local.crio_k8s_major_minor_for_template
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    
    tags = {
      Name         = "guy-control-plane-root"
      DebugEnabled = "true"
    }
  }

  tags = {
    Name                                        = "guy-control-plane"
    Role                                        = "control-plane"
    "kubernetes.io-cluster-${var.cluster_name}" = "owned"
    "kubernetes.io-cluster-autoscaler-enabled"  = "true"
    "kubernetes.io-cluster-autoscaler-${var.cluster_name}" = "owned"
    "DebugEnabled"                              = "true"
    "DeploymentTime"                            = timestamp()
  }

  lifecycle {
    create_before_destroy = false
    ignore_changes = [
      user_data
    ]
  }
}

resource "null_resource" "ssh_debug" {
  depends_on = [aws_instance.control_plane, null_resource.create_log_directories]

  triggers = {
    control_plane_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"ssh_debug", "status":"start", "instance_id":"${aws_instance.control_plane.id}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log

      PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "${aws_instance.control_plane.id}" --region "${var.region}" --query "Reservations[].Instances[].PublicIpAddress" --output text)
      if [ -z "$PUBLIC_IP" ]; then
        echo '{"stage":"ssh_debug", "status":"error", "message":"No public IP assigned", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
        # Consider exiting with error if this is critical for the provisioner's purpose
        # exit 1
        exit 0 # Current behavior seems to be continue on failure
      fi
      echo '{"stage":"ssh_debug", "status":"info", "public_ip":"$PUBLIC_IP", "time":"${timestamp()}"}' >> ../logs/tf_debug.log

      # Determine local SSH key path
      LOCAL_SSH_KEY_TO_USE=""
      if [ -n "${var.key_name}" ]; then
        # An existing AWS key_name is specified, so use ssh_private_key_file_path
        if [ -n "${var.ssh_private_key_file_path}" ]; then
          # Expand tilde if present in the path
          # Using eval for robust tilde expansion
          eval ACTUAL_KEY_PATH="${var.ssh_private_key_file_path}"
          LOCAL_SSH_KEY_TO_USE="$ACTUAL_KEY_PATH"
        else
          echo '{"stage":"ssh_debug", "status":"error", "message":"var.key_name (${var.key_name}) is set, but var.ssh_private_key_file_path is not. Cannot determine local private key for SSH.", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
          # exit 1 # This is a configuration error, should ideally fail
          exit 0 # Keeping with on_failure = continue behavior
        fi
      else
        # No existing key_name, use the path to the key generated by Terraform
        LOCAL_SSH_KEY_TO_USE="${path.root}/generated-ssh-key.pem"
      fi

      if [ ! -f "$LOCAL_SSH_KEY_TO_USE" ]; then
        echo '{"stage":"ssh_debug", "status":"error", "message":"SSH private key file not found at resolved path: [$LOCAL_SSH_KEY_TO_USE]", "var_key_name":"${var.key_name}", "var_ssh_path":"${var.ssh_private_key_file_path}" ,"time":"${timestamp()}"}' >> ../logs/tf_debug.log
        # exit 1
        exit 0 # Keeping with on_failure = continue behavior
      fi

      echo '{"stage":"ssh_debug", "status":"info", "message":"Attempting SSH with key: $LOCAL_SSH_KEY_TO_USE", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$LOCAL_SSH_KEY_TO_USE" ubuntu@$PUBLIC_IP "echo SSH_OK" > /tmp/ssh_test.log 2>&1
      if grep -q "SSH_OK" /tmp/ssh_test.log; then
        echo '{"stage":"ssh_debug", "status":"success", "message":"SSH connection successful", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      else
        echo '{"stage":"ssh_debug", "status":"error", "message":"SSH connection failed. Check /tmp/ssh_test.log and ensure key permissions are correct (e.g., chmod 400).", "details":"$(cat /tmp/ssh_test.log)", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      fi
    EOT
    on_failure = continue
  }
}

# Capture control plane logs via SSM
resource "null_resource" "control_plane_ssm_debug" {
  depends_on = [aws_instance.control_plane, null_resource.create_log_directories]

  triggers = {
    control_plane_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"ssm_debug", "status":"start", "instance_id":"${aws_instance.control_plane.id}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log

      # Check SSM agent status
      SSM_STATUS=$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=${aws_instance.control_plane.id}" --region "${var.region}" --query "InstanceInformationList[0].PingStatus" --output text 2>/dev/null)
      echo '{"stage":"ssm_debug", "status":"info", "ssm_status":"$SSM_STATUS", "time":"${timestamp()}"}' >> ../logs/tf_debug.log

      # Capture cloud-init logs
      CMD_ID=$(aws ssm send-command --instance-ids "${aws_instance.control_plane.id}" --document-name "AWS-RunShellScript" --parameters 'commands=["cat /var/log/cloud-init-output.log"]' --region "${var.region}" --query "Command.CommandId" --output text 2>/dev/null)
      if [ -n "$CMD_ID" ]; then
        sleep 10
        aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "${aws_instance.control_plane.id}" --region "${var.region}" --query "CommandPlugins[].Output" --output text > ../logs/cluster_state/cloud_init_${timestamp()}.log 2>&1
        echo '{"stage":"ssm_debug", "status":"info", "message":"Captured cloud-init logs", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      fi

      # Capture kubelet logs
      CMD_ID=$(aws ssm send-command --instance-ids "${aws_instance.control_plane.id}" --document-name "AWS-RunShellScript" --parameters 'commands=["journalctl -u kubelet"]' --region "${var.region}" --query "Command.CommandId" --output text 2>/dev/null)
      if [ -n "$CMD_ID" ]; then
        sleep 10
        aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "${aws_instance.control_plane.id}" --region "${var.region}" --query "CommandPlugins[].Output" --output text > ../logs/cluster_state/kubelet_${timestamp()}.log 2>&1
        echo '{"stage":"ssm_debug", "status":"info", "message":"Captured kubelet logs", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      fi
    EOT
    on_failure = continue
  }
}

#DEBUGGABLE: Control plane initialization monitoring
resource "null_resource" "control_plane_bootstrap_debug" {
  depends_on = [
    aws_instance.control_plane,
    null_resource.create_log_directories
  ]
  
  triggers = {
    cp_instance_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      # Create log directories if they don't exist
      mkdir -p ../logs
      mkdir -p ../logs/cluster_state

      echo '{"stage":"control_plane_bootstrap", "status":"monitoring", "instance_id":"${aws_instance.control_plane.id}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Wait for instance to be running and capture detailed state
      aws ec2 wait instance-running --instance-ids "${aws_instance.control_plane.id}" --region "${var.region}" || {
        echo '{"stage":"control_plane_wait", "status":"timeout", "instance_id":"${aws_instance.control_plane.id}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      }
      
      # Capture instance details after it's running
      aws ec2 describe-instances --instance-ids "${aws_instance.control_plane.id}" --region "${var.region}" > ../logs/cluster_state/cp_running_state_${timestamp()}.json 2>&1
      
      # Monitor bootstrap process via cloud-init logs (if SSM is available)
      for i in {1..10}; do
        if aws ssm describe-instance-information --region "${var.region}" --filters "Key=InstanceIds,Values=${aws_instance.control_plane.id}" --query "InstanceInformationList[0].PingStatus" --output text 2>/dev/null | grep -q "Online"; then
          echo '{"stage":"ssm_connectivity", "status":"online", "instance_id":"${aws_instance.control_plane.id}", "attempt":"'$i'", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
          
          # Capture cloud-init status
          aws ssm send-command --region "${var.region}" --document-name "AWS-RunShellScript" \
            --instance-ids "${aws_instance.control_plane.id}" \
            --parameters 'commands=["cloud-init status"]' \
            --query "Command.CommandId" --output text > /tmp/cloud_init_check_${timestamp()}.cmd 2>/dev/null || true
          break
        else
          echo '{"stage":"ssm_connectivity", "status":"waiting", "instance_id":"${aws_instance.control_plane.id}", "attempt":"'$i'", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
          sleep 30
        fi
      done
      
      echo '{"stage":"control_plane_bootstrap", "status":"monitoring_complete", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

#DEBUGGABLE: Worker ASG creation debug hook
resource "null_resource" "worker_asg_debug" {
  depends_on = [
    aws_launch_template.worker_lt,
    null_resource.create_log_directories
  ]
  
  triggers = {
    asg_timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"worker_asg_creation", "status":"start", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Validate ASG prerequisites
      aws ec2 describe-launch-templates --launch-template-names "${aws_launch_template.worker_lt.name}" --region "${var.region}" > ../logs/cluster_state/worker_lt_${timestamp()}.json 2>&1
      
      echo '{"stage":"worker_asg_prerequisites", "status":"validated", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

resource "aws_autoscaling_group" "worker_asg" {
  name                = "guy-polybot-asg"
  max_size            = 3
  min_size            = 1
  desired_capacity    = 2
  vpc_zone_identifier = module.vpc.public_subnets
  target_group_arns   = [aws_lb_target_group.http_tg.arn, aws_lb_target_group.https_tg.arn]
  health_check_type   = "EC2"
  health_check_grace_period = 300
  default_cooldown    = 300
  
  launch_template {
    id      = aws_launch_template.worker_lt.id
    version = aws_launch_template.worker_lt.latest_version
  }

  tag {
    key                 = "k8s.io/cluster-autoscaler/enabled"
    value               = "true"
    propagate_at_launch = true
  }
  tag {
    key                 = "k8s.io/cluster-autoscaler/${var.cluster_name}"
    value               = "owned"
    propagate_at_launch = true
  }
  tag {
    key                 = "Name"
    value               = "guy-worker-node-${random_id.suffix.hex}"
    propagate_at_launch = true
  }
  tag {
    key                 = "kubernetes-io-cluster-${var.cluster_name}"
    value               = "owned"
    propagate_at_launch = true
  }
  tag {
    key                 = "k8s.io/role/node"
    value               = "true"
    propagate_at_launch = true
  }
  tag {
    key                 = "ClusterIdentifier" 
    value               = "${var.cluster_name}-${random_id.suffix.hex}"
    propagate_at_launch = true
  }
  
  depends_on = [
    null_resource.worker_asg_debug,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
    null_resource.verify_control_plane_readiness,
    null_resource.update_join_command,
  ]
  
  lifecycle {
    replace_triggered_by = [
      aws_launch_template.worker_lt.id, 
      terraform_data.worker_script_details,
    ]
    ignore_changes = [
      desired_capacity,
      launch_template[0].version 
    ]
  }

  # This is the correctly placed provisioner
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = "echo -e \"\\033[0;32m✅ Worker node Auto Scaling Group '${var.cluster_name}-worker-asg' created!\\033[0m\""
  }
}

  resource "aws_security_group" "worker_sg" {
  name        = "Guy-WorkerNodes-SG-${random_id.suffix.hex}"
  description = "Security group for Kubernetes worker nodes"
  vpc_id      = module.vpc.vpc_id

  # Allow SSH from anywhere for debugging
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow SSH access from anywhere"
  }

  # Allow HTTP traffic
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP traffic"
  }

  # Allow HTTPS traffic
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic"
  }

  # Kubelet API for control plane communication
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Kubelet API - required for control plane communication"
  }

  # Read-only Kubelet API
  ingress {
    from_port   = 10255
    to_port     = 10255
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Read-only Kubelet API"
  }

  # NodePort services range
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort services for external access"
  }

  # Kubernetes API server access for worker nodes
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kubernetes API server access"
  }

  # Allow all internal VPC traffic for cluster communication
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Allow all internal VPC traffic for cluster communication"
  }

  # Calico overlay networking (VXLAN) - required for pod-to-pod communication
  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    self        = true
    description = "Calico VXLAN overlay - required for pod networking"
  }

  # Calico BGP traffic - required for network policy
  ingress {
    from_port   = 179
    to_port     = 179
    protocol    = "tcp"
    self        = true
    description = "Calico BGP traffic - required for network policy"
  }

  # Container runtime ports (containerd/Docker)
  ingress {
    from_port   = 2376
    to_port     = 2377
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Container runtime communication"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "guy-worker-sg-${random_id.suffix.hex}"
    # Adjusted tag key to avoid invalid characters (replaced / with -)
    "kubernetes.io-cluster-${var.cluster_name}" = "owned"
    "kubernetes.io-role-node"                  = "true"
  }
}

resource "aws_iam_role" "worker_role" {
  name = "Guy-K8S-WorkerNode-Role"

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
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "worker_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",  # VALIDATION: Added for EBS dynamic volumes
    "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  ])

  role       = aws_iam_role.worker_role.name
  policy_arn = each.value
}

# Worker node inline policies
resource "aws_iam_role_policy" "worker_secrets_access_policy" {
  name = "SecretsManagerEnhancedAccess"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets",
          "secretsmanager:ListSecretVersionIds"
        ]
        Resource = "arn:aws:secretsmanager:${var.region}:*:secret:kubernetes-join-command*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_ec2_tags_policy" {
  name = "EC2TagsManagement"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_autoscaling_lifecycle_policy" {
  name = "AutoscalingLifecycleActions"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "autoscaling:CompleteLifecycleAction"
        Resource = "arn:aws:autoscaling:${var.region}:*:autoScalingGroup:*:autoScalingGroupName/guy-polybot-asg"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_cluster_autoscaler_policy" {
  name = "ClusterAutoscalerPolicy"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeScalingActivities",
          "ec2:DescribeImages",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:GetInstanceTypesFromInstanceRequirements",
          "eks:DescribeNodegroup"
        ]
        Resource = ["*"]
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup"
        ]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_ec2_ecr_policy" {
  name = "EC2andECRAccess"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_ssm_parameters_policy" {
  name = "SSMParametersAccess"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Statement1"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/k8s/worker-node-counter"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "control_plane_ssm_policy" {
  name = "SSMSecretsManager"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_storage_policy" {
  name = "S3_SQS_SecretsAccess"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "s3:*"
        Resource = [
          "${aws_s3_bucket.worker_logs.arn}",
          "${aws_s3_bucket.worker_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::guy-polybot-bucket",
          "arn:aws:s3:::guy-polybot-bucket/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = "arn:aws:sqs:${var.region}:*:guy-polybot-queue"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_cloudwatch_policy" {
  name = "CloudWatchMonitoring"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarmsForMetric",
          "cloudwatch:DescribeAlarmHistory",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricData",
          "cloudwatch:GetInsightRuleReport",
          "logs:DescribeLogGroups",
          "logs:GetLogGroupFields",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:GetQueryResults",
          "logs:GetLogEvents",
          "ec2:DescribeTags",
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "tag:GetResources"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_sns_publish_policy" {
  name = "SNSPublishPolicy"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = "arn:aws:sns:${var.region}:*:Guy-netflix-event-topic"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_lambda_invoke_policy" {
  name = "LambdaInvokePolicy"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.region}:*:function:*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_elb_policy" {
  name = "EC2TaggingAndELBPermissions"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowEC2Tagging"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DescribeTags",
          "ec2:DescribeInstances",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeRouteTables",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },
      {
        Sid = "AllowELBPermissions"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
          "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
          "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
          "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:CreateLoadBalancerListeners",
          "elasticloadbalancing:CreateLoadBalancerPolicy",
          "elasticloadbalancing:DeleteLoadBalancerListeners",
          "elasticloadbalancing:DeleteLoadBalancerPolicy",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:RegisterTargets"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "worker_debug_policy" {
  name = "WorkerNodeDebugAccess"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:CreateTags",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ssm:UpdateInstanceInformation",
          "ssm:ListInstanceAssociations",
          "ssm:DescribeInstanceProperties",
          "ssm:DescribeDocumentParameters"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lb" "polybot_alb" {
  name               = "guy-polybot-lg"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = module.vpc.public_subnets

  # Critical: Enable deletion protection to prevent accidental removal
  enable_deletion_protection = false

  tags = {
    Name = "guy-polybot-lg"
    # Critical: AWS cloud provider integration tags
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    "kubernetes.io/role/elb" = "1"
    # Required for AWS Load Balancer Controller
    "elbv2.k8s.aws/cluster" = var.cluster_name
  }
}

resource "aws_lb_target_group" "http_tg" {
  name        = "guy-polybot-http-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance"
  deregistration_delay = 30
}

resource "aws_lb_target_group" "https_tg" {
  name        = "guy-polybot-https-tg"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance"
  deregistration_delay = 30
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http_tg.arn
  }
}

# Commented out HTTPS listener until proper certificate is available
/* 
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.polybot_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https_tg.arn
  }
}
*/

resource "aws_security_group" "alb_sg" {
  name        = "guy-LB-SG"
  description = "Security group for ALB"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP traffic"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "guy-alb-sg"
    # Critical: AWS cloud provider integration tags
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    "kubernetes.io/role/elb" = "1"
  }
}

# Commented out until proper domain and route53 setup
/*
resource "aws_acm_certificate" "polybot_cert" {
  domain_name       = "guy-polybot-lg.devops-int-college.com"
  validation_method = "DNS"

  tags = {
    Name = "polybot-cert"
  }
}

resource "aws_route53_record" "cert_validation" {
  zone_id = var.route53_zone_id
  name    = tolist(aws_acm_certificate.polybot_cert.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.polybot_cert.domain_validation_options)[0].resource_record_type
  ttl     = 300
  records = [tolist(aws_acm_certificate.polybot_cert.domain_validation_options)[0].resource_record_value]
  allow_overwrite = true
}
*/

resource "aws_iam_role_policy" "control_plane_inline_policy" {
  name   = "control-plane-inline-policy"
  role   = aws_iam_role.control_plane_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:BatchGetImage",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeTags",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
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
          "ssm:DescribeAssociation",
          "ssm:GetDeployablePatchSnapshotForInstance",
          "ssm:GetDocument",
          "ssm:DescribeDocument",
          "ssm:GetManifest",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:ListAssociations",
          "ssm:ListInstanceAssociations",
          "ssm:PutInventory",
          "ssm:PutComplianceItems",
          "ssm:PutConfigurePackageResult",
          "ssm:UpdateAssociationStatus",
          "ssm:UpdateInstanceAssociationStatus",
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages",
          "ec2messages:SendReply"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

# Generate a key pair for SSH access if none is provided or if the provided one doesn't exist
resource "tls_private_key" "ssh" {
  count     = var.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Save the private key locally
resource "local_file" "private_key" {
  count           = var.key_name == "" ? 1 : 0
  content         = tls_private_key.ssh[0].private_key_pem
  filename        = "${path.root}/generated-ssh-key.pem"
  file_permission = "0400"
}

# Create the key pair in AWS
resource "aws_key_pair" "generated_key" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "k8s-cluster-auto-key"
  public_key = tls_private_key.ssh[0].public_key_openssh
}

# Final progress reporter
resource "terraform_data" "completion_progress" {
  depends_on = [
    aws_autoscaling_group.worker_asg,
    aws_instance.control_plane
  ]
  
  triggers_replace = {
    timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      # ... (initial echo statements) ...
      CONTROL_PLANE_IP="${aws_instance.control_plane.public_ip}"

      # Determine local SSH key path for kubectl
      LOCAL_SSH_KEY_FOR_KUBECTL=""
      if [ -n "${var.key_name}" ]; then
        if [ -n "${var.ssh_private_key_file_path}" ]; then
          eval ACTUAL_KEY_PATH_KUBECTL="${var.ssh_private_key_file_path}"
          LOCAL_SSH_KEY_FOR_KUBECTL="$ACTUAL_KEY_PATH_KUBECTL"
        else
          echo -e "\\033[0;31mConfiguration Error: var.key_name (${var.key_name}) is set, but var.ssh_private_key_file_path is not for kubectl SSH. Cannot proceed with this check reliably.\\033[0m"
          # Exit or set SSH_IDENTITY_ARG_KUBECTL to empty and let it try default keys
          exit 1 # Or some other handling
        fi
      else
        LOCAL_SSH_KEY_FOR_KUBECTL="${path.root}/generated-ssh-key.pem"
      fi

      SSH_IDENTITY_ARG_KUBECTL=""
      if [ ! -f "$LOCAL_SSH_KEY_FOR_KUBECTL" ]; then
        echo -e "\\033[0;31mSSH Key Error: Private key file for kubectl not found at [$LOCAL_SSH_KEY_FOR_KUBECTL]. Will try SSH without specific key.\\033[0m"
      else
        SSH_IDENTITY_ARG_KUBECTL="-i \"$LOCAL_SSH_KEY_FOR_KUBECTL\""
      fi
        
      check_cluster_status() {
        local attempt=$1
        echo -e "\\033[0;33m🔍 Checking Kubernetes cluster status (Attempt $attempt/5) using key $LOCAL_SSH_KEY_FOR_KUBECTL...\\033[0m"
        # Use $SSH_IDENTITY_ARG_KUBECTL which includes -i "path" or is empty
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 $SSH_IDENTITY_ARG_KUBECTL ubuntu@$CONTROL_PLANE_IP "kubectl get nodes" > /tmp/nodes_output 2>&1
        # ... (rest of the function)
      }
      # ... (rest of the script)
    EOT
  }
}

# New resource to verify control plane is fully ready
resource "null_resource" "verify_control_plane_readiness" {
  depends_on = [
    aws_instance.control_plane,
    null_resource.control_plane_bootstrap_debug
  ]

  triggers = {
    control_plane_ip = aws_instance.control_plane.public_ip
    control_plane_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      # Set environment variables for the script
      export CP_INSTANCE_ID="${aws_instance.control_plane.id}"
      export AWS_REGION_VAR="${var.region}"
      export JOIN_COMMAND_LATEST_SECRET_ID="${aws_secretsmanager_secret.kubernetes_join_command_latest.id}"
      # Pass the shell variable SKIP_K8S_VERIFICATION if it's set in the TF execution environment
      export SKIP_K8S_VERIFICATION_VAR="$${SKIP_K8S_VERIFICATION:-false}"

      SCRIPT_PATH="${path.module}/scripts/verify_control_plane_readiness.sh"
      chmod +x "$SCRIPT_PATH"
      "$SCRIPT_PATH"
    EOT
  }
}

# Simplified join command resource that relies on the control plane to generate tokens
resource "null_resource" "update_join_command" {
  depends_on = [
    aws_instance.control_plane,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
    null_resource.verify_control_plane_readiness
  ]

  # This will cause this resource to be recreated whenever the control plane IP changes
  triggers = {
    control_plane_ip = aws_instance.control_plane.public_ip
    control_plane_id = aws_instance.control_plane.id
    # The verification resource ID ensures we wait for control plane readiness
    verification_id = null_resource.verify_control_plane_readiness.id
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

resource "null_resource" "validate_user_data_size" {
  provisioner "local-exec" {
    command = <<EOT
      echo "Validating user data script sizes..."
      
      # Check bootstrap_worker.sh size
      WORKER_SCRIPT_SIZE=$(cat ${path.module}/bootstrap_worker.sh | base64 | wc -c)
      if [[ $WORKER_SCRIPT_SIZE -gt 16384 ]]; then
        echo "ERROR: bootstrap_worker.sh exceeds 16,384 bytes after base64 encoding (size: $WORKER_SCRIPT_SIZE bytes)"
        exit 1
      else
        echo "worker script size is valid: $WORKER_SCRIPT_SIZE bytes"
      fi
      
      # Check control_plane_user_data.sh size
      CP_SCRIPT_SIZE=$(cat ${path.module}/control_plane_user_data.sh | base64 | wc -c)
      if [[ $CP_SCRIPT_SIZE -gt 16384 ]]; then
        echo "ERROR: control_plane_user_data.sh exceeds 16,384 bytes after base64 encoding (size: $CP_SCRIPT_SIZE bytes)"
        exit 1
      else
        echo "control plane script size is valid: $CP_SCRIPT_SIZE bytes"
      fi
      
      echo "All script sizes are within AWS EC2 user-data limit (16,384 bytes)"
    EOT
  }
}

# Critical Fix: Add missing EBS CSI driver and AWS cloud provider permissions
resource "aws_iam_role_policy" "control_plane_ebs_csi_policy" {
  name = "EBSCSIDriverPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:AttachVolume", 
          "ec2:DetachVolume",
          "ec2:ModifyVolume",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumeAttribute",
          "ec2:DescribeVolumeStatus",
          "ec2:DescribeVolumesModifications",
          "ec2:CreateSnapshot",
          "ec2:CopySnapshot",
          "ec2:DescribeInstanceAttribute",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# Critical Fix: AWS cloud provider permissions for control plane
resource "aws_iam_role_policy" "control_plane_cloud_provider_policy" {
  name = "AWSCloudProviderPolicy"
  role = aws_iam_role.control_plane_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeRegions",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVolumes",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceAttribute",
          "ec2:DescribeVpcs",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeInstanceTypes",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:ReplaceRoute"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/kubernetes.io/cluster/${var.cluster_name}" = ["owned", "shared"]
          }
        }
      }
    ]
  })
}

#DEBUGGABLE: Control plane IAM debugging hook
resource "null_resource" "control_plane_iam_debug" {
  depends_on = [null_resource.vpc_debug_post]
  
  triggers = {
    iam_timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"control_plane_iam_setup", "status":"start", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Check existing IAM resources to avoid conflicts
      aws iam get-role --role-name control-plane-role > ../logs/cluster_state/existing_cp_role_${timestamp()}.json 2>&1 || {
        echo '{"stage":"iam_role_check", "status":"new_role_needed", "role":"control-plane-role", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      }
    EOT
    
    on_failure = continue
  }
}

#DEBUGGABLE: Security group creation debug hook  
resource "null_resource" "security_group_debug" {
  depends_on = [null_resource.control_plane_iam_debug]
  
  triggers = {
    sg_timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"security_group_creation", "status":"start", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Check VPC security groups to avoid conflicts
      aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${module.vpc.vpc_id}" --region "${var.region}" > ../logs/cluster_state/existing_sgs_${timestamp()}.json 2>&1
      
      echo '{"stage":"security_group_pre_check", "status":"complete", "vpc_id":"${module.vpc.vpc_id}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

# Fix 2: Enhanced security group with all required Kubernetes ports and proper tags
resource "aws_security_group" "k8s_sg" {
  depends_on = [null_resource.security_group_debug]
  
  name_prefix = "guy-k8s-sg-"
  vpc_id      = var.vpc_id != "" ? var.vpc_id : module.vpc.vpc_id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Kubernetes API server
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kubernetes API server"
  }

  # etcd server client API
  ingress {
    from_port   = 2379
    to_port     = 2380
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "etcd server client API"
  }

  # Kubelet API
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Kubelet API"
  }

  # kube-controller-manager
  ingress {
    from_port   = 10257
    to_port     = 10257
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "kube-controller-manager"
  }

  # kube-scheduler
  ingress {
    from_port   = 10259
    to_port     = 10259
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "kube-scheduler"
  }

  # Calico BGP
  ingress {
    from_port   = 179
    to_port     = 179
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Calico BGP"
  }

  # Calico VXLAN
  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Calico VXLAN"
  }

  # Container runtime (containerd)
  ingress {
    from_port   = 2376
    to_port     = 2377
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Container runtime"
  }

  # NodePort Services (combined into one rule)
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort services for external access"
  }

  # Allow all internal traffic for clustering
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Allow all internal VPC traffic for cluster communication"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name                                        = "guy-k8s-sg"
    "kubernetes.io-cluster-${var.cluster_name}" = "owned"  # Already correct
    "DebugEnabled"                              = "true"
  }

  lifecycle {
    create_before_destroy = true
  }
}

#DEBUGGABLE: Worker node launch template debug hook
resource "null_resource" "worker_lt_debug" {
  #VALIDATION: Enhanced dependencies with API server readiness check
  depends_on = [
    null_resource.control_plane_bootstrap_debug,
    null_resource.verify_control_plane_readiness  # Added comprehensive readiness check
  ]
  
  triggers = {
    worker_timestamp = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"worker_launch_template_creation", "status":"start", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Validate worker prerequisites
      aws iam get-instance-profile --instance-profile-name ${aws_iam_instance_profile.worker_profile.name} > ../logs/cluster_state/worker_instance_profile_${timestamp()}.json 2>&1
      
      echo '{"stage":"worker_prerequisites", "status":"validated", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
    EOT
    
    on_failure = continue
  }
}

resource "aws_launch_template" "worker_lt" {
  depends_on = [null_resource.worker_lt_debug] # Ensure this dependency is correct based on your setup

  name_prefix   = "guy-polybot-worker-"
  image_id      = var.worker_ami
  instance_type = var.worker_instance_type
  key_name      = local.actual_key_name # Ensure local.actual_key_name is correctly defined

  vpc_security_group_ids = [aws_security_group.worker_sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.worker_profile.name
  }

  user_data = base64encode(templatefile("${path.module}/bootstrap_worker.sh", {
    # Variables that bootstrap_worker.sh expects:
    cluster_name                 = var.cluster_name
    region                       = var.region
    SSH_PUBLIC_KEY               = local.actual_key_name != "" && var.key_name == "" ? tls_private_key.ssh[0].public_key_openssh : "" 
                                 # More robust SSH key logic: only pass generated key if var.key_name is not set.
                                 # If var.key_name is set, pass empty, script handles it.

    JOIN_COMMAND_SECRET          = aws_secretsmanager_secret.kubernetes_join_command.name
    JOIN_COMMAND_LATEST_SECRET   = aws_secretsmanager_secret.kubernetes_join_command_latest.name

    # === ADD/ENSURE THESE ARE PASSED ===
    K8S_PACKAGE_VERSION_TO_INSTALL = local.k8s_package_version_for_template
    K8S_MAJOR_MINOR_FOR_REPO     = local.k8s_major_minor_for_template
    CRIO_K8S_MAJOR_MINOR_FOR_REPO= local.crio_k8s_major_minor_for_template
    # ====================================

    # worker_asg_name remains commented out to prevent cycles;
    # bootstrap_worker.sh dynamically discovers the ASG name if needed for lifecycle hooks.
    # worker_asg_name              = aws_autoscaling_group.worker_asg.name 
  }))

  block_device_mappings {
    device_name = "/dev/sda1" # Or as appropriate for your AMI
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Good for security (IMDSv2)
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name                                        = "guy-worker-node" # Name will be further customized by script if using SSM counter
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
      "k8s.io/role/node"                          = "" # Common practice is an empty value or "node"
      "DebugEnabled"                              = "true"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name                                        = "guy-worker-node-volume"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
      "DebugEnabled"                              = "true"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

#DEBUGGABLE: Final cluster state validation and debug artifact creation
resource "null_resource" "cluster_debug_final" {
  depends_on = [
    aws_autoscaling_group.worker_asg,
    null_resource.verify_control_plane_readiness
  ]
  
  triggers = {
    cluster_complete = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      echo '{"stage":"cluster_deployment_complete", "status":"finalizing", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      
      # Create comprehensive cluster state snapshot
      mkdir -p ../logs/final_state
      
      # Capture control plane state
      aws ec2 describe-instances --instance-ids "${aws_instance.control_plane.id}" --region "${var.region}" > ../logs/final_state/control_plane_final_${timestamp()}.json 2>&1
      
      # Capture ASG state
      aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "${aws_autoscaling_group.worker_asg.name}" --region "${var.region}" > ../logs/final_state/worker_asg_final_${timestamp()}.json 2>&1
      
      # Capture launch template state  
      aws ec2 describe-launch-templates --launch-template-names "${aws_launch_template.worker_lt.name}" --region "${var.region}" > ../logs/final_state/launch_template_final_${timestamp()}.json 2>&1
      
      # Test final connectivity
      timeout 30 bash -c "until nc -z ${aws_instance.control_plane.public_ip} 6443; do sleep 2; done" && {
        echo '{"stage":"final_api_connectivity", "status":"success", "ip":"${aws_instance.control_plane.public_ip}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      } || {
        echo '{"stage":"final_api_connectivity", "status":"error", "ip":"${aws_instance.control_plane.public_ip}", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      }
      
      # Generate deployment summary
      cat > ../logs/deployment_summary_${timestamp()}.json <<SUMMARY
{
  "deployment_complete": "${timestamp()}",
  "control_plane": {
    "instance_id": "${aws_instance.control_plane.id}",
    "public_ip": "${aws_instance.control_plane.public_ip}",
    "private_ip": "${aws_instance.control_plane.private_ip}"
  },
  "worker_asg": {
    "name": "${aws_autoscaling_group.worker_asg.name}",
    "desired_capacity": ${aws_autoscaling_group.worker_asg.desired_capacity},
    "min_size": ${aws_autoscaling_group.worker_asg.min_size},
    "max_size": ${aws_autoscaling_group.worker_asg.max_size}
  },
  "cluster_info": {
    "name": "${var.cluster_name}",
    "region": "${var.region}",
    "vpc_id": "${module.vpc.vpc_id}"
  },
  "debug_files_created": {
    "logs_directory": "../logs/",
    "cluster_state": "../logs/cluster_state/",
    "kubernetes_state": "../logs/kubernetes_state/",
    "final_state": "../logs/final_state/"
  }
}
SUMMARY
      
      echo '{"stage":"cluster_deployment_complete", "status":"success", "time":"${timestamp()}"}' >> ../logs/tf_debug.log
      echo "🎉 Cluster deployment debug artifacts created successfully!"
    EOT
    
    on_failure = continue
  }
}

# S3 bucket for worker logs and debugging artifacts
resource "aws_s3_bucket" "worker_logs" {
  bucket = "guy-polybot-worker-logs-${random_id.suffix.hex}"
  force_destroy = true
  
  tags = {
    Name                                        = "guy-polybot-worker-logs"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    #DEBUGGABLE: Mark for debug tracking
    "DebugEnabled"                              = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "worker_logs_pab" {
  bucket = aws_s3_bucket.worker_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "worker_logs_versioning" {
  bucket = aws_s3_bucket.worker_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "worker_logs_lifecycle" {
  bucket = aws_s3_bucket.worker_logs.id

  rule {
    id     = "delete_old_logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "terraform_data" "worker_script_details" {
  triggers_replace = {
    # This key will change if the content of bootstrap_worker.sh changes
    worker_script_sha = filesha256("${path.module}/bootstrap_worker.sh")

    # This key will change if var.rebuild_workers becomes true and then back to false (or vice-versa)
    # or simply use the timestamp to always trigger if rebuild_workers is true.
    rebuild_trigger   = var.rebuild_workers ? timestamp() : "false"
  }
}

# AWS Secrets Manager for storing Kubernetes join commands
resource "aws_secretsmanager_secret" "kubernetes_join_command" {
  name                    = "kubernetes-join-command-${random_id.suffix.hex}"
  description             = "Kubernetes cluster join command for worker nodes"
  recovery_window_in_days = 0  # Allow immediate deletion for development

  tags = {
    Name                                        = "kubernetes-join-command"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    #DEBUGGABLE: Mark for debug tracking
    "DebugEnabled"                              = "true"
  }
}

resource "aws_secretsmanager_secret" "kubernetes_join_command_latest" {
  name                    = "kubernetes-join-command-latest-${random_id.suffix.hex}"
  description             = "Latest Kubernetes cluster join command for worker nodes"
  recovery_window_in_days = 0  # Allow immediate deletion for development

  tags = {
    Name                                        = "kubernetes-join-command-latest"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    #DEBUGGABLE: Mark for debug tracking
    "DebugEnabled"                              = "true"
  }
}

# Initialize the secrets with placeholder values
resource "aws_secretsmanager_secret_version" "kubernetes_join_command_initial" {
  secret_id     = aws_secretsmanager_secret.kubernetes_join_command.id
  secret_string = "kubeadm join placeholder:6443 --token ${local.kubeadm_token} --discovery-token-ca-cert-hash sha256:placeholder"
}

resource "aws_secretsmanager_secret_version" "kubernetes_join_command_latest_initial" {
  secret_id     = aws_secretsmanager_secret.kubernetes_join_command_latest.id
  secret_string = "kubeadm join placeholder:6443 --token ${local.kubeadm_token} --discovery-token-ca-cert-hash sha256:placeholder"
}

# Dedicated security group for control plane node
resource "aws_security_group" "control_plane_sg" {
  depends_on = [null_resource.security_group_debug]
  
  name_prefix = "guy-control-plane-sg-"
  vpc_id      = var.vpc_id != "" ? var.vpc_id : module.vpc.vpc_id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Kubernetes API server
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kubernetes API server"
  }

  # etcd server client API (CRITICAL for control plane)
  ingress {
    from_port   = 2379
    to_port     = 2380
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "etcd server client API"
  }

  # Kubelet API (control plane)
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Kubelet API"
  }

  # kube-controller-manager
  ingress {
    from_port   = 10257
    to_port     = 10257
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "kube-controller-manager"
  }

  # kube-scheduler
  ingress {
    from_port   = 10259
    to_port     = 10259
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "kube-scheduler"
  }

  # All VPC traffic for internal cluster communication
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Allow all internal VPC traffic for cluster communication"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name                                        = "guy-control-plane-sg"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    "kubernetes.io/role/control-plane"         = "true"
    #DEBUGGABLE: Mark for debug tracking
    "DebugEnabled"                              = "true"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# IAM Instance Profile for Worker Nodes
resource "aws_iam_instance_profile" "worker_profile" {
  name = "Guy-K8S-WorkerNode-Profile"
  role = aws_iam_role.worker_role.name
  
  lifecycle {
    create_before_destroy = true
  }
}



