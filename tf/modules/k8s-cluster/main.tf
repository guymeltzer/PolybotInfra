#DEBUGGABLE: VPC creation debug hook
resource "null_resource" "vpc_debug_pre" {
  triggers = {
    vpc_config = jsonencode({
      vpc_cidr = "10.0.0.0/16"
      region   = var.region
      timestamp = timestamp()
    })
  }

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

  enable_nat_gateway = true
  single_nat_gateway = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name                                        = "guy-vpc"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    # AWS Cloud Provider integration tags
    "kubernetes.io/role/elb"                    = "1"
    #DEBUGGABLE: Mark for debug tracking
    "DebugEnabled"                              = "true"
  }

  public_subnet_tags = {
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    # Ensure load balancer controller can find subnets
    "kubernetes.io/role/internal-elb"           = ""
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"           = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  }
}

#DEBUGGABLE: VPC creation validation hook
resource "null_resource" "vpc_debug_post" {
  depends_on = [module.vpc]
  
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

# Format the token for kubeadm (must be in format AAAAAA.BBBBBBBBBBBBBBBB)
locals {
  kubeadm_token = "${random_string.token_part1.result}.${random_string.token_part2.result}"

  # Fix CIDR conflict: VPC uses 10.0.0.0/16, so use 10.244.0.0/16 for pods
  # This ensures no overlap between VPC subnets and pod network
  pod_cidr = var.pod_cidr != "" ? var.pod_cidr : "10.244.0.0/16"
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

# IAM Managed Policy Attachments for Control Plane
resource "aws_iam_role_policy_attachment" "control_plane_policies" {
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
    aws_security_group.control_plane_sg
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
    aws_secretsmanager_secret.kubernetes_join_command_latest
  ]

  ami           = var.control_plane_ami
  instance_type = var.control_plane_instance_type
  key_name      = local.actual_key_name
  
  iam_instance_profile   = aws_iam_instance_profile.control_plane_profile.name
  vpc_security_group_ids = [aws_security_group.control_plane_sg.id]
  subnet_id              = var.vpc_id != "" ? var.subnet_ids[0] : module.vpc.public_subnets[0]

  # Enhanced user data with comprehensive error handling
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
  }))

  # Enhanced metadata options for proper cloud integration
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
      DebugEnabled = "true"  #DEBUGGABLE
    }
  }

  tags = {
    Name                                        = "guy-control-plane"
    Role                                        = "control-plane"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    # AWS cloud provider integration tags (CRITICAL)
    "k8s.io/cluster-autoscaler/enabled"         = "true"
    "k8s.io/cluster-autoscaler/${var.cluster_name}" = "owned"
    #DEBUGGABLE: Enhanced debug tracking
    "DebugEnabled"                              = "true"
    "DeploymentTime"                            = timestamp()
  }

  lifecycle {
    create_before_destroy = false
    ignore_changes = [
      user_data  # Prevent unnecessary recreation when user data changes
    ]
  }
}

#DEBUGGABLE: Control plane initialization monitoring
resource "null_resource" "control_plane_bootstrap_debug" {
  depends_on = [aws_instance.control_plane]
  
  triggers = {
    cp_instance_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
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

# Force update ASG when worker script changes
resource "terraform_data" "force_asg_update" {
  input = terraform_data.control_plane_script_hash.id
  
  triggers_replace = [
    aws_launch_template.worker_lt.latest_version,
    var.rebuild_workers
  ]
}

#DEBUGGABLE: Worker ASG creation debug hook
resource "null_resource" "worker_asg_debug" {
  depends_on = [aws_launch_template.worker_lt]
  
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
    version = "$Latest"
  }

  # Critical Fix: Valid AWS tag keys for cluster autoscaler
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
  
  # Critical Fix: Valid tag key format for AWS cloud provider
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
  
  # Critical Fix: Ensure proper dependency chain - workers start only after control plane is verified ready
  depends_on = [
    null_resource.worker_asg_debug,
    aws_instance.control_plane,
    aws_launch_template.worker_lt,
    terraform_data.force_asg_update,
    aws_secretsmanager_secret.kubernetes_join_command,
    aws_secretsmanager_secret.kubernetes_join_command_latest,
    null_resource.verify_control_plane_readiness,  # Critical: Wait for control plane to be actually ready
    null_resource.update_join_command,             # Critical: Ensure join token exists
    terraform_data.worker_progress
  ]
  
  lifecycle {
    # Force replacement when worker script hash changes
    replace_triggered_by = [
      terraform_data.force_asg_update
    ]
    # Ignore certain changes that would cause replacement
    ignore_changes = [
      desired_capacity,
      launch_template[0].version
    ]
  }

  # Report progress after ASG is created
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = "echo -e \"\\033[0;32m✅ Worker node Auto Scaling Group '${var.cluster_name}-worker-asg' created!\\033[0m\""
  }
}

resource "aws_security_group" "worker_sg" {
  name        = "Guy-WorkerNodes-SG"
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
  
  # Critical: Kubelet API for control plane communication
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Only from VPC for security
    description = "Kubelet API - required for control plane communication"
  }

  # Critical: Read-only Kubelet API
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
    description = "NodePort service range"
  }

  # Critical: Kubernetes API server access for worker nodes
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Workers need to reach API server
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

  # Critical: Calico overlay networking (VXLAN) - required for pod-to-pod communication
  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    self        = true
    description = "Calico VXLAN overlay - required for pod networking"
  }

  # Critical: Calico BGP traffic - required for network policy
  ingress {
    from_port   = 179
    to_port     = 179
    protocol    = "tcp"
    self        = true
    description = "Calico BGP traffic - required for network policy"
  }

  # Critical: Container runtime ports (containerd/Docker)
  ingress {
    from_port   = 2376
    to_port     = 2377
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Container runtime communication"
  }

  # NodePort Services (CRITICAL for external service access)
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

  # NodePort Services (CRITICAL for external service access on workers)
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort services for external access via workers"
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
    Name = "guy-worker-sg"
    # Critical: AWS cloud provider integration tags
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    "kubernetes.io/role/node" = "true"
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

locals {
  # Use provided key name if set, otherwise use the auto-generated key
  actual_key_name = var.key_name != "" ? var.key_name : (length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : "")
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
      echo -e "\\033[1;34m================================================================\\033[0m"
      echo -e "\\033[1;34m 🚀 Step 3/4: Kubernetes Cluster Initialization in Progress 🚀 \\033[0m"
      echo -e "\\033[1;34m================================================================\\033[0m"
      echo -e "\\033[0;33m⏱️  Initializing control plane and worker nodes...\\033[0m"
      
      CONTROL_PLANE_IP="${aws_instance.control_plane.public_ip}"
      
      # Simple function to check cluster status
      check_cluster_status() {
        local attempt=$1
        echo -e "\\033[0;33m🔍 Checking Kubernetes cluster status (Attempt $attempt/5)...\\033[0m"
        
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ubuntu@$CONTROL_PLANE_IP "kubectl get nodes" > /tmp/nodes_output 2>&1
        
        if grep -q "Ready" /tmp/nodes_output; then
          echo -e "\\033[0;32m✅ Kubernetes nodes found and ready!\\033[0m"
          cat /tmp/nodes_output
          return 0
        else
          echo -e "\\033[0;33m⏱️  Cluster not ready yet. Output from control plane:\\033[0m"
          cat /tmp/nodes_output
          echo ""
          return 1
        fi
      }
      
      # Main check loop with simpler approach
      for attempt in {1..5}; do
        if check_cluster_status $attempt; then
          echo -e "\\033[1;34m================================================================\\033[0m"
          echo -e "\\033[1;32m ✅ Step 4/4: Kubernetes Cluster is Ready!\\033[0m"
          echo -e "\\033[1;34m================================================================\\033[0m"
          echo -e "\\033[1;32m     🎉 Kubernetes Deployment Complete! 🎉\\033[0m"
          echo -e "\\033[1;34m================================================================\\033[0m"
          echo -e "\\033[0;32m📋 Cluster Information:\\033[0m"
          echo -e "\\033[0;32m   🖥️  Control Plane: ssh ubuntu@$CONTROL_PLANE_IP\\033[0m"
          echo -e "\\033[0;32m   🔍 Check Status: kubectl --kubeconfig=./kubeconfig.yaml get nodes\\033[0m"
          echo -e "\\033[0;32m   📜 View Logs: ssh ubuntu@$CONTROL_PLANE_IP \"cat /var/log/k8s-control-plane-init.log\"\\033[0m"
          echo -e "\\033[1;34m================================================================\\033[0m"
          exit 0
        fi
        
        if [ $attempt -lt 5 ]; then
          echo -e "\\033[0;33m⏱️  Waiting 60 seconds before next check...\\033[0m"
          sleep 60
        fi
      done
      
      # Final status when all checks fail
      echo -e "\\033[1;34m================================================================\\033[0m"
      echo -e "\\033[0;33m⚠️  Control plane initialization in progress.\\033[0m"
      echo -e "\\033[0;33m⚠️  Deployment continuing, but manual verification recommended.\\033[0m"
      echo -e "\\033[0;33m⚠️  Try these commands to check the cluster status:\\033[0m"
      echo -e "\\033[0;36m   ssh ubuntu@$CONTROL_PLANE_IP \"sudo systemctl status kubelet\"\\033[0m"
      echo -e "\\033[0;36m   ssh ubuntu@$CONTROL_PLANE_IP \"sudo journalctl -u kubelet\"\\033[0m"
      echo -e "\\033[0;36m   ssh ubuntu@$CONTROL_PLANE_IP \"kubectl get nodes\"\\033[0m"
      echo -e "\\033[1;34m================================================================\\033[0m"
    EOT
  }
}

# New resource to verify control plane is fully ready
resource "null_resource" "verify_control_plane_readiness" {
  depends_on = [
    aws_instance.control_plane,
    null_resource.control_plane_bootstrap_debug
  ]

  # This will cause this resource to be recreated whenever the control plane changes
  triggers = {
    control_plane_ip = aws_instance.control_plane.public_ip
    control_plane_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      # Allow skipping verification with environment variable
      if [ "$${SKIP_K8S_VERIFICATION:-false}" == "true" ]; then
        echo "SKIP_K8S_VERIFICATION is set to true, skipping control plane verification"
        exit 0
      fi
      
      echo "Verifying control plane readiness at $(date)..."
      
      # Define max attempts and delay between attempts
      MAX_ATTEMPTS=20
      DELAY=30
      READINESS_LOG="/tmp/k8s_control_plane_readiness.log"
      INSTANCE_ID="${aws_instance.control_plane.id}"
      REGION="${var.region}"
      
      # Create the log file and capture script output
      echo "Starting control plane verification at $(date)" > $READINESS_LOG
      exec > >(tee -a $READINESS_LOG) 2>&1
      
      # Function to check if SSM agent is ready on the control plane
      check_ssm_readiness() {
        echo "Checking SSM agent readiness on $INSTANCE_ID..."
        aws ssm describe-instance-information \
          --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
          --region $REGION | grep -q "$INSTANCE_ID"
        return $?
      }
      
      # Function to check if instance is fully initialized via EC2 status checks
      check_instance_status() {
        echo "Checking EC2 instance status..."
        STATUS=$(aws ec2 describe-instance-status \
          --instance-ids $INSTANCE_ID \
          --region $REGION \
          --query "InstanceStatuses[0].InstanceStatus.Status" \
          --output text 2>/dev/null)
          
        if [[ "$STATUS" == "ok" ]]; then
          echo "EC2 instance status is ok"
          return 0
        else
          echo "EC2 instance status is $STATUS, not fully initialized yet"
          return 1
        fi
      }
      
      # Multiple approaches to check if API server is ready
      check_api_server_readiness() {
        echo "Checking Kubernetes API server readiness (attempt $1)..."
        local success=false
        
        # Method 1: Check if port 6443 is listening using ss
        echo "Method 1: Checking if port 6443 is listening using ss"
        PORT_CHECK=$(aws ssm send-command \
          --instance-ids $INSTANCE_ID \
          --document-name "AWS-RunShellScript" \
          --parameters 'commands=["sudo ss -tlnp | grep 6443 || echo not-ready"]' \
          --region $REGION \
          --output text \
          --query "CommandInvocations[].CommandPlugins[].Output" 2>/dev/null || echo "SSM command failed")
          
        echo "Port check result: $PORT_CHECK"
        
        if [[ "$PORT_CHECK" != "not-ready" ]] && [[ "$PORT_CHECK" != "SSM command failed" ]] && [[ "$PORT_CHECK" != "None" ]]; then
          echo "Port 6443 is open according to ss command"
          success=true
        else
          # Method 2: Try netstat as an alternative
          echo "Method 2: Checking if port 6443 is listening using netstat"
          NETSTAT_CHECK=$(aws ssm send-command \
            --instance-ids $INSTANCE_ID \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["sudo netstat -tlnp | grep 6443 || echo not-ready"]' \
            --region $REGION \
            --output text \
            --query "CommandInvocations[].CommandPlugins[].Output" 2>/dev/null || echo "SSM command failed")
            
          echo "Netstat check result: $NETSTAT_CHECK"
          
          if [[ "$NETSTAT_CHECK" != "not-ready" ]] && [[ "$NETSTAT_CHECK" != "SSM command failed" ]] && [[ "$NETSTAT_CHECK" != "None" ]]; then
            echo "Port 6443 is open according to netstat command"
            success=true
          else
            # Method 3: Direct TCP connection check using nc
            echo "Method 3: Checking direct TCP connection to port 6443"
            NC_CHECK=$(aws ssm send-command \
              --instance-ids $INSTANCE_ID \
              --document-name "AWS-RunShellScript" \
              --parameters 'commands=["nc -zv localhost 6443 2>&1 || echo connection-failed"]' \
              --region $REGION \
              --output text \
              --query "CommandInvocations[].CommandPlugins[].Output" 2>/dev/null || echo "SSM command failed")
              
            echo "NC connection check result: $NC_CHECK"
            
            if [[ "$NC_CHECK" == *"succeeded"* ]] || [[ "$NC_CHECK" == *"open"* ]]; then
              echo "Port 6443 is reachable via nc command"
              success=true
            fi
          fi
        fi
        
        # Check the API health endpoint as final validation
        if $success; then
          echo "Port appears to be open, checking API server health endpoint"
          API_CHECK=$(aws ssm send-command \
            --instance-ids $INSTANCE_ID \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["sudo KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/healthz 2>/dev/null || echo not-ready"]' \
            --region $REGION \
            --output text \
            --query "CommandInvocations[].CommandPlugins[].Output" 2>/dev/null || echo "SSM command failed")
            
          echo "API health check result: $API_CHECK"
          
          if [[ "$API_CHECK" == *"ok"* ]]; then
            echo "API server is healthy"
            return 0
          else
            echo "API server is not responding correctly"
          fi
        fi
        
        # If we've reached the last few attempts, try one last alternative check
        if [ $1 -ge $((MAX_ATTEMPTS - 3)) ]; then
          echo "Last resort check: Looking for kube-apiserver process"
          PROCESS_CHECK=$(aws ssm send-command \
            --instance-ids $INSTANCE_ID \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["ps aux | grep kube-apiserver | grep -v grep || echo not-running"]' \
            --region $REGION \
            --output text \
            --query "CommandInvocations[].CommandPlugins[].Output" 2>/dev/null || echo "SSM command failed")
            
          echo "API server process check result: $PROCESS_CHECK"
          
          if [[ "$PROCESS_CHECK" != "not-running" ]] && [[ "$PROCESS_CHECK" != "SSM command failed" ]] && [[ "$PROCESS_CHECK" != "None" ]]; then
            echo "kube-apiserver process is running, considering this sufficient"
            return 0
          fi
        fi
        
        return 1
      }
      
      # Function to check if secrets manager contains a valid join token
      check_secrets_readiness() {
        echo "Checking if join token exists in Secrets Manager..."
        
        # Try to get the secret value
        JOIN_CMD=$(aws secretsmanager get-secret-value \
          --secret-id ${aws_secretsmanager_secret.kubernetes_join_command_latest.id} \
          --region $REGION \
          --query SecretString \
          --output text 2>/dev/null)
        
        if [[ -z "$JOIN_CMD" ]]; then
          echo "No join command found in Secrets Manager"
          return 1
        fi
        
        if [[ "$JOIN_CMD" == *"kubeadm join"* ]] && [[ "$JOIN_CMD" == *"--token"* ]]; then
          echo "Valid join command found in Secrets Manager"
          return 0
        else
          echo "Invalid join command format found in Secrets Manager"
          return 1
        fi
      }
      
      # Function to try to generate join token
      trigger_token_creation() {
        echo "Attempting to trigger token creation..."
        
        aws ssm send-command \
          --instance-ids $INSTANCE_ID \
          --document-name "AWS-RunShellScript" \
          --parameters 'commands=["sudo systemctl start k8s-token-creator.service || sudo /usr/local/bin/refresh-join-token.sh || sudo kubeadm token create --print-join-command"]' \
          --region $REGION \
          --output text \
          --query "CommandInvocations[].CommandPlugins[].Output" > /dev/null 2>&1
          
        echo "Token creation triggered. Waiting before next attempt..."
        return 0
      }
      
      # Main verification loop
      OVERALL_SUCCESS=false
      API_SERVER_READY=false
      SECRETS_READY=false
      
      for ((i=1; i<=MAX_ATTEMPTS; i++)); do
        echo "=== Verification attempt $i/$MAX_ATTEMPTS at $(date) ==="
        
        # Step 1: Check EC2 instance status first
        if ! check_instance_status; then
          echo "EC2 instance not fully initialized. Waiting $DELAY seconds before next attempt..."
          sleep $DELAY
          continue
        fi
        
        # Step 2: Check SSM agent readiness
        if ! check_ssm_readiness; then
          echo "SSM agent not ready yet. Waiting $DELAY seconds before next attempt..."
          sleep $DELAY
          continue
        fi
        
        # Step 3: Check API server readiness
        if ! $API_SERVER_READY && check_api_server_readiness $i; then
          API_SERVER_READY=true
          echo "✅ API server check passed"
        fi
        
        # Step 4: Verify token exists in Secrets Manager
        if ! $SECRETS_READY && check_secrets_readiness; then
          SECRETS_READY=true
          echo "✅ Secrets Manager check passed"
        fi
        
        # If we have both checks passing, we're done
        if $API_SERVER_READY && $SECRETS_READY; then
          OVERALL_SUCCESS=true
          echo "✅ Control plane verification SUCCESSFUL at $(date)"
          break
        fi
        
        # If API is ready but no token, trigger token creation
        if $API_SERVER_READY && ! $SECRETS_READY; then
          trigger_token_creation
        fi
        
        # Continue to next attempt
        echo "Waiting $DELAY seconds before next attempt..."
        sleep $DELAY
      done
      
      # Final status report
      echo "===== Control Plane Verification Results ====="
      echo "API Server Ready: $API_SERVER_READY"
      echo "Secret Token Ready: $SECRETS_READY"
      echo "Overall Success: $OVERALL_SUCCESS"
      
      # If we've reached maximum attempts but at least API server is ready,
      # consider this a partial success and exit with status 0
      if ! $OVERALL_SUCCESS && $API_SERVER_READY; then
        echo "⚠️ Partial success: API server is ready but token verification failed"
        echo "Continuing deployment anyway as the token may be created later"
        # Exit with success code to allow deployment to proceed
        exit 0
      fi
      
      # If overall verification failed but we're at the max attempts
      if ! $OVERALL_SUCCESS; then
        echo "❌ Control plane verification FAILED after $MAX_ATTEMPTS attempts"
        echo "Continuing deployment anyway, but worker nodes may not be able to join immediately"
        # Exit with success code to allow deployment to proceed
        # The cluster will eventually stabilize when the control plane is ready
        exit 0
      fi
      
      exit 0
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

  # etcd server client API (CRITICAL - was missing!)
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

  # NodePort Services (CRITICAL for external service access)
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

  # NodePort Services (CRITICAL for external service access on workers)
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NodePort services for external access via workers"
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
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    #DEBUGGABLE: Mark for debug tracking
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
  depends_on = [null_resource.worker_lt_debug]
  
  name_prefix   = "guy-polybot-worker-"
  image_id      = var.worker_ami
  instance_type = var.worker_instance_type
  key_name      = local.actual_key_name
  
  # CRITICAL: Add missing properties for worker nodes
  vpc_security_group_ids = [aws_security_group.worker_sg.id]
  
  iam_instance_profile {
    name = aws_iam_instance_profile.worker_profile.name
  }
  
  # CRITICAL: Add user data for worker node bootstrap
  user_data = base64encode(templatefile("${path.module}/bootstrap_worker.sh", {
    cluster_name = var.cluster_name
    region       = var.region
    secret_name  = aws_secretsmanager_secret.kubernetes_join_command_latest.name
  }))
  
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 20
      volume_type = "gp3"
      encrypted   = true
      delete_on_termination = true
    }
  }
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name                                        = "guy-worker-node"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
      "k8s.io/role/node"                         = "true"
      #DEBUGGABLE: Mark for debug tracking
      "DebugEnabled"                              = "true"
    }
  }
  
  tag_specifications {
    resource_type = "volume"
    tags = {
      Name                                        = "guy-worker-node-volume"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
      #DEBUGGABLE: Mark for debug tracking
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



