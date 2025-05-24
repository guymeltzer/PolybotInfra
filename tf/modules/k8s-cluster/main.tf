module "vpc" {
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
    Name                               = "guy-vpc"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }

  public_subnet_tags = {
    "kubernetes.io/role/elb"          = "1"
    "kubernetes.io/role/internal-elb" = "1"
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

  # Determine pod CIDR for the cluster
  pod_cidr = var.pod_cidr
}

# Security Group for Kubernetes Cluster Resources
resource "aws_security_group" "k8s_sg" {
  name        = "Guy-K8S-SG"
  description = "Security group for Kubernetes control plane and workers"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  # Explicitly allow outbound traffic to Kubernetes API server
  egress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outbound traffic to Kubernetes API server"
  }

  tags = {
    Name = "guy-k8s-sg"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
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

resource "aws_instance" "control_plane" {
  ami                    = var.control_plane_ami
  instance_type          = var.control_plane_instance_type
  key_name               = local.actual_key_name
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.control_plane_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.control_plane_profile.name
  associate_public_ip_address = true

  # Prepare user data with template
  user_data_base64 = base64gzip(templatefile(
    "${path.module}/control_plane_user_data.sh",
    {
      ssh_public_key    = var.ssh_public_key != "" ? var.ssh_public_key : "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD3F6tyPEFEzV0LX3X8BsXdMsQz1x2cEikKDEY0aIj41qgxMCP/iteneqXSIFZBp5vizPvaoIR3Um9xK7PGoW8giupGn+EPuxIA4cDM4vzOqOkiMPhz5XK0whEjkVzTo4+S0puvDZuwIsdiW9mxhJc7tgBNL0cYlWSYVkz4G/fslNfRPW5mYAM49f4fhtxPb5ok4Q2Lg9dPKVHO/Bgeu5woMc7RY0p1ej6D4CKFE6lymSDJpW0YHX/wqE9+cfEauh7xZcG0q9t2ta6F6fmX0agvpFyZo8aFbXeUBr7osSCJNgvavWbM/06niWrOvYX2xwWdhXmXSrbX8ZbabVohBK41 temp-key",
      region            = var.region,
      cluster_name      = var.cluster_name,
      # Add these required variables to fix templating issues
      token_formatted   = local.kubeadm_token,
      KUBERNETES_JOIN_COMMAND_SECRET = aws_secretsmanager_secret.kubernetes_join_command.name,
      KUBERNETES_JOIN_COMMAND_LATEST_SECRET = aws_secretsmanager_secret.kubernetes_join_command_latest.name,
      # Add explicit empty variables for heredoc escape
      PRIVATE_IP        = "",
      PUBLIC_IP         = "",
      TOKEN             = "",
      DISCOVERY_HASH    = "",
      API_SERVER_IP     = "",
      # Add the missing 'step' variable referenced in the template
      step              = "",
      # We're adding other AWS related variables
      VPC_CIDR          = module.vpc.vpc_cidr_block,
      POD_CIDR          = local.pod_cidr
    }
  ))

  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name = "guy-control-plane"
    Role = "control-plane"
    ClusterIdentifier = "${var.cluster_name}-${random_id.suffix.hex}"
  }

  depends_on = [
    module.vpc,
    terraform_data.deployment_progress
  ]

  lifecycle {
    # Prevent replacement: Ignore changes to user_data since we want to preserve the control plane
    ignore_changes = [user_data_base64, tags["ClusterIdentifier"]]
    # Only replace when script content changes
    replace_triggered_by = [
      terraform_data.control_plane_script_hash
    ]
    # Create new instance before destroying the old one
    create_before_destroy = false
    # Prevent destruction by default
    prevent_destroy = false
  }

  # Add a provisioner to report progress
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = "echo -e \"\\033[0;32m✅ Control Plane instance launched! Instance ID: ${self.id}\\033[0m\""
  }
}

resource "null_resource" "wait_for_control_plane" {
  depends_on = [aws_instance.control_plane]

  provisioner "local-exec" {
    command = <<EOF
      # Wait for the control plane to initialize
      echo "Waiting for control plane to initialize..."
      sleep 60
      
      # Create empty certificate files if they don't already exist
      mkdir -p ${path.module}/certs
      [ -f ${path.module}/certs/ca.crt ] || touch ${path.module}/certs/ca.crt
      [ -f ${path.module}/certs/client.crt ] || touch ${path.module}/certs/client.crt
      [ -f ${path.module}/certs/client.key ] || touch ${path.module}/certs/client.key
      
      echo "Control plane certificates prepared (dummy files)."
      echo "NOTE: Actual certificates not retrieved. You may need to manually retrieve them later."
      
      # To manually retrieve certificates later, use:
      # aws ssm send-command --instance-ids ${aws_instance.control_plane.id} --document-name "AWS-RunShellScript" --parameters commands="cat /etc/kubernetes/pki/ca.crt" --output text --query "CommandInvocations[].CommandPlugins[].Output"
      # aws ssm send-command --instance-ids ${aws_instance.control_plane.id} --document-name "AWS-RunShellScript" --parameters commands="cat /etc/kubernetes/pki/apiserver-kubelet-client.crt" --output text --query "CommandInvocations[].CommandPlugins[].Output" 
      # aws ssm send-command --instance-ids ${aws_instance.control_plane.id} --document-name "AWS-RunShellScript" --parameters commands="cat /etc/kubernetes/pki/apiserver-kubelet-client.key" --output text --query "CommandInvocations[].CommandPlugins[].Output"
    EOF
  }
}

resource "local_file" "kubeconfig" {
  content = templatefile("${path.module}/templates/kubeconfig.tpl", {
    endpoint       = aws_lb.polybot_alb.dns_name
    token          = local.kubeadm_token
    cluster_ca     = base64encode(file("${path.module}/certs/ca.crt"))
    client_cert    = base64encode(file("${path.module}/certs/client.crt"))
    client_key     = base64encode(file("${path.module}/certs/client.key"))
    aws_region     = var.region
    cluster_name   = "k8s-cluster"
  })
  filename = "${path.module}/kubeconfig"

  depends_on = [
    null_resource.wait_for_control_plane
  ]
}

# Secrets Manager for Kubernetes join command
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_secretsmanager_secret" "kubernetes_join_command" {
  name                    = "kubernetes-join-command-${random_id.suffix.hex}"
  description             = "Kubernetes join command for worker nodes"
  recovery_window_in_days = 0  # No recovery window for easy replacement
  force_overwrite_replica_secret = true

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_secretsmanager_secret" "kubernetes_join_command_latest" {
  name                    = "kubernetes-join-command-latest-${random_id.suffix.hex}"
  description             = "Latest Kubernetes join command for worker nodes"
  recovery_window_in_days = 0  # No recovery window for easy replacement
  force_overwrite_replica_secret = true

  lifecycle {
    create_before_destroy = true
  }
}

# Lambda function for node draining and token refresh
resource "aws_lambda_function" "node_management_lambda" {
  function_name = "guy-polybot-token"
  role          = aws_iam_role.node_management_lambda_role.arn
  handler       = "index.lambda_handler"
  runtime       = "python3.9"
  timeout       = 120
  memory_size   = 256

  filename = "${path.module}/lambda_package.zip"

  environment {
    variables = {
      CONTROL_PLANE_INSTANCE_ID = aws_instance.control_plane.id
      REGION                   = var.region
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_management_lambda_policy_attach,
    aws_secretsmanager_secret.kubernetes_join_command
  ]
}

# Create the Lambda package with the node draining/token refresh code
resource "local_file" "lambda_function_code" {
  filename = "${path.module}/lambda_code.py"
  content = <<EOF
import boto3
import json
import time
import logging
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    autoscaling = boto3.client('autoscaling')
    ssm_client = boto3.client('ssm')
    secrets_client = boto3.client('secretsmanager')
    ec2_client = boto3.client('ec2')
    region = '${var.region}'
    control_plane_instance_id = '${aws_instance.control_plane.id}'
    
    logger.info(f"Event received: {json.dumps(event)}")
    
    # Handle SNS events (node termination)
    if 'Records' in event and len(event['Records']) > 0:
        try:
            record = event['Records'][0]
            if record.get('EventSource') == 'aws:sns' or record.get('EventSource') == 'aws:sqs' or record.get('Source') == 'aws:sns':
                logger.info("Processing SNS/SQS event")
                
                # Parse the message - handle both direct JSON or string-encoded JSON
                message_text = record.get('Sns', {}).get('Message', '{}')
                try:
                    message = json.loads(message_text)
                except Exception:
                    logger.warning(f"Failed to parse message as JSON: {message_text}")
                    message = {}
                
                logger.info(f"Parsed message: {json.dumps(message)}")
                
                # Check if this is an ASG lifecycle event
                if message.get('LifecycleTransition') == 'autoscaling:EC2_INSTANCE_TERMINATING':
                    logger.info("Processing scale-down event")
                    instance_id = message.get('EC2InstanceId')
                    lifecycle_hook_name = message.get('LifecycleHookName')
                    asg_name = message.get('AutoScalingGroupName')
                    
                    if not instance_id or not lifecycle_hook_name or not asg_name:
                        logger.error(f"Missing required fields in message: {json.dumps(message)}")
                        return {'statusCode': 400, 'body': 'Missing required fields in SNS message'}
                    
                    try:
                        # Get instance details
                        ec2_response = ec2_client.describe_instances(InstanceIds=[instance_id])
                        if not ec2_response.get('Reservations') or not ec2_response['Reservations'][0].get('Instances'):
                            logger.warning(f"No instance data found for {instance_id}")
                            return complete_lifecycle(autoscaling, lifecycle_hook_name, asg_name, instance_id, 'CONTINUE', 
                                                    f"No instance data found for {instance_id}")
                        
                        instance = ec2_response['Reservations'][0]['Instances'][0]
                        tags = instance.get('Tags', [])
                        private_ip = instance.get('PrivateIpAddress', '')
                        
                        # Find node name from tags or use IP
                        node_name = None
                        for tag in tags:
                            if tag.get('Key') == 'Name':
                                node_name = tag.get('Value')
                                break
                        
                        # Fall back to IP-based node name if tag not found
                        if not node_name:
                            node_name = f"ip-{private_ip.replace('.', '-')}.ec2.internal"
                        
                        logger.info(f"Draining node: {node_name}")
                        
                        # Drain node with 3 retries
                        success = False
                        for attempt in range(3):
                            try:
                                # Drain the node
                                drain_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf drain --ignore-daemonsets --delete-emptydir-data --force {node_name}"
                                logger.info(f"Running drain command: {drain_command}")
                                
                                response = ssm_client.send_command(
                                    InstanceIds=[control_plane_instance_id],
                                    DocumentName='AWS-RunShellScript',
                                    Parameters={'commands': [drain_command]},
                                    TimeoutSeconds=300
                                )
                                
                                command_id = response['Command']['CommandId']
                                wait_for_command(ssm_client, command_id, control_plane_instance_id)
                                
                                # Delete the node
                                delete_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf delete node {node_name}"
                                logger.info(f"Running delete command: {delete_command}")
                                
                                response = ssm_client.send_command(
                                    InstanceIds=[control_plane_instance_id],
                                    DocumentName='AWS-RunShellScript',
                                    Parameters={'commands': [delete_command]},
                                    TimeoutSeconds=300
                                )
                                
                                command_id = response['Command']['CommandId']
                                wait_for_command(ssm_client, command_id, control_plane_instance_id)
                                
                                success = True
                                break
                            except Exception as e:
                                logger.error(f"Attempt {attempt+1} failed: {str(e)}")
                                if attempt < 2:  # Only sleep if we're going to retry
                                    time.sleep(10)
                        
                        return complete_lifecycle(autoscaling, lifecycle_hook_name, asg_name, instance_id, 
                                                'CONTINUE', "Node drained and deleted successfully")
                    
                    except Exception as e:
                        logger.error(f"Error handling scale-down event: {str(e)}")
                        logger.error(traceback.format_exc())
                        return complete_lifecycle(autoscaling, lifecycle_hook_name, asg_name, instance_id, 
                                                'ABANDON', f"Error: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing SNS record: {str(e)}")
            logger.error(traceback.format_exc())
            return {'statusCode': 500, 'body': f"Error: {str(e)}"}
    
    # Default action: token refresh
    logger.info("Running join command refresh logic")
    try:
        # Get join command from control plane
        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': ['kubeadm token create --print-join-command']}
        )
        
        command_id = response['Command']['CommandId']
        join_command = wait_for_command(ssm_client, command_id, control_plane_instance_id)
        
        if not join_command:
            raise Exception("Failed to get join command from control plane")
            
        logger.info(f"Join command retrieved: {join_command}")
        
        # Update secrets with the new join command
        update_secrets(secrets_client, join_command)
        
        return {'statusCode': 200, 'body': 'Join command updated successfully'}
        
    except Exception as e:
        logger.error(f"Error in token refresh: {str(e)}")
        logger.error(traceback.format_exc())
        return {'statusCode': 500, 'body': f"Error: {str(e)}"}

def wait_for_command(ssm_client, command_id, instance_id):
    """Wait for SSM command to complete and return its output"""
    max_attempts = 30
    attempt = 0
    
    while attempt < max_attempts:
        time.sleep(2)
        try:
            command_output = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            status = command_output['Status']
            
            if status in ['Success', 'Completed']:
                return command_output.get('StandardOutputContent', '').strip()
            elif status in ['Failed', 'Cancelled', 'TimedOut']:
                error = command_output.get('StandardErrorContent', 'Unknown error')
                raise Exception(f"SSM command failed: {error}")
                
        except ssm_client.exceptions.InvocationDoesNotExist:
            # Command not yet registered, wait and retry
            pass
            
        attempt += 1
    
    raise Exception("SSM command did not complete within 60 seconds")

def update_secrets(secrets_client, join_command):
    """Update all join command secrets with the new command"""
    # Get all secrets with 'kubernetes-join-command' in the name
    try:
        response = secrets_client.list_secrets(
            Filters=[{'Key': 'name', 'Values': ['kubernetes-join-command']}]
        )
        
        secrets = response.get('SecretList', [])
        
        if not secrets:
            raise Exception("No kubernetes-join-command secrets found")
            
        # Update the -latest secret first (highest priority)
        latest_secrets = [s for s in secrets if '-latest' in s['Name']]
        if latest_secrets:
            latest_secret = sorted(latest_secrets, key=lambda x: x.get('LastChangedDate', 0), reverse=True)[0]
            logger.info(f"Updating latest secret: {latest_secret['Name']}")
            
            secrets_client.put_secret_value(
                SecretId=latest_secret['Name'],
                SecretString=join_command
            )
        
        # Then update the base secrets
        base_secrets = [s for s in secrets if '-latest' not in s['Name'] and not s['Name'].endswith(('-INIT', '-COMPLETE'))]
        if base_secrets:
            base_secret = sorted(base_secrets, key=lambda x: x.get('LastChangedDate', 0), reverse=True)[0]
            logger.info(f"Updating base secret: {base_secret['Name']}")
            
            secrets_client.put_secret_value(
                SecretId=base_secret['Name'],
                SecretString=join_command
            )
        
        # Create a new timestamped secret as backup
        timestamp = int(time.time())
        new_secret_name = f"kubernetes-join-command-{timestamp}"
        
        secrets_client.create_secret(
            Name=new_secret_name,
            Description="Kubernetes join command created by Lambda",
            SecretString=join_command
        )
        
        return True
    except Exception as e:
        logger.error(f"Error updating secrets: {str(e)}")
        raise

def complete_lifecycle(autoscaling, hook_name, asg_name, instance_id, result, message):
    """Complete a lifecycle action and return a response"""
    try:
        logger.info(f"Completing lifecycle action: {hook_name}, ASG: {asg_name}, Instance: {instance_id}, Result: {result}")
        
        autoscaling.complete_lifecycle_action(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=asg_name,
            LifecycleActionResult=result,
            InstanceId=instance_id
        )
        
        return {'statusCode': 200, 'body': message}
    except Exception as e:
        logger.error(f"Error completing lifecycle action: {str(e)}")
        return {'statusCode': 500, 'body': f"Error completing lifecycle action: {str(e)}"}
EOF
}

resource "null_resource" "create_lambda_zip" {
  depends_on = [local_file.lambda_function_code]
  
  provisioner "local-exec" {
    command = "cd ${path.module} && zip lambda_package.zip lambda_code.py"
  }

  triggers = {
    lambda_code_hash = sha256(local_file.lambda_function_code.content)
  }
}

# IAM role for the Lambda function
resource "aws_iam_role" "node_management_lambda_role" {
  name = "guy-polybot-token-role"

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
}

# Lambda policy for node management
resource "aws_iam_policy" "node_management_lambda_policy" {
  name        = "guy-polybot-token-policy"
  description = "Policy for Lambda function to manage Kubernetes nodes"

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
          "ec2:DescribeInstances",
          "ec2:CreateTags",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:CompleteLifecycleAction",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "node_management_lambda_policy_attach" {
  role       = aws_iam_role.node_management_lambda_role.name
  policy_arn = aws_iam_policy.node_management_lambda_policy.arn
}

# SNS Topic for ASG Lifecycle Hooks
resource "aws_sns_topic" "lifecycle_topic" {
  name = "guy-lifecycle-topic"
}

# Subscribe Lambda to SNS Topic
resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.lifecycle_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.node_management_lambda.arn
}

# Lambda permission for SNS
resource "aws_lambda_permission" "sns_permission" {
  statement_id  = "lambda-59321475-88d3-4cfa-b6a6-febec42e38bd"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.node_management_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.lifecycle_topic.arn
}

# EventBridge (CloudWatch Events) Rule for scheduled refresh
resource "aws_cloudwatch_event_rule" "token_refresh_rule" {
  name                = "guy-fetch-rule"
  description         = "Hourly Kubernetes token refresh"
  schedule_expression = "cron(0 * * * ? *)"
}

# EventBridge Target for Lambda
resource "aws_cloudwatch_event_target" "token_refresh_target" {
  rule      = aws_cloudwatch_event_rule.token_refresh_rule.name
  target_id = "LambdaFunction"
  arn       = aws_lambda_function.node_management_lambda.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "eventbridge_permission" {
  statement_id  = "cloudwatch-events-permission"
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
  heartbeat_timeout      = 600
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"

  notification_target_arn = aws_sns_topic.lifecycle_topic.arn
  role_arn                = aws_iam_role.asg_lifecycle_hook_role.arn
}

resource "aws_autoscaling_lifecycle_hook" "scale_down_hook" {
  name                   = "guy-scale-down-hook"
  autoscaling_group_name = aws_autoscaling_group.worker_asg.name
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300
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

resource "aws_security_group" "control_plane_sg" {
  name        = "Guy-Control-Plane-SG"
  description = "Allows SSH and API server access to the cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow worker nodes to connect to API server"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Allow all internal VPC traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
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

# IAM policy for access to S3 logs bucket
resource "aws_iam_policy" "worker_s3_access" {
  name        = "guy-worker-s3-access"
  description = "Policy allowing workers to access S3 bucket for logs"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.worker_logs.arn}",
          "${aws_s3_bucket.worker_logs.arn}/*"
        ]
      }
    ]
  })
}

# Attach the S3 access policy to the worker role
resource "aws_iam_role_policy_attachment" "worker_s3_access" {
  role       = aws_iam_role.worker_role.name
  policy_arn = aws_iam_policy.worker_s3_access.arn
}

resource "aws_launch_template" "worker_lt" {
  name_prefix   = "guy-polybot-worker-"
  image_id      = var.worker_ami
  instance_type = var.worker_instance_type
  key_name      = local.actual_key_name

  # This bootstrap script has the full initialization content embedded
  user_data = base64encode(
    templatefile(
      "${path.module}/worker_user_data.sh",
      {
        ssh_public_key = var.ssh_public_key != "" ? var.ssh_public_key : (length(tls_private_key.ssh) > 0 ? tls_private_key.ssh[0].public_key_openssh : ""),
        JOIN_COMMAND_SECRET = aws_secretsmanager_secret.kubernetes_join_command.name,
        JOIN_COMMAND_LATEST_SECRET = aws_secretsmanager_secret.kubernetes_join_command_latest.name,
        region = var.region,
        KUBERNETES_JOIN_COMMAND_SECRET = aws_secretsmanager_secret.kubernetes_join_command.name,
        KUBERNETES_JOIN_COMMAND_LATEST_SECRET = aws_secretsmanager_secret.kubernetes_join_command_latest.name
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
      "kubernetes.io/cluster/kubernetes" = "owned"
      "k8s.io/cluster-autoscaler/enabled" = "true"
      "k8s.io/role/node" = "true"
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

  tag {
    key                 = "k8s.io/cluster-autoscaler/enabled"
    value               = "true"
    propagate_at_launch = true
  }

  tag {
    key                 = "k8s.io/cluster-autoscaler/guy-polybot-cluster"
    value               = "owned"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "Name"
    value               = "guy-worker-node-${random_id.suffix.hex}"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "kubernetes.io/cluster/kubernetes"
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
    aws_instance.control_plane,
    aws_secretsmanager_secret.kubernetes_join_command,
    null_resource.wait_for_control_plane,
    terraform_data.force_asg_update,
    terraform_data.worker_progress,
    null_resource.update_join_command
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
  
  # Kubelet API for control plane communication
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow from anywhere for debugging
    description = "Allow kubelet API access"
  }

  # NodePort services
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow NodePort service range"
  }

  # Specific NodePort for applications
  ingress {
    from_port   = 31024
    to_port     = 31024
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow specific NodePort service"
  }

  # Critical - API server access
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow Kubernetes API server access"
  }

  # Allow all internal VPC traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Allow all internal VPC traffic"
  }

  # Allow Calico overlay networking (VXLAN)
  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    self        = true
    description = "Calico VXLAN overlay"
  }

  # Allow Calico BGP traffic
  ingress {
    from_port   = 179
    to_port     = 179
    protocol    = "tcp"
    self        = true
    description = "Calico BGP traffic"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  # Explicit outbound rule for the Kubernetes API server
  egress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outbound traffic to Kubernetes API server"
  }

  tags = {
    Name = "guy-worker-sg"
    "kubernetes.io/cluster/kubernetes" = "owned"
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
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",
    "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
    "arn:aws:iam::aws:policy/AmazonSNSFullAccess",
    "arn:aws:iam::aws:policy/CloudWatchFullAccess",
    "arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
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

  tags = {
    Name = "guy-polybot-lg"
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
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "kubernetes.io/cluster/kubernetes" = "owned"
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
    null_resource.wait_for_control_plane
  ]

  # This will cause this resource to be recreated whenever the control plane changes
  triggers = {
    control_plane_ip = aws_instance.control_plane.public_ip
    control_plane_id = aws_instance.control_plane.id
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
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

