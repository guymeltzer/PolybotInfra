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
  
  # Token suffix for hostname generation
  token_suffix_for_template = random_string.token_part1.result

  # === Updated Kubernetes & CRI-O Versioning for ~May 2025 ===
  # Targeting Kubernetes v1.31.x
  k8s_version_full_for_template    = "1.31.9"
  k8s_major_minor_for_template     = join(".", slice(split(".", "1.31.9"), 0, 2)) # This will be "1.31"
  k8s_package_version_for_template = "1.31.9-1.1" # e.g., "1.31.0-00"

  # CRI-O versioning aligns with Kubernetes major.minor
  crio_k8s_major_minor_for_template  = join(".", slice(split(".", "1.31.9"), 0, 2)) # This will be "1.31"

  # Determine pod CIDR for the cluster
  pod_cidr = var.pod_cidr
  
  # Use provided key name if set, otherwise use the auto-generated key
  actual_key_name = var.key_name != "" ? var.key_name : (length(aws_key_pair.generated_key) > 0 ? aws_key_pair.generated_key[0].key_name : "polybot-key")
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

# Resource to clean up existing ASG if it exists
resource "null_resource" "cleanup_existing_asg" {
  # Run when manually forced OR when health assessment determines it's needed
  count = var.force_cleanup_asg || (
    fileexists("/tmp/asg_cleanup_needed.txt") ? 
    (file("/tmp/asg_cleanup_needed.txt") == "true\n" || file("/tmp/asg_cleanup_needed.txt") == "true") : 
    false
  ) ? 1 : 0

  triggers = {
    asg_name = "guy-polybot-asg"
    # Trigger on manual force or health assessment
    force_cleanup = var.force_cleanup_asg
    health_assessment = try(terraform_data.cluster_health_assessment.id, "no-assessment")
    # Include health status to trigger cleanup when assessment changes
    health_status = fileexists("/tmp/cluster_health_status.txt") ? file("/tmp/cluster_health_status.txt") : "unknown"
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      #!/bin/bash
      ASG_NAME="guy-polybot-asg"
      
      # Determine cleanup reason
      MANUAL_FORCE="${var.force_cleanup_asg}"
      AUTO_CLEANUP="false"
      HEALTH_STATUS="unknown"
      
      if [[ -f "/tmp/asg_cleanup_needed.txt" ]]; then
        AUTO_CLEANUP=$(cat /tmp/asg_cleanup_needed.txt)
      fi
      
      if [[ -f "/tmp/cluster_health_status.txt" ]]; then
        HEALTH_STATUS=$(cat /tmp/cluster_health_status.txt)
      fi
      
      echo "🔍 ASG CLEANUP INITIATED"
      echo "========================"
      if [[ "$MANUAL_FORCE" == "true" ]]; then
        echo "🔧 REASON: Manual force cleanup (force_cleanup_asg=true)"
        echo "⚠️  WARNING: This will delete and recreate the ASG, causing worker node replacement!"
      elif [[ "$AUTO_CLEANUP" == "true" ]]; then
        echo "🤖 REASON: Automatic cleanup triggered by health assessment"
        echo "📊 Health status: $HEALTH_STATUS"
        echo "🎯 This will clean up problematic worker nodes and recreate the ASG"
      else
        echo "ℹ️  REASON: Unknown trigger condition"
      fi
      echo ""
      
      # Check if ASG exists
      if aws autoscaling describe-auto-scaling-groups \
         --region ${var.region} \
         --auto-scaling-group-names "$ASG_NAME" \
         --query "AutoScalingGroups[0].AutoScalingGroupName" \
         --output text 2>/dev/null | grep -q "$ASG_NAME"; then
        
        echo "⚠️  Found existing ASG: $ASG_NAME. Deleting it..."
        
        # First, set desired capacity to 0 to gracefully terminate instances
        echo "📉 Setting desired capacity to 0 for graceful shutdown..."
        aws autoscaling update-auto-scaling-group \
          --region ${var.region} \
          --auto-scaling-group-name "$ASG_NAME" \
          --desired-capacity 0 \
          --min-size 0 || echo "Failed to update capacity, continuing..."
        
        # Wait longer for graceful shutdown
        echo "⏳ Waiting 120 seconds for instances to gracefully terminate..."
        sleep 120
        
        # Delete the ASG
        echo "🗑️  Deleting Auto Scaling Group: $ASG_NAME"
        aws autoscaling delete-auto-scaling-group \
          --region ${var.region} \
          --auto-scaling-group-name "$ASG_NAME" \
          --force-delete || echo "Failed to delete ASG, it may not exist"
        
        # Wait for deletion to complete
        echo "⏳ Waiting for ASG deletion to complete..."
        for attempt in {1..30}; do
          if ! aws autoscaling describe-auto-scaling-groups \
             --region ${var.region} \
             --auto-scaling-group-names "$ASG_NAME" \
             --query "AutoScalingGroups[0].AutoScalingGroupName" \
             --output text 2>/dev/null | grep -q "$ASG_NAME"; then
            echo "✅ ASG successfully deleted"
            break
          fi
          echo "Still waiting for ASG deletion... (attempt $attempt/30)"
          sleep 10
        done
      else
        echo "✅ No existing ASG found with name: $ASG_NAME"
      fi
      
      echo "🎯 ASG cleanup completed. New ASG will be created shortly."
      
      # Clear the health assessment flags after successful cleanup
      rm -f /tmp/asg_cleanup_needed.txt /tmp/cluster_health_status.txt
      echo "🧹 Cleared health assessment flags"
    EOT
  }

  depends_on = [terraform_data.cluster_health_assessment]
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

# Generate SSH key pair if one isn't provided
resource "tls_private_key" "ssh" {
  count     = var.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "polybot-key"
  public_key = tls_private_key.ssh[0].public_key_openssh
}

resource "local_file" "ssh_private_key" {
  count    = var.key_name == "" ? 1 : 0
  content  = tls_private_key.ssh[0].private_key_pem
  filename = "${path.module}/polybot-key.pem"
  file_permission = "0600"
}

# IAM Role for Worker Nodes
resource "aws_iam_role" "worker_role" {
  name = "Guy-K8S-Worker-IAM-Role"

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

# IAM Policy Attachments for Worker Nodes
resource "aws_iam_role_policy_attachment" "worker_node_policy" {
  role       = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "worker_cni_policy" {
  role       = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "worker_registry_policy" {
  role       = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "worker_ssm_policy" {
  role       = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "worker_ebs_csi_policy" {
  role       = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# Security Group for Worker Nodes
resource "aws_security_group" "worker_sg" {
  name        = "Guy-Worker-SG"
  description = "Security group for Kubernetes worker nodes"
  vpc_id      = module.vpc.vpc_id

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
    cidr_blocks = ["10.0.0.0/16"]
    description = "All traffic from VPC"
  }

  ingress {
    from_port   = 1025
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Node ports"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP traffic"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "guy-worker-sg"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# Application Load Balancer
resource "aws_lb" "polybot_alb" {
  name               = "guy-polybot-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = false

  tags = {
    Name = "guy-polybot-alb"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# Security Group for ALB
resource "aws_security_group" "alb_sg" {
  name        = "Guy-ALB-SG"
  description = "Security group for Application Load Balancer"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP traffic"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "guy-alb-sg"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# Target Group for HTTP traffic
resource "aws_lb_target_group" "http_tg" {
  name     = "guy-http-tg"
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

  tags = {
    Name = "guy-http-tg"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# Target Group for HTTPS traffic
resource "aws_lb_target_group" "https_tg" {
  name     = "guy-https-tg"
  port     = 443
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

  tags = {
    Name = "guy-https-tg"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# ALB Listener for HTTP
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http_tg.arn
  }
}

# ALB Listener for HTTPS
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = "443"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https_tg.arn
  }
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
      TOKEN_SUFFIX      = local.token_suffix_for_template,
      K8S_VERSION_FULL  = local.k8s_version_full_for_template,
      K8S_PACKAGE_VERSION = local.k8s_package_version_for_template,
      K8S_MAJOR_MINOR   = local.k8s_major_minor_for_template,
      CRIO_K8S_MAJOR_MINOR = local.crio_k8s_major_minor_for_template,
      JOIN_COMMAND_SECRET = aws_secretsmanager_secret.kubernetes_join_command.name,
      JOIN_COMMAND_LATEST_SECRET = aws_secretsmanager_secret.kubernetes_join_command_latest.name,
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

# Terraform data resource to track ASG state
resource "terraform_data" "asg_state_tracker" {
  input = {
    cleanup_completed = (
      var.force_cleanup_asg || (
        fileexists("/tmp/asg_cleanup_needed.txt") ? 
        (file("/tmp/asg_cleanup_needed.txt") == "true\n" || file("/tmp/asg_cleanup_needed.txt") == "true") : 
        false
      )
    ) ? (
      length(null_resource.cleanup_existing_asg) > 0 ? 
      null_resource.cleanup_existing_asg[0].id : "no-cleanup"
    ) : "no-cleanup"
  }
  
  lifecycle {
    replace_triggered_by = [
      # Only replace when cleanup actually runs
    ]
  }
}

resource "aws_autoscaling_group" "worker_asg" {
  name                = "guy-polybot-asg"
  max_size            = 3
  min_size            = 1
  desired_capacity    = var.desired_worker_nodes
  vpc_zone_identifier = module.vpc.public_subnets
  target_group_arns   = [aws_lb_target_group.http_tg.arn, aws_lb_target_group.https_tg.arn]
  health_check_type   = "EC2"
  health_check_grace_period = 60   # Reduced from 300 to 60 seconds
  default_cooldown    = 60         # Reduced from 300 to 60 seconds
  
  # Optimize termination policies for faster scale-down
  termination_policies = ["NewestInstance", "Default"]
  
  # Enable faster instance refresh
  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances"
  ]
  
  launch_template {
    id      = aws_launch_template.worker_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "k8s.io-cluster-autoscaler-enabled"
    value               = "true"
    propagate_at_launch = true
  }

  tag {
    key                 = "k8s.io-cluster-autoscaler-guy-polybot-cluster"
    value               = "owned"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "Name"
    value               = "guy-worker-node-${random_id.suffix.hex}"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "kubernetes-io-cluster-kubernetes"
    value               = "owned"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "k8s.io-role-node"
    value               = "true"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "ClusterIdentifier" 
    value               = "${var.cluster_name}-${random_id.suffix.hex}"
    propagate_at_launch = true
  }
  
  depends_on = [
    # Only depend on cleanup if it's enabled
    terraform_data.asg_state_tracker,   # Add state tracker dependency
    aws_instance.control_plane,
    aws_secretsmanager_secret.kubernetes_join_command,
    null_resource.wait_for_control_plane,
    null_resource.verify_cluster_readiness,  # Add cluster readiness dependency
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
      launch_template[0].version,
      # Ignore tag changes if ASG is being recreated
      tag,
    ]
    
    # Create before destroy to handle recreation
    create_before_destroy = true
  }

  # Report progress after ASG is created
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = "echo -e \"\\033[0;32m✅ Worker node Auto Scaling Group '${var.cluster_name}-worker-asg' created!\\033[0m\""
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
        
        return True
    except Exception as e:
        logger.error(f"Error updating secrets: {str(e)}")
        raise
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
        K8S_PACKAGE_VERSION_TO_INSTALL = local.k8s_package_version_for_template,
        K8S_MAJOR_MINOR_FOR_REPO = local.k8s_major_minor_for_template,
        CRIO_K8S_MAJOR_MINOR_FOR_REPO = local.crio_k8s_major_minor_for_template,
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

# Enhanced cluster readiness check to verify taint resolution
resource "null_resource" "verify_cluster_readiness" {
  depends_on = [
    aws_instance.control_plane,
    null_resource.wait_for_control_plane
  ]

  triggers = {
    control_plane_id = aws_instance.control_plane.id
    control_plane_public_ip = aws_instance.control_plane.public_ip
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOT
      #!/bin/bash
      
      echo "🔍 Verifying cluster readiness and cloud provider taint resolution..."
      
      CONTROL_PLANE_IP="${aws_instance.control_plane.public_ip}"
      CONTROL_PLANE_ID="${aws_instance.control_plane.id}"
      MAX_WAIT_TIME=900  # 15 minutes
      SLEEP_INTERVAL=30
      WAITED=0
      
      # Function to check cluster via SSM
      check_cluster_via_ssm() {
        echo "📡 Checking cluster status via SSM..."
        
        # Check if SSM is available
        if ! aws ssm describe-instance-information --region ${var.region} \
           --filters "Key=InstanceIds,Values=$CONTROL_PLANE_ID" \
           --query "InstanceInformationList[*].PingStatus" --output text | grep -q "Online"; then
          echo "❌ SSM not available on control plane"
          return 1
        fi
        
        # Get cluster status
        COMMAND_ID=$(aws ssm send-command --region ${var.region} \
          --document-name "AWS-RunShellScript" \
          --instance-ids "$CONTROL_PLANE_ID" \
          --parameters 'commands=["export KUBECONFIG=/etc/kubernetes/admin.conf && echo \"=== NODE STATUS ===\" && kubectl get nodes -o wide && echo \"\" && echo \"=== SYSTEM PODS ===\" && kubectl get pods -n kube-system -o wide && echo \"\" && echo \"=== CLOUD PROVIDER TAINT CHECK ===\" && kubectl get nodes -o json | jq -r \".items[].spec.taints[]? | select(.key == \\\"node.cloudprovider.kubernetes.io/uninitialized\\\") | .key\" || echo \"No cloud provider taint found\" && echo \"\" && echo \"=== PENDING PODS ===\" && kubectl get pods -A --field-selector=status.phase=Pending | head -10"]' \
          --output text --query "Command.CommandId" 2>/dev/null)
        
        if [ -z "$COMMAND_ID" ]; then
          echo "❌ Failed to send SSM command"
          return 1
        fi
        
        sleep 10
        
        # Get command output
        CLUSTER_STATUS=$(aws ssm get-command-invocation --region ${var.region} \
          --command-id "$COMMAND_ID" --instance-id "$CONTROL_PLANE_ID" \
          --query "StandardOutputContent" --output text 2>/dev/null)
        
        if [ -z "$CLUSTER_STATUS" ]; then
          echo "❌ Failed to get cluster status"
          return 1
        fi
        
        echo "📊 Cluster Status:"
        echo "$CLUSTER_STATUS"
        echo ""
        
        # Analyze the status
        local ready_nodes=$(echo "$CLUSTER_STATUS" | grep -c " Ready " || echo "0")
        local running_coredns=$(echo "$CLUSTER_STATUS" | grep "coredns" | grep -c "Running" || echo "0")
        local running_calico_controllers=$(echo "$CLUSTER_STATUS" | grep "calico-kube-controllers" | grep -c "Running" || echo "0")
        local cloud_taint=$(echo "$CLUSTER_STATUS" | grep "node.cloudprovider.kubernetes.io/uninitialized" || echo "")
        local pending_pods=$(echo "$CLUSTER_STATUS" | grep "Pending" | wc -l || echo "0")
        
        echo "📈 Analysis:"
        echo "  Ready nodes: $ready_nodes"
        echo "  CoreDNS running: $running_coredns"
        echo "  Calico controllers running: $running_calico_controllers"
        echo "  Cloud provider taint: $${cloud_taint:-"Not found (good!)"}"
        echo "  Pending pods: $pending_pods"
        
        # Check if cluster is ready
        if [ "$ready_nodes" -ge 1 ] && [ "$running_coredns" -ge 1 ] && [ "$running_calico_controllers" -ge 1 ] && [ -z "$cloud_taint" ]; then
          echo "✅ Cluster is ready! System pods are running and cloud provider taint is resolved."
          return 0
        else
          echo "⏳ Cluster not ready yet..."
          if [ -n "$cloud_taint" ]; then
            echo "⚠️  Cloud provider taint still present: $cloud_taint"
          fi
          return 1
        fi
      }
      
      # Wait for cluster to be ready
      echo "⏳ Waiting up to $MAX_WAIT_TIME seconds for cluster to be ready..."
      
      while [ $WAITED -lt $MAX_WAIT_TIME ]; do
        echo "🔄 Check $((WAITED / SLEEP_INTERVAL + 1)) - Time elapsed: ${WAITED}s"
        
        if check_cluster_via_ssm; then
          echo ""
          echo "🎉 SUCCESS: Cluster is ready and cloud provider taint issue is resolved!"
          echo "🎯 You can now proceed with worker node deployment and ArgoCD installation."
          exit 0
        fi
        
        sleep $SLEEP_INTERVAL
        WAITED=$((WAITED + SLEEP_INTERVAL))
        
        if [ $WAITED -lt $MAX_WAIT_TIME ]; then
          echo "⏳ Retrying in $SLEEP_INTERVAL seconds... ($((MAX_WAIT_TIME - WAITED))s remaining)"
        fi
      done
      
      echo ""
      echo "❌ TIMEOUT: Cluster did not become ready within $MAX_WAIT_TIME seconds"
      echo ""
      echo "🔧 Troubleshooting suggestions:"
      echo "1. Check cloud provider taint manager logs:"
      echo "   ssh -i ${local.actual_key_name}.pem ubuntu@$CONTROL_PLANE_IP"
      echo "   sudo journalctl -u cloud-provider-taint-manager.service -f"
      echo ""
      echo "2. Check cloud provider taint manager script logs:"
      echo "   ssh -i ${local.actual_key_name}.pem ubuntu@$CONTROL_PLANE_IP"
      echo "   sudo tail -f /var/log/cloud-provider-taint-manager.log"
      echo ""
      echo "3. Manual taint removal if needed:"
      echo "   ssh -i ${local.actual_key_name}.pem ubuntu@$CONTROL_PLANE_IP"
      echo "   sudo kubectl taint node --all node.cloudprovider.kubernetes.io/uninitialized:NoSchedule-"
      echo "   sudo kubectl taint node --all node.cloudprovider.kubernetes.io/uninitialized:NoExecute-"
      echo ""
      echo "4. Check system pod status:"
      echo "   ssh -i ${local.actual_key_name}.pem ubuntu@$CONTROL_PLANE_IP"
      echo "   sudo kubectl get pods -n kube-system -o wide"
      echo "   sudo kubectl describe pod -n kube-system <pod-name>"
      echo ""
      
      # Don't fail the entire deployment, just warn
      echo "⚠️  Continuing deployment despite readiness check timeout..."
      echo "💡 You may need to manually resolve the cloud provider taint issue."
      
      exit 0
    EOT
  }
}

