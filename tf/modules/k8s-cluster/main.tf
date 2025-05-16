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
          "secretsmanager:UpdateSecret"
        ]
        Resource = "arn:aws:secretsmanager:${var.region}:*:secret:kubernetes-join-command-*"
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

resource "aws_instance" "control_plane" {
  ami                    = var.control_plane_ami
  instance_type          = "t3.medium"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.control_plane_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.control_plane_profile.name
  key_name               = var.key_name != "" ? var.key_name : null

  user_data = base64encode(file("${path.module}/control_plane_user_data.sh"))

  tags = {
    Name                         = "guy-control-plane"
    "kubernetes.io/role"         = "control-plane"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }

  # Create directory for Kubernetes certificates
  provisioner "local-exec" {
    command = "mkdir -p ${path.module}/certs"
  }

  # Copy certificates from control plane after setup
  provisioner "local-exec" {
    command = <<-EOT
      # Wait for the Kubernetes API to be available
      sleep 300
      
      # Get certificates using SSH (using AWS Systems Manager for security)
      aws ssm send-command \
        --instance-ids ${self.id} \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["sudo cat /etc/kubernetes/pki/ca.crt"] \
        --output text > ${path.module}/certs/ca.crt

      aws ssm send-command \
        --instance-ids ${self.id} \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["sudo cat /etc/kubernetes/pki/apiserver-kubelet-client.crt"] \
        --output text > ${path.module}/certs/client.crt

      aws ssm send-command \
        --instance-ids ${self.id} \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["sudo cat /etc/kubernetes/pki/apiserver-kubelet-client.key"] \
        --output text > ${path.module}/certs/client.key
    EOT
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

# IAM Instance Profile for Worker Nodes
resource "aws_iam_instance_profile" "worker_profile" {
  name = "Guy-K8S-Worker-Profile"
  role = aws_iam_role.worker_role.name
}

resource "aws_launch_template" "worker_lt" {
  name_prefix   = "guy-polybot-worker-"
  image_id      = var.worker_ami
  instance_type = "t3.medium"

  network_interfaces {
    subnet_id       = module.vpc.public_subnets[0]
    security_groups = [aws_security_group.worker_sg.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.worker_profile.name
  }

  user_data = base64encode(file("${path.module}/worker_user_data.sh"))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name                         = "guy-worker-node"
      "kubernetes.io/cluster/kubernetes" = "owned"
    }
  }
}

resource "aws_autoscaling_group" "worker_asg" {
  name                = "guy-polybot-asg"
  max_size            = 3
  min_size            = 1
  desired_capacity    = 2
  vpc_zone_identifier = module.vpc.public_subnets
  target_group_arns   = [aws_lb_target_group.http_tg.arn, aws_lb_target_group.https_tg.arn]

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
}

resource "aws_security_group" "worker_sg" {
  name        = "Guy-WorkerNodes-SG"
  description = "Allows all traffic to the VPC"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 31024
    to_port     = 31024
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    security_groups = [aws_security_group.control_plane_sg.id]
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
  }

  tags = {
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

resource "aws_iam_role" "worker_role" {
  name = "Guy-K8S-WorkerNode-Role-${formatdate("YYYYMMDDhhmmss", timestamp())}"

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
resource "aws_iam_role_policy" "worker_secrets_ec2_policy" {
  name = "SecretsManagerAndEC2TagsAccess"
  role = aws_iam_role.worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "ec2:CreateTags"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.region}:*:secret:kubernetes-join-command-*",
          "arn:aws:ec2:${var.region}:*:instance/*"
        ]
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
          "ec2:DescribeTags"
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
        Action = "secretsmanager:GetSecretValue"
        Resource = "*"
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
}

resource "aws_lb_target_group" "https_tg" {
  name        = "guy-polybot-https-tg"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance"
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.polybot_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

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

# Generate kubeconfig file locally
resource "local_file" "kubeconfig" {
  depends_on = [aws_instance.control_plane]
  content = templatefile("${path.module}/kubeconfig_template.tpl", {
    cluster_name    = var.cluster_name
    control_plane_ip = aws_instance.control_plane.public_ip
    client_certificate = fileexists("${path.module}/certs/client.crt") ? file("${path.module}/certs/client.crt") : ""
    client_key        = fileexists("${path.module}/certs/client.key") ? file("${path.module}/certs/client.key") : ""
    ca_certificate    = fileexists("${path.module}/certs/ca.crt") ? file("${path.module}/certs/ca.crt") : ""
  })
  filename = "${path.module}/kubeconfig.yaml"
}

# Upload kubeconfig to S3 for CI/CD
resource "aws_s3_object" "kubeconfig" {
  depends_on = [local_file.kubeconfig]
  bucket     = "polybot-tfstate-bucket"
  key        = "kubeconfig/config"
  source     = "${path.module}/kubeconfig.yaml"
}

# Secrets Manager for Kubernetes join command
resource "aws_secretsmanager_secret" "kubernetes_join_command" {
  name        = "kubernetes-join-command-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  description = "Kubernetes join command for worker nodes"
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

def lambda_handler(event, context):
    autoscaling = boto3.client('autoscaling')
    ssm_client = boto3.client('ssm')
    secrets_client = boto3.client('secretsmanager')
    region = '${var.region}'
    control_plane_instance_id = '${aws_instance.control_plane.id}'
    
    print(f"Event received: {json.dumps(event)}")
    
    if 'Records' in event and event['Records'][0]['EventSource'] == 'aws:sns':
        print("SNS event detected")
        message = json.loads(event['Records'][0]['Sns']['Message'])
        print(f"SNS message: {message}")
        if message.get('LifecycleTransition') == 'autoscaling:EC2_INSTANCE_TERMINATING':
            print("Processing scale-down event")
            instance_id = message['EC2InstanceId']
            lifecycle_hook_name = message['LifecycleHookName']
            asg_name = message['AutoScalingGroupName']
            
            try:
                ec2_client = boto3.client('ec2', region_name=region)
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                tags = response['Reservations'][0]['Instances'][0]['Tags']
                private_ip = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
                node_name = next((tag['Value'] for tag in tags if tag['Key'] == 'Name'), f"node/{private_ip}")
                print(f"Draining node: {node_name}")
                
                # Drain and delete the node
                drain_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf drain --ignore-daemonsets --delete-emptydir-data --force {node_name}"
                delete_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf delete node {node_name}"
                
                # Execute drain command
                response = ssm_client.send_command(
                    InstanceIds=[control_plane_instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': [drain_command]},
                    TimeoutSeconds=300
                )
                
                command_id = response['Command']['CommandId']
                max_attempts = 60
                attempt = 0
                while attempt < max_attempts:
                    time.sleep(2)
                    command_output = ssm_client.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=control_plane_instance_id
                    )
                    if command_output['Status'] in ['Success', 'Completed']:
                        print("Node drained successfully")
                        break
                    elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                        raise Exception(f"Drain failed: {command_output.get('StandardErrorContent', 'Unknown error')}")
                    attempt += 1
                else:
                    print("Drain command still running; proceeding with termination")
                
                # Execute delete command
                response = ssm_client.send_command(
                    InstanceIds=[control_plane_instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': [delete_command]},
                    TimeoutSeconds=300
                )
                
                command_id = response['Command']['CommandId']
                max_attempts = 60
                attempt = 0
                while attempt < max_attempts:
                    time.sleep(2)
                    command_output = ssm_client.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=control_plane_instance_id
                    )
                    if command_output['Status'] in ['Success', 'Completed']:
                        print("Node deleted successfully")
                        break
                    elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                        raise Exception(f"Delete failed: {command_output.get('StandardErrorContent', 'Unknown error')}")
                    attempt += 1
                else:
                    print("Delete command still running; proceeding with termination")
                
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionResult='CONTINUE',
                    InstanceId=instance_id
                )
                return {'statusCode': 200, 'body': 'Node drained, deleted, and termination completed'}
            except Exception as e:
                print(f"Error: {str(e)}")
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionResult='ABANDON',
                    InstanceId=instance_id
                )
                return {'statusCode': 500, 'body': f"Error: {str(e)}"}
    
    print("Running join command refresh logic")
    try:
        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': ['kubeadm token create --print-join-command']}
        )
        command_id = response['Command']['CommandId']
        max_attempts = 15
        attempt = 0
        while attempt < max_attempts:
            time.sleep(2)
            command_output = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=control_plane_instance_id
            )
            if command_output['Status'] in ['Success', 'Completed']:
                join_command = command_output['StandardOutputContent'].strip()
                print(f"Join command updated: {join_command}")
                break
            elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                error = command_output.get('StandardErrorContent', 'Unknown error')
                raise Exception(f"SSM command failed: {error}")
            attempt += 1
        else:
            raise Exception("SSM command did not complete within 30 seconds")
        
        secrets_client.put_secret_value(
            SecretId='kubernetes-join-command',
            SecretString=join_command
        )
        return {'statusCode': 200, 'body': 'Join command updated successfully'}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': f"Error: {str(e)}"}
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
          "secretsmanager:PutSecretValue"
        ]
        Resource = aws_secretsmanager_secret.kubernetes_join_command.arn
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
  heartbeat_timeout      = 600
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

