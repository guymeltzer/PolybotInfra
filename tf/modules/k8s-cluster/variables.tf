variable "region" {
  description = "AWS region"
  type        = string
}

variable "cluster_name" {
  description = "Name of the Kubernetes cluster"
  type        = string
  default     = "polybot-cluster"
}

variable "vpc_id" {
  description = "ID of the VPC where resources will be created"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for the Kubernetes cluster"
  type        = list(string)
  default     = []
}

variable "control_plane_instance_type" {
  description = "Instance type for the control plane node"
  type        = string
  default     = "t3.medium"
}

variable "worker_instance_type" {
  description = "Instance type for worker nodes"
  type        = string
  default     = "t3.medium"
}

variable "worker_count" {
  description = "Number of worker nodes to create"
  type        = number
  default     = 2
}

variable "control_plane_ami" {
  description = "AMI ID for control plane node"
  type        = string
}

variable "worker_ami" {
  description = "AMI ID for worker nodes"
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 zone ID for DNS records"
  type        = string
}

variable "key_name" {
  description = "SSH key name for EC2 instances"
  type        = string
  default     = ""
}

variable "addons" {
  description = "List of URLs to Kubernetes add-on manifests to apply"
  type        = list(string)
  default     = []
}

variable "rebuild_workers" {
  description = "Flag to trigger rebuild of worker nodes"
  type        = bool
  default     = false
}

variable "rebuild_control_plane" {
  description = "Flag to trigger rebuild of the control plane instance"
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "EC2 instance type for the cluster nodes"
  type        = string
  default     = "t3.medium"
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

variable "ssh_public_key" {
  description = "The SSH public key content to be installed on instances"
  type        = string
  default     = ""
  sensitive   = true
}

variable "skip_api_verification" {
  description = "Skip API server verification (true/false)"
  type        = bool
  default     = false
}

variable "skip_token_verification" {
  description = "Skip join token verification (true/false)"
  type        = bool
  default     = false
}

variable "verification_max_attempts" {
  description = "Maximum number of attempts for control plane verification"
  type        = number
  default     = 20
}

variable "verification_wait_seconds" {
  description = "Seconds to wait between verification attempts"
  type        = number
  default     = 30
}

variable "pod_cidr" {
  description = "CIDR block for Kubernetes pod network"
  type        = string
  default     = "10.244.0.0/16"
}