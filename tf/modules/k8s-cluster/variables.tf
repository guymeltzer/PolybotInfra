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
  description = "Set to true to force rebuilding worker nodes"
  type        = bool
  default     = false
}