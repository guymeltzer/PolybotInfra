variable "enable_resources" {
  description = "Whether to enable creation of Kubernetes resources"
  type        = bool
  default     = true
}

variable "skip_mongodb" {
  description = "Whether to skip MongoDB deployment"
  type        = bool
  default     = false
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file"
  type        = string
}

variable "module_path" {
  description = "Path to the module directory"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key to use"
  type        = string
  default     = ""
}

variable "kubernetes_dependency" {
  description = "Resource dependency for Kubernetes readiness"
  type        = any
  default     = null
}

variable "ebs_csi_dependency" {
  description = "Resource dependency for EBS CSI driver readiness"
  type        = any
  default     = null
}

variable "kubeconfig_trigger_id" {
  description = "ID to use as a trigger for kubeconfig changes"
  type        = string
}

variable "control_plane_id" {
  description = "ID of the control plane instance"
  type        = string
  default     = "none"
}

variable "region" {
  description = "AWS region"
  type        = string
} 