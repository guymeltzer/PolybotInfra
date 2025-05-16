variable "git_repo_url" {
  description = "URL of the Git repository containing the application manifests"
  type        = string
  default     = "https://github.com/guymeltzer/PolybotInfra.git"
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file"
  type        = string
  default     = "~/.kube/config"
} 