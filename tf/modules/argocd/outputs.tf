output "argocd_url" {
  description = "The URL of the ArgoCD server"
  value       = "https://argocd-server.argocd:443"
}

output "applications" {
  description = "List of deployed ArgoCD applications"
  value = {
    dev = [
      yamldecode(kubectl_manifest.polybot_application_dev.yaml_body).metadata.name,
      yamldecode(kubectl_manifest.yolo5_application_dev.yaml_body).metadata.name,
      yamldecode(kubectl_manifest.mongodb_application_dev.yaml_body).metadata.name
    ],
    prod = [
      yamldecode(kubectl_manifest.polybot_application_prod.yaml_body).metadata.name,
      yamldecode(kubectl_manifest.yolo5_application_prod.yaml_body).metadata.name,
      yamldecode(kubectl_manifest.mongodb_application_prod.yaml_body).metadata.name
    ]
  }
} 