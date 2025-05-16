output "argocd_url" {
  description = "The URL of the ArgoCD server"
  value       = "https://${kubernetes_namespace.argocd.metadata[0].name}-server.${kubernetes_namespace.argocd.metadata[0].name}:443"
}

output "applications" {
  description = "List of deployed ArgoCD applications"
  value = {
    dev = [
      kubernetes_manifest.polybot_application_dev.manifest.metadata.name,
      kubernetes_manifest.yolo5_application_dev.manifest.metadata.name,
      kubernetes_manifest.mongodb_application_dev.manifest.metadata.name
    ],
    prod = [
      kubernetes_manifest.polybot_application_prod.manifest.metadata.name,
      kubernetes_manifest.yolo5_application_prod.manifest.metadata.name,
      kubernetes_manifest.mongodb_application_prod.manifest.metadata.name
    ]
  }
} 