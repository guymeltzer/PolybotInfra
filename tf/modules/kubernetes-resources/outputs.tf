output "storage_classes_id" {
  description = "ID of the storage classes resource"
  value       = try(null_resource.create_storage_classes[0].id, "")
}

output "disk_cleanup_id" {
  description = "ID of the disk cleanup resource"
  value       = try(null_resource.improved_disk_cleanup[0].id, "")
}

output "mongodb_id" {
  description = "ID of the MongoDB deployment resource"
  value       = try(null_resource.deploy_mongodb[0].id, "")
}

output "init_environment_id" {
  description = "ID of the environment initialization resource"
  value       = try(terraform_data.init_environment[0].id, "")
}

output "kubectl_provider_id" {
  description = "ID of the kubectl provider configuration resource"
  value       = try(terraform_data.kubectl_provider_config[0].id, "")
}

output "providers_ready_id" {
  description = "ID of the providers ready check resource"
  value       = try(null_resource.providers_ready[0].id, "")
} 