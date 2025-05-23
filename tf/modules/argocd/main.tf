terraform {
  required_providers {
    kubernetes = {
      source                = "hashicorp/kubernetes"
      configuration_aliases = [kubernetes]
    }
    helm = {
      source                = "hashicorp/helm"
      configuration_aliases = [helm]
    }
    kubectl = {
      source                = "gavinbunney/kubectl"
      configuration_aliases = [kubectl]
    }
  }
}

# The argocd namespace is now created in the parent module using kubectl directly
# resource "kubernetes_namespace" "argocd" {
#   metadata {
#     name = "argocd"
#   }
# }

resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  namespace  = "argocd" # Use string directly instead of referencing the removed resource
  version    = "5.51.4" # Specify a stable version

  values = [
    <<-EOT
    server:
      extraArgs:
        - --insecure
      service:
        type: LoadBalancer
    configs:
      secret:
        createSecret: true
    EOT
  ]

  wait            = false # Don't wait for all resources to be ready
  timeout         = 300   # 5 minutes timeout
  atomic          = false # Don't use atomic deployment to avoid failures
  cleanup_on_fail = true
}

# Wait for ArgoCD to be ready before creating applications
resource "time_sleep" "wait_for_argocd" {
  depends_on      = [helm_release.argocd]
  create_duration = "60s"
}

# Remove namespace resources since they are managed by the parent module
# This avoids conflicts when trying to create the same namespace twice

# Create ArgoCD application resources for each service in dev environment
resource "kubectl_manifest" "polybot_application_dev" {
  depends_on = [time_sleep.wait_for_argocd]
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "polybot-dev"
      namespace = "argocd"
    }
    spec = {
      destination = {
        namespace = "dev"
        server    = "https://kubernetes.default.svc"
      }
      project = "default"
      source = {
        path           = "k8s/Polybot"
        repoURL        = var.git_repo_url
        targetRevision = "HEAD"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
      }
    }
  })
}

resource "kubectl_manifest" "yolo5_application_dev" {
  depends_on = [time_sleep.wait_for_argocd]
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "yolo5-dev"
      namespace = "argocd"
    }
    spec = {
      destination = {
        namespace = "dev"
        server    = "https://kubernetes.default.svc"
      }
      project = "default"
      source = {
        path           = "k8s/Yolo5"
        repoURL        = var.git_repo_url
        targetRevision = "HEAD"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
      }
    }
  })
}

resource "kubectl_manifest" "mongodb_application_dev" {
  depends_on = [time_sleep.wait_for_argocd]
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "mongodb-dev"
      namespace = "argocd"
    }
    spec = {
      destination = {
        namespace = "dev"
        server    = "https://kubernetes.default.svc"
      }
      project = "default"
      source = {
        path           = "k8s/MongoDB"
        repoURL        = var.git_repo_url
        targetRevision = "HEAD"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
      }
    }
  })
}

# Create ArgoCD application resources for each service in prod environment
resource "kubectl_manifest" "polybot_application_prod" {
  depends_on = [time_sleep.wait_for_argocd]
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "polybot-prod"
      namespace = "argocd"
    }
    spec = {
      destination = {
        namespace = "prod"
        server    = "https://kubernetes.default.svc"
      }
      project = "default"
      source = {
        path           = "k8s/Polybot"
        repoURL        = var.git_repo_url
        targetRevision = "HEAD"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
      }
    }
  })
}

resource "kubectl_manifest" "yolo5_application_prod" {
  depends_on = [time_sleep.wait_for_argocd]
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "yolo5-prod"
      namespace = "argocd"
    }
    spec = {
      destination = {
        namespace = "prod"
        server    = "https://kubernetes.default.svc"
      }
      project = "default"
      source = {
        path           = "k8s/Yolo5"
        repoURL        = var.git_repo_url
        targetRevision = "HEAD"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
      }
    }
  })
}

resource "kubectl_manifest" "mongodb_application_prod" {
  depends_on = [time_sleep.wait_for_argocd]
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "mongodb-prod"
      namespace = "argocd"
    }
    spec = {
      destination = {
        namespace = "prod"
        server    = "https://kubernetes.default.svc"
      }
      project = "default"
      source = {
        path           = "k8s/MongoDB"
        repoURL        = var.git_repo_url
        targetRevision = "HEAD"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = true
        }
      }
    }
  })
} 