#!/bin/bash
# ArgoCD Connection Helper
PORT=8081

# Function to check if kubectl is available
check_kubectl() {
  if ! command -v kubectl &> /dev/null; then
    echo -e "\033[1;31m❌ ERROR: kubectl not found. Please install kubectl first.\033[0m"
    exit 1
  fi
}

# Function to check if kubeconfig is valid
check_kubeconfig() {
  if ! kubectl get nodes &>/dev/null; then
    echo -e "\033[1;33m⚠️ WARNING: Cannot connect to Kubernetes cluster with current kubeconfig.\033[0m"
    echo -e "\033[1;33m⚠️ If you're running this locally, make sure your kubeconfig is valid.\033[0m"
    echo -e "\033[1;33m⚠️ Try: export KUBECONFIG=$(pwd)/kubeconfig.yaml\033[0m"
    return 1
  fi
  return 0
}

# Function to check if ArgoCD is deployed
check_argocd() {
  if ! kubectl get namespace argocd &>/dev/null; then
    echo -e "\033[1;33m⚠️ ArgoCD namespace not found. Creating it...\033[0m"
    kubectl create namespace argocd
  fi
  
  if ! kubectl get deployment -n argocd argocd-server &>/dev/null; then
    echo -e "\033[1;33m⚠️ ArgoCD server not deployed.\033[0m"
    echo -e "\033[1;33m⚠️ It might still be installing or failed to install.\033[0m"
    
    echo -e "\033[1;34m🔄 Checking ArgoCD pods...\033[0m"
    kubectl get pods -n argocd
    
    echo -e "\033[1;34m🔄 Would you like to install ArgoCD now? (y/n)\033[0m"
    read -r answer
    
    if [[ "$answer" == "y" ]]; then
      echo -e "\033[1;34m🔄 Installing ArgoCD...\033[0m"
      kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
      echo -e "\033[1;34m🔄 Waiting for ArgoCD server to start (this might take a few minutes)...\033[0m"
      kubectl -n argocd wait --for=condition=available --timeout=300s deployment/argocd-server || true
    else
      echo -e "\033[1;33m⚠️ ArgoCD installation skipped. Cannot proceed with port forwarding.\033[0m"
      return 1
    fi
  fi
  return 0
}

# Function to handle port forwarding
start_port_forward() {
  # Check if port is in use
  PORT_PID=$(lsof -ti:$PORT 2>/dev/null)
  if [ -n "$PORT_PID" ]; then
    echo -e "\033[1;33m⚠️ Port $PORT is already in use by PID $PORT_PID\033[0m"
    echo -e "\033[1;34m🔄 Stopping existing process...\033[0m"
    kill -9 $PORT_PID 2>/dev/null || true
    sleep 2
  fi
  
  # Kill any existing kubectl port-forwards
  pkill -f "kubectl.*port-forward.*argocd-server" || true
  
  # Check if ArgoCD service exists
  if ! kubectl get svc -n argocd argocd-server &>/dev/null; then
    echo -e "\033[1;31m❌ ArgoCD server service not found. Cannot start port forwarding.\033[0m"
    return 1
  fi
  
  # Start port forwarding
  echo -e "\033[1;34m🔄 Starting ArgoCD port forwarding on port $PORT...\033[0m"
  kubectl port-forward svc/argocd-server -n argocd $PORT:443 &
  PORT_FORWARD_PID=$!
  echo $PORT_FORWARD_PID > /tmp/argocd-port-forward.pid
  
  # Give it time to establish
  sleep 3
  
  # Verify port-forward is running
  if ! ps -p $PORT_FORWARD_PID > /dev/null; then
    echo -e "\033[1;31m❌ Port forwarding failed to start\033[0m"
    return 1
  fi
  
  echo -e "\033[1;32m✅ ArgoCD port forwarding started successfully on port $PORT\033[0m"
  return 0
}

# Function to retrieve and display password
get_password() {
  echo -e "\033[1;34m🔑 Retrieving ArgoCD admin password...\033[0m"
  ATTEMPTS=0
  MAX_ATTEMPTS=3
  
  while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
    ADMIN_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d)
    
    if [ -n "$ADMIN_PASSWORD" ]; then
      echo -e "\033[1;32m✅ Password retrieved successfully\033[0m"
      echo "$ADMIN_PASSWORD" > /tmp/argocd-admin-password.txt
      chmod 600 /tmp/argocd-admin-password.txt
      break
    else
      ATTEMPTS=$((ATTEMPTS+1))
      echo -e "\033[1;33m⚠️ Password not found yet. Attempt $ATTEMPTS/$MAX_ATTEMPTS\033[0m"
      if [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; then
        echo -e "\033[1;34m🔄 Waiting 10 seconds before retrying...\033[0m"
        sleep 10
      fi
    fi
  done
  
  if [ -z "$ADMIN_PASSWORD" ]; then
    echo -e "\033[1;33m⚠️ Could not retrieve password after $MAX_ATTEMPTS attempts\033[0m"
    echo -e "\033[1;33m⚠️ ArgoCD may still be initializing or the password secret might not exist yet\033[0m"
    return 1
  fi
  
  return 0
}

# Function to stop port forwarding
stop_port_forward() {
  echo -e "\033[1;34m🔄 Stopping ArgoCD port forwarding...\033[0m"
  pkill -f "kubectl.*port-forward.*argocd-server" || true
  rm -f /tmp/argocd-port-forward.pid
  echo -e "\033[1;32m✅ Port forwarding stopped\033[0m"
}

# Main execution
check_kubectl

case "$1" in
  start)
    if check_kubeconfig && check_argocd && start_port_forward && get_password; then
      echo -e "\033[1;32m=======================================\033[0m"
      echo -e "\033[1;32m✅ ArgoCD is now accessible at: \033[1;37mhttps://localhost:$PORT\033[0m"
      echo -e "\033[1;32m✅ Username: \033[1;37madmin\033[0m" 
      echo -e "\033[1;32m✅ Password: \033[1;37m$(cat /tmp/argocd-admin-password.txt)\033[0m"
      echo -e "\033[1;32m=======================================\033[0m"
    else
      echo -e "\033[1;31m❌ Failed to set up ArgoCD access completely\033[0m"
      echo -e "\033[1;33m⚠️ You may need to wait for ArgoCD to fully deploy\033[0m"
      echo -e "\033[1;33m⚠️ Try running this script again in a few minutes\033[0m"
    fi
    ;;
  stop)
    stop_port_forward
    ;;
  password)
    if check_kubeconfig && check_argocd && get_password; then
      echo -e "\033[1;32m✅ Username: \033[1;37madmin\033[0m" 
      echo -e "\033[1;32m✅ Password: \033[1;37m$(cat /tmp/argocd-admin-password.txt)\033[0m"
    fi
    ;;
  *)
    echo -e "\033[1;34m=======================================\033[0m"
    echo -e "\033[1;34m       ArgoCD Access Helper\033[0m"
    echo -e "\033[1;34m=======================================\033[0m"
    echo -e "\033[1;37mUsage: $0 [command]\033[0m"
    echo -e "\033[1;37mCommands:\033[0m"
    echo -e "  \033[1;37mstart    - Start port forwarding and get admin password\033[0m"
    echo -e "  \033[1;37mstop     - Stop port forwarding\033[0m"
    echo -e "  \033[1;37mpassword - Get admin password only\033[0m"
    echo -e "\033[1;34m=======================================\033[0m"
    ;;
esac 