@echo off
echo Starting HappywiseGhala and ArgoCD...
start "HappywiseGhala" kubectl port-forward svc/nginx-service -n happywiseghala 9093:9093 --address 0.0.0.0
start "ArgoCD" kubectl port-forward svc/argocd-server -n argocd 8080:443 --address 0.0.0.0
echo.
echo ================================
echo All apps are now accessible at:
echo ================================
echo HappywiseGhala : http://192.168.100.8:9093
echo ArgoCD         : https://192.168.100.8:8080
echo ================================
pause
