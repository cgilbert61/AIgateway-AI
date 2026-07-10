param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "status")]
    [string]$Action
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "     AIAIAI Kubernetes Resource Manager   " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if ($Action -eq "stop") {
    Write-Host "Scaling all deployments to 0 replicas to save host resources..." -ForegroundColor Yellow
    kubectl scale deployment aiaiai-gateway --replicas=0
    kubectl scale deployment aiaiai-sidecar --replicas=0
    kubectl scale deployment aiaiai-postgres --replicas=0
    kubectl scale deployment aiaiai-redis --replicas=0
    Write-Host "All pods successfully scaled down to 0." -ForegroundColor Green
}
elseif ($Action -eq "start") {
    Write-Host "Scaling up database and cache services..." -ForegroundColor Yellow
    kubectl scale deployment aiaiai-postgres --replicas=1
    kubectl scale deployment aiaiai-redis --replicas=1
    
    Write-Host "Waiting for database to start..." -ForegroundColor DarkYellow
    Start-Sleep -Seconds 5
    
    Write-Host "Scaling up gateway and sidecar services..." -ForegroundColor Yellow
    kubectl scale deployment aiaiai-gateway --replicas=3
    kubectl scale deployment aiaiai-sidecar --replicas=2
    Write-Host "Deployments scaled up and starting." -ForegroundColor Green
}
elseif ($Action -eq "status") {
    kubectl get deployments,pods,hpa
}
