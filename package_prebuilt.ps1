Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   AIAIAI Pre-built Air-Gapped Packager   " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$stageDir = "airgap_stage"
$zipFile = "aiaiai_airgap_deployment.zip"

# 1. Cleanup Old Staging Directory and Zip
if (Test-Path $stageDir) {
    Write-Host "Cleaning up old staging directory..." -ForegroundColor DarkYellow
    Remove-Item -Recurse -Force $stageDir | Out-Null
}
if (Test-Path $zipFile) {
    Write-Host "Removing old zip file..." -ForegroundColor DarkYellow
    Remove-Item -Force $zipFile | Out-Null
}

# 2. Build the Docker Stack
Write-Host "[1/6] Building application Docker images..." -ForegroundColor Yellow
docker compose build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build Docker stack!"
    exit 1
}

# 3. Create Staging Directories
Write-Host "[2/6] Creating deployment staging directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $stageDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stageDir "database") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stageDir "config") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stageDir "gateway/policies") | Out-Null

# 4. Save Docker Images to a single Tar file
Write-Host "[3/6] Saving all Docker images to images.tar (this may take a minute)..." -ForegroundColor Yellow
$images = "aiaiai-aiaiai_gateway", "aiaiai-aiaiai_sidecar", "aiaiai-aiaiai_mock_llm", "postgres:15", "redis:7-alpine"
$tarPath = Join-Path $stageDir "images.tar"
docker save $images -o $tarPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to save Docker images!"
    exit 1
}

# 5. Copy Compose and Configuration Files
Write-Host "[4/6] Copying docker-compose and configuration assets..." -ForegroundColor Yellow
Copy-Item "docker-compose.yml" -Destination (Join-Path $stageDir "docker-compose.yml") -Force
Copy-Item "database/*" -Destination (Join-Path $stageDir "database") -Force
Copy-Item "config/*" -Destination (Join-Path $stageDir "config") -Force
Copy-Item "gateway/policies/*" -Destination (Join-Path $stageDir "gateway/policies") -Force

# 6. Create deployment restore script
Write-Host "[5/6] Generating deployment restorer script..." -ForegroundColor Yellow
$deployScriptContent = @'
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "    AIAIAI Air-Gapped Deployer Script     " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Load Pre-built Images
Write-Host "Loading pre-built Docker images from images.tar (this may take a minute)..." -ForegroundColor Yellow
docker load -i images.tar
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to load Docker images!"
    exit 1
}

# 2. Launch Stack
Write-Host "Starting AIAIAI system containers..." -ForegroundColor Yellow
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to start Docker compose stack!"
    exit 1
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "    System Deployment Completed!          " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Gateway & Dashboard: http://localhost:1173"
Write-Host "Configuration Portal: http://localhost:1163"
'@
$deployScriptPath = Join-Path $stageDir "deploy.ps1"
Set-Content -Path $deployScriptPath -Value $deployScriptContent -Encoding utf8

# 7. Compress Archive to Zip
Write-Host "[6/6] Compressing deployable staging directory to $zipFile..." -ForegroundColor Yellow
Compress-Archive -Path "$stageDir/*" -DestinationPath $zipFile -Force

# 8. Clean Staging Folder
Write-Host "Cleaning up staging files..." -ForegroundColor DarkYellow
Remove-Item -Recurse -Force $stageDir | Out-Null

Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Air-Gapped Zip Package Created Successfully! " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Created archive: $zipFile" -ForegroundColor Cyan
Write-Host "To deploy offline:" -ForegroundColor Cyan
Write-Host "1. Copy '$zipFile' to your air-gapped machine."
Write-Host "2. Extract the zip file."
Write-Host "3. Run '.\deploy.ps1' to load images and launch everything instantly!"
