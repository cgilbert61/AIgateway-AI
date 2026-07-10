Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "    AIAIAI Air-Gapped Packaging Script    " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Vendor Go Dependencies
Write-Host "[1/4] Vendoring Go gateway dependencies..." -ForegroundColor Yellow
Push-Location gateway
go mod tidy
go mod vendor
Pop-Location
Write-Host "Go vendoring complete." -ForegroundColor Green

# 2. Download Python Wheels
Write-Host "[2/4] Downloading Python wheels for sidecar..." -ForegroundColor Yellow
Push-Location sidecar
if (!(Test-Path wheels)) { New-Item -ItemType Directory -Path wheels | Out-Null }
pip download -r requirements.txt -d wheels --platform manylinux2014_x86_64 --only-binary=:all: --implementation cp --python-version 310
Pop-Location
Write-Host "Python wheels download complete." -ForegroundColor Green

# 3. Create Export Directory
Write-Host "[3/4] Creating airgap_export directory..." -ForegroundColor Yellow
$exportDir = "airgap_export"
if (!(Test-Path $exportDir)) {
    New-Item -ItemType Directory -Path $exportDir | Out-Null
}

# 4. Pull and Save Docker Images to Tarballs
Write-Host "[4/4] Exporting Docker base images to tarball files..." -ForegroundColor Yellow
$images = @(
    "golang:1.22-alpine",
    "alpine:3.18",
    "python:3.10-slim",
    "postgres:15",
    "redis:7-alpine"
)

foreach ($img in $images) {
    $safeName = $img.Replace(":", "-").Replace("/", "-")
    $tarPath = Join-Path $exportDir "$safeName.tar"
    Write-Host "Pulling $img..." -ForegroundColor DarkYellow
    docker pull $img | Out-Null
    Write-Host "Saving $img to $tarPath..." -ForegroundColor DarkYellow
    docker save $img -o $tarPath
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Air-Gapped Package Created Successfully! " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "To deploy offline:" -ForegroundColor Cyan
Write-Host "1. Copy the entire repository directory AND the '$exportDir' directory to your offline machine."
Write-Host "2. On the offline machine, load the Docker images:"
Write-Host "   Get-ChildItem $exportDir\*.tar | ForEach-Object { docker load -i `$_.FullName }"
Write-Host "3. Build and launch the containers:"
Write-Host "   docker compose up --build -d"
