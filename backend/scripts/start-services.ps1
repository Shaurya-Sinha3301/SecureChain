# PowerShell script to start SecureChain services
param(
    [string]$Mode = "full",  # full, minimal, or opencti-only
    [switch]$Build = $false,
    [switch]$Clean = $false
)

Write-Host "🚀 Starting SecureChain Services..." -ForegroundColor Green

# Clean up if requested
if ($Clean) {
    Write-Host "🧹 Cleaning up existing containers and volumes..." -ForegroundColor Yellow
    docker-compose -f docker-compose.full.yml down -v
    docker-compose -f docker-compose.minimal.yml down -v
    docker system prune -f
}

# Determine which compose file to use
$ComposeFile = switch ($Mode) {
    "full" { "docker-compose.full.yml" }
    "minimal" { "docker-compose.minimal.yml" }
    "opencti-only" { "docker-compose.opencti.yml" }
    default { "docker-compose.full.yml" }
}

Write-Host "📋 Using compose file: $ComposeFile" -ForegroundColor Cyan

# Build if requested
if ($Build) {
    Write-Host "🔨 Building images..." -ForegroundColor Yellow
    docker-compose -f $ComposeFile build
}

# Start services
Write-Host "▶️ Starting services..." -ForegroundColor Blue
docker-compose -f $ComposeFile up -d

# Wait for services to be ready
Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow

# Check PostgreSQL
Write-Host "🐘 Checking PostgreSQL..." -ForegroundColor Cyan
$retries = 30
do {
    $result = docker exec securechain_postgres pg_isready -U securechain 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL is ready" -ForegroundColor Green
        break
    }
    Start-Sleep 2
    $retries--
} while ($retries -gt 0)

# Check Neo4j
Write-Host "🔗 Checking Neo4j..." -ForegroundColor Cyan
$retries = 30
do {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:7474" -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Neo4j is ready" -ForegroundColor Green
            break
        }
    } catch {
        # Continue waiting
    }
    Start-Sleep 2
    $retries--
} while ($retries -gt 0)

# Check OpenCTI (if in full mode)
if ($Mode -eq "full") {
    Write-Host "🛡️ Checking OpenCTI..." -ForegroundColor Cyan
    $retries = 60  # OpenCTI takes longer to start
    do {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -TimeoutSec 10 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ OpenCTI is ready" -ForegroundColor Green
                break
            }
        } catch {
            # Continue waiting
        }
        Start-Sleep 5
        $retries--
    } while ($retries -gt 0)
}

# Show service status
Write-Host "`n📊 Service Status:" -ForegroundColor Magenta
docker-compose -f $ComposeFile ps

# Show access URLs
Write-Host "`n🌐 Access URLs:" -ForegroundColor Magenta
Write-Host "   PostgreSQL: localhost:5432 (user: securechain, password: password)" -ForegroundColor White
Write-Host "   Neo4j Browser: http://localhost:7474 (user: neo4j, password: neo4j_password)" -ForegroundColor White
Write-Host "   Redis: localhost:6379" -ForegroundColor White

if ($Mode -eq "full") {
    Write-Host "   OpenCTI: http://localhost:8080 (admin@opencti.io / ChangeMe)" -ForegroundColor White
    Write-Host "   MinIO Console: http://localhost:9001 (ChangeMeAccessKey / ChangeMeSecretKey)" -ForegroundColor White
    Write-Host "   RabbitMQ Management: http://localhost:15672 (guest / guest)" -ForegroundColor White
}

Write-Host "   SecureChain Backend: http://localhost:8001" -ForegroundColor White

Write-Host "`n🎉 Services started successfully!" -ForegroundColor Green
Write-Host "💡 To stop services: docker-compose -f $ComposeFile down" -ForegroundColor Yellow