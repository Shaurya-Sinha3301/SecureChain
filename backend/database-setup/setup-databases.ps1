# PowerShell script to set up PostgreSQL and Neo4j databases for SecureChain

param(
    [string]$Mode = "docker",  # docker, local, or check
    [switch]$InitData = $false,
    [switch]$Reset = $false
)

Write-Host "🗄️ SecureChain Database Setup" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

# Function to check if a command exists
function Test-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# Function to wait for service to be ready
function Wait-ForService($serviceName, $testCommand, $maxRetries = 30) {
    Write-Host "⏳ Waiting for $serviceName to be ready..." -ForegroundColor Yellow
    
    $retries = 0
    do {
        try {
            Invoke-Expression $testCommand
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ $serviceName is ready!" -ForegroundColor Green
                return $true
            }
        } catch {
            # Continue waiting
        }
        
        Start-Sleep 3
        $retries++
        Write-Host "   Attempt $retries/$maxRetries..." -ForegroundColor Gray
        
    } while ($retries -lt $maxRetries)
    
    Write-Host "❌ $serviceName failed to start within timeout" -ForegroundColor Red
    return $false
}

if ($Mode -eq "check") {
    Write-Host "🔍 Checking database connectivity..." -ForegroundColor Cyan
    
    # Check PostgreSQL
    try {
        if (Test-Command "docker") {
            $pgResult = docker exec securechain_postgres pg_isready -U securechain 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ PostgreSQL (Docker) is accessible" -ForegroundColor Green
            } else {
                Write-Host "❌ PostgreSQL (Docker) is not accessible" -ForegroundColor Red
            }
        }
        
        # Try local PostgreSQL
        if (Test-Command "psql") {
            $env:PGPASSWORD = "password"
            psql -h localhost -p 5432 -U securechain -d securechain -c "SELECT 1;" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ PostgreSQL (Local) is accessible" -ForegroundColor Green
            } else {
                Write-Host "❌ PostgreSQL (Local) is not accessible" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "❌ PostgreSQL check failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Check Neo4j
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:7474" -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Neo4j is accessible at http://localhost:7474" -ForegroundColor Green
        } else {
            Write-Host "❌ Neo4j is not accessible" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Neo4j is not accessible" -ForegroundColor Red
    }
    
    exit 0
}

if ($Reset) {
    Write-Host "🧹 Resetting databases..." -ForegroundColor Yellow
    
    if ($Mode -eq "docker") {
        # Stop and remove containers
        docker stop securechain_postgres securechain_neo4j 2>$null
        docker rm securechain_postgres securechain_neo4j 2>$null
        
        # Remove volumes
        docker volume rm backend_postgres_data backend_neo4j_data backend_neo4j_logs 2>$null
        
        Write-Host "✅ Docker containers and volumes removed" -ForegroundColor Green
    }
}

if ($Mode -eq "docker") {
    Write-Host "🐳 Setting up databases with Docker..." -ForegroundColor Cyan
    
    # Check if Docker is available
    if (-not (Test-Command "docker")) {
        Write-Host "❌ Docker is not installed or not in PATH" -ForegroundColor Red
        Write-Host "Please install Docker Desktop from https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
        exit 1
    }
    
    # Check if docker-compose is available
    if (-not (Test-Command "docker-compose")) {
        Write-Host "❌ docker-compose is not available" -ForegroundColor Red
        Write-Host "Please install docker-compose or use Docker Desktop" -ForegroundColor Yellow
        exit 1
    }
    
    # Start databases using docker-compose
    Write-Host "🚀 Starting PostgreSQL and Neo4j containers..." -ForegroundColor Blue
    
    Set-Location "SecureChain/backend"
    docker-compose -f docker-compose.minimal.yml up -d postgres neo4j
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to start database containers" -ForegroundColor Red
        exit 1
    }
    
    # Wait for PostgreSQL
    $pgReady = Wait-ForService "PostgreSQL" "docker exec securechain_postgres pg_isready -U securechain"
    
    # Wait for Neo4j
    $neo4jReady = Wait-ForService "Neo4j" "curl -f http://localhost:7474 2>nul"
    
    if (-not $pgReady -or -not $neo4jReady) {
        Write-Host "❌ One or more databases failed to start" -ForegroundColor Red
        exit 1
    }
    
} elseif ($Mode -eq "local") {
    Write-Host "🏠 Setting up local databases..." -ForegroundColor Cyan
    
    # Check for local PostgreSQL
    if (-not (Test-Command "psql")) {
        Write-Host "❌ PostgreSQL is not installed locally" -ForegroundColor Red
        Write-Host "Please install PostgreSQL from https://www.postgresql.org/download/" -ForegroundColor Yellow
        exit 1
    }
    
    # Check for local Neo4j (this is more complex to detect)
    Write-Host "⚠️ Please ensure Neo4j is installed and running locally" -ForegroundColor Yellow
    Write-Host "Neo4j can be downloaded from https://neo4j.com/download/" -ForegroundColor Yellow
}

# Initialize databases if requested
if ($InitData) {
    Write-Host "🔧 Initializing database schemas..." -ForegroundColor Cyan
    
    # Initialize PostgreSQL
    Write-Host "📊 Setting up PostgreSQL schema..." -ForegroundColor Blue
    
    if ($Mode -eq "docker") {
        # Copy SQL file to container and execute
        docker cp "database-setup/postgres-init/01-create-database.sql" securechain_postgres:/tmp/
        docker exec securechain_postgres psql -U postgres -d securechain -f /tmp/01-create-database.sql
    } else {
        # Execute locally
        $env:PGPASSWORD = "password"
        psql -h localhost -p 5432 -U postgres -d securechain -f "database-setup/postgres-init/01-create-database.sql"
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL schema initialized successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ PostgreSQL schema initialization failed" -ForegroundColor Red
    }
    
    # Initialize Neo4j
    Write-Host "🔗 Setting up Neo4j schema..." -ForegroundColor Blue
    
    # Read the Cypher script
    $cypherScript = Get-Content "database-setup/neo4j-init/01-create-constraints.cypher" -Raw
    
    # Execute via HTTP API (works for both Docker and local)
    try {
        $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("neo4j:neo4j_password"))
        $headers = @{
            "Authorization" = "Basic $auth"
            "Content-Type" = "application/json"
        }
        
        $body = @{
            "statements" = @(
                @{
                    "statement" = $cypherScript
                }
            )
        } | ConvertTo-Json -Depth 3
        
        $response = Invoke-RestMethod -Uri "http://localhost:7474/db/data/transaction/commit" -Method Post -Headers $headers -Body $body
        
        if ($response.errors.Count -eq 0) {
            Write-Host "✅ Neo4j schema initialized successfully" -ForegroundColor Green
        } else {
            Write-Host "❌ Neo4j schema initialization had errors:" -ForegroundColor Red
            $response.errors | ForEach-Object { Write-Host "   $($_.message)" -ForegroundColor Red }
        }
    } catch {
        Write-Host "❌ Neo4j schema initialization failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 You can manually run the script in Neo4j Browser at http://localhost:7474" -ForegroundColor Yellow
    }
}

# Show connection information
Write-Host "`n🌐 Database Connection Information:" -ForegroundColor Magenta
Write-Host "=================================" -ForegroundColor Magenta

Write-Host "PostgreSQL:" -ForegroundColor White
Write-Host "  Host: localhost" -ForegroundColor Gray
Write-Host "  Port: 5432" -ForegroundColor Gray
Write-Host "  Database: securechain" -ForegroundColor Gray
Write-Host "  Username: securechain" -ForegroundColor Gray
Write-Host "  Password: password" -ForegroundColor Gray
Write-Host "  Connection String: postgresql://securechain:password@localhost:5432/securechain" -ForegroundColor Gray

Write-Host "`nNeo4j:" -ForegroundColor White
Write-Host "  Browser: http://localhost:7474" -ForegroundColor Gray
Write-Host "  Bolt: bolt://localhost:7687" -ForegroundColor Gray
Write-Host "  Username: neo4j" -ForegroundColor Gray
Write-Host "  Password: neo4j_password" -ForegroundColor Gray

# Test connections
Write-Host "`n🔍 Testing connections..." -ForegroundColor Cyan

# Test PostgreSQL
try {
    if ($Mode -eq "docker") {
        docker exec securechain_postgres psql -U securechain -d securechain -c "SELECT COUNT(*) FROM vulnerability_findings;" 2>$null
    } else {
        $env:PGPASSWORD = "password"
        psql -h localhost -p 5432 -U securechain -d securechain -c "SELECT COUNT(*) FROM vulnerability_findings;" 2>$null
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL connection test passed" -ForegroundColor Green
    } else {
        Write-Host "❌ PostgreSQL connection test failed" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ PostgreSQL connection test failed" -ForegroundColor Red
}

# Test Neo4j
try {
    $response = Invoke-WebRequest -Uri "http://localhost:7474" -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Neo4j connection test passed" -ForegroundColor Green
    } else {
        Write-Host "❌ Neo4j connection test failed" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Neo4j connection test failed" -ForegroundColor Red
}

Write-Host "`n🎉 Database setup complete!" -ForegroundColor Green
Write-Host "💡 Next steps:" -ForegroundColor Yellow
Write-Host "   1. Update your .env file with the connection strings above" -ForegroundColor White
Write-Host "   2. Start the SecureChain backend: uvicorn main:app --reload" -ForegroundColor White
Write-Host "   3. Test the integration with AI-Vuln-Scanner" -ForegroundColor White

Write-Host "`n📚 Useful commands:" -ForegroundColor Yellow
Write-Host "   Check status: .\setup-databases.ps1 -Mode check" -ForegroundColor White
Write-Host "   Reset databases: .\setup-databases.ps1 -Reset" -ForegroundColor White
Write-Host "   View PostgreSQL data: docker exec -it securechain_postgres psql -U securechain -d securechain" -ForegroundColor White
Write-Host "   View Neo4j data: Open http://localhost:7474 in browser" -ForegroundColor White