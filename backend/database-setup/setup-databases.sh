#!/bin/bash

# Bash script to set up PostgreSQL and Neo4j databases for SecureChain

MODE=${1:-docker}  # docker, local, or check
INIT_DATA=${2:-false}
RESET=${3:-false}

echo "🗄️ SecureChain Database Setup"
echo "================================"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local test_command=$2
    local max_retries=${3:-30}
    
    echo "⏳ Waiting for $service_name to be ready..."
    
    local retries=0
    while [ $retries -lt $max_retries ]; do
        if eval "$test_command" >/dev/null 2>&1; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        
        sleep 3
        ((retries++))
        echo "   Attempt $retries/$max_retries..."
    done
    
    echo "❌ $service_name failed to start within timeout"
    return 1
}

if [ "$MODE" = "check" ]; then
    echo "🔍 Checking database connectivity..."
    
    # Check PostgreSQL
    if command_exists docker; then
        if docker exec securechain_postgres pg_isready -U securechain >/dev/null 2>&1; then
            echo "✅ PostgreSQL (Docker) is accessible"
        else
            echo "❌ PostgreSQL (Docker) is not accessible"
        fi
    fi
    
    # Try local PostgreSQL
    if command_exists psql; then
        export PGPASSWORD=password
        if psql -h localhost -p 5432 -U securechain -d securechain -c "SELECT 1;" >/dev/null 2>&1; then
            echo "✅ PostgreSQL (Local) is accessible"
        else
            echo "❌ PostgreSQL (Local) is not accessible"
        fi
    fi
    
    # Check Neo4j
    if curl -f http://localhost:7474 >/dev/null 2>&1; then
        echo "✅ Neo4j is accessible at http://localhost:7474"
    else
        echo "❌ Neo4j is not accessible"
    fi
    
    exit 0
fi

if [ "$RESET" = "true" ]; then
    echo "🧹 Resetting databases..."
    
    if [ "$MODE" = "docker" ]; then
        # Stop and remove containers
        docker stop securechain_postgres securechain_neo4j 2>/dev/null
        docker rm securechain_postgres securechain_neo4j 2>/dev/null
        
        # Remove volumes
        docker volume rm backend_postgres_data backend_neo4j_data backend_neo4j_logs 2>/dev/null
        
        echo "✅ Docker containers and volumes removed"
    fi
fi

if [ "$MODE" = "docker" ]; then
    echo "🐳 Setting up databases with Docker..."
    
    # Check if Docker is available
    if ! command_exists docker; then
        echo "❌ Docker is not installed or not in PATH"
        echo "Please install Docker from https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check if docker-compose is available
    if ! command_exists docker-compose; then
        echo "❌ docker-compose is not available"
        echo "Please install docker-compose"
        exit 1
    fi
    
    # Start databases using docker-compose
    echo "🚀 Starting PostgreSQL and Neo4j containers..."
    
    cd SecureChain/backend || exit 1
    docker-compose -f docker-compose.minimal.yml up -d postgres neo4j
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to start database containers"
        exit 1
    fi
    
    # Wait for PostgreSQL
    if ! wait_for_service "PostgreSQL" "docker exec securechain_postgres pg_isready -U securechain"; then
        exit 1
    fi
    
    # Wait for Neo4j
    if ! wait_for_service "Neo4j" "curl -f http://localhost:7474"; then
        exit 1
    fi
    
elif [ "$MODE" = "local" ]; then
    echo "🏠 Setting up local databases..."
    
    # Check for local PostgreSQL
    if ! command_exists psql; then
        echo "❌ PostgreSQL is not installed locally"
        echo "Please install PostgreSQL from https://www.postgresql.org/download/"
        exit 1
    fi
    
    # Check for local Neo4j (this is more complex to detect)
    echo "⚠️ Please ensure Neo4j is installed and running locally"
    echo "Neo4j can be downloaded from https://neo4j.com/download/"
fi

# Initialize databases if requested
if [ "$INIT_DATA" = "true" ]; then
    echo "🔧 Initializing database schemas..."
    
    # Initialize PostgreSQL
    echo "📊 Setting up PostgreSQL schema..."
    
    if [ "$MODE" = "docker" ]; then
        # Copy SQL file to container and execute
        docker cp "database-setup/postgres-init/01-create-database.sql" securechain_postgres:/tmp/
        docker exec securechain_postgres psql -U postgres -d securechain -f /tmp/01-create-database.sql
    else
        # Execute locally
        export PGPASSWORD=password
        psql -h localhost -p 5432 -U postgres -d securechain -f "database-setup/postgres-init/01-create-database.sql"
    fi
    
    if [ $? -eq 0 ]; then
        echo "✅ PostgreSQL schema initialized successfully"
    else
        echo "❌ PostgreSQL schema initialization failed"
    fi
    
    # Initialize Neo4j
    echo "🔗 Setting up Neo4j schema..."
    
    # Execute via cypher-shell if available
    if command_exists cypher-shell; then
        cypher-shell -u neo4j -p neo4j_password -f "database-setup/neo4j-init/01-create-constraints.cypher"
        
        if [ $? -eq 0 ]; then
            echo "✅ Neo4j schema initialized successfully"
        else
            echo "❌ Neo4j schema initialization failed"
        fi
    else
        echo "⚠️ cypher-shell not available. Please run the Neo4j script manually:"
        echo "   1. Open http://localhost:7474 in your browser"
        echo "   2. Login with neo4j/neo4j_password"
        echo "   3. Copy and paste the contents of database-setup/neo4j-init/01-create-constraints.cypher"
    fi
fi

# Show connection information
echo ""
echo "🌐 Database Connection Information:"
echo "================================="

echo "PostgreSQL:"
echo "  Host: localhost"
echo "  Port: 5432"
echo "  Database: securechain"
echo "  Username: securechain"
echo "  Password: password"
echo "  Connection String: postgresql://securechain:password@localhost:5432/securechain"

echo ""
echo "Neo4j:"
echo "  Browser: http://localhost:7474"
echo "  Bolt: bolt://localhost:7687"
echo "  Username: neo4j"
echo "  Password: neo4j_password"

# Test connections
echo ""
echo "🔍 Testing connections..."

# Test PostgreSQL
if [ "$MODE" = "docker" ]; then
    if docker exec securechain_postgres psql -U securechain -d securechain -c "SELECT COUNT(*) FROM vulnerability_findings;" >/dev/null 2>&1; then
        echo "✅ PostgreSQL connection test passed"
    else
        echo "❌ PostgreSQL connection test failed"
    fi
else
    export PGPASSWORD=password
    if psql -h localhost -p 5432 -U securechain -d securechain -c "SELECT COUNT(*) FROM vulnerability_findings;" >/dev/null 2>&1; then
        echo "✅ PostgreSQL connection test passed"
    else
        echo "❌ PostgreSQL connection test failed"
    fi
fi

# Test Neo4j
if curl -f http://localhost:7474 >/dev/null 2>&1; then
    echo "✅ Neo4j connection test passed"
else
    echo "❌ Neo4j connection test failed"
fi

echo ""
echo "🎉 Database setup complete!"
echo "💡 Next steps:"
echo "   1. Update your .env file with the connection strings above"
echo "   2. Start the SecureChain backend: uvicorn main:app --reload"
echo "   3. Test the integration with AI-Vuln-Scanner"

echo ""
echo "📚 Useful commands:"
echo "   Check status: ./setup-databases.sh check"
echo "   Reset databases: ./setup-databases.sh docker false true"
echo "   View PostgreSQL data: docker exec -it securechain_postgres psql -U securechain -d securechain"
echo "   View Neo4j data: Open http://localhost:7474 in browser"