#!/bin/bash

# Bash script to start SecureChain services
MODE=${1:-full}  # full, minimal, or opencti-only
BUILD=${2:-false}
CLEAN=${3:-false}

echo "🚀 Starting SecureChain Services..."

# Clean up if requested
if [ "$CLEAN" = "true" ]; then
    echo "🧹 Cleaning up existing containers and volumes..."
    docker-compose -f docker-compose.full.yml down -v
    docker-compose -f docker-compose.minimal.yml down -v
    docker system prune -f
fi

# Determine which compose file to use
case $MODE in
    "full")
        COMPOSE_FILE="docker-compose.full.yml"
        ;;
    "minimal")
        COMPOSE_FILE="docker-compose.minimal.yml"
        ;;
    "opencti-only")
        COMPOSE_FILE="docker-compose.opencti.yml"
        ;;
    *)
        COMPOSE_FILE="docker-compose.full.yml"
        ;;
esac

echo "📋 Using compose file: $COMPOSE_FILE"

# Build if requested
if [ "$BUILD" = "true" ]; then
    echo "🔨 Building images..."
    docker-compose -f $COMPOSE_FILE build
fi

# Start services
echo "▶️ Starting services..."
docker-compose -f $COMPOSE_FILE up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."

# Check PostgreSQL
echo "🐘 Checking PostgreSQL..."
retries=30
while [ $retries -gt 0 ]; do
    if docker exec securechain_postgres pg_isready -U securechain >/dev/null 2>&1; then
        echo "✅ PostgreSQL is ready"
        break
    fi
    sleep 2
    ((retries--))
done

# Check Neo4j
echo "🔗 Checking Neo4j..."
retries=30
while [ $retries -gt 0 ]; do
    if curl -f http://localhost:7474 >/dev/null 2>&1; then
        echo "✅ Neo4j is ready"
        break
    fi
    sleep 2
    ((retries--))
done

# Check OpenCTI (if in full mode)
if [ "$MODE" = "full" ]; then
    echo "🛡️ Checking OpenCTI..."
    retries=60  # OpenCTI takes longer to start
    while [ $retries -gt 0 ]; do
        if curl -f http://localhost:8080/health >/dev/null 2>&1; then
            echo "✅ OpenCTI is ready"
            break
        fi
        sleep 5
        ((retries--))
    done
fi

# Show service status
echo ""
echo "📊 Service Status:"
docker-compose -f $COMPOSE_FILE ps

# Show access URLs
echo ""
echo "🌐 Access URLs:"
echo "   PostgreSQL: localhost:5432 (user: securechain, password: password)"
echo "   Neo4j Browser: http://localhost:7474 (user: neo4j, password: neo4j_password)"
echo "   Redis: localhost:6379"

if [ "$MODE" = "full" ]; then
    echo "   OpenCTI: http://localhost:8080 (admin@opencti.io / ChangeMe)"
    echo "   MinIO Console: http://localhost:9001 (ChangeMeAccessKey / ChangeMeSecretKey)"
    echo "   RabbitMQ Management: http://localhost:15672 (guest / guest)"
fi

echo "   SecureChain Backend: http://localhost:8001"

echo ""
echo "🎉 Services started successfully!"
echo "💡 To stop services: docker-compose -f $COMPOSE_FILE down"