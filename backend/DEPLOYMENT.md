# SecureChain Deployment Guide

## Deployment Options

You have several options for running SecureChain services:

### Option 1: All-in-One (Recommended for Development)
Run everything together including OpenCTI:

```bash
# Windows PowerShell
.\scripts\start-services.ps1 -Mode full

# Linux/Mac
chmod +x scripts/start-services.sh
./scripts/start-services.sh full
```

### Option 2: Minimal Setup (Databases Only)
Run just PostgreSQL, Neo4j, and Redis:

```bash
# Windows PowerShell
.\scripts\start-services.ps1 -Mode minimal

# Linux/Mac
./scripts/start-services.sh minimal
```

### Option 3: Manual Docker Commands

#### Full Setup:
```bash
cd SecureChain/backend
docker-compose -f docker-compose.full.yml up -d
```

#### Minimal Setup:
```bash
cd SecureChain/backend
docker-compose -f docker-compose.minimal.yml up -d
```

## Service Startup Order

The services have dependencies and should start in this order:

1. **Infrastructure Services** (Redis, PostgreSQL, Neo4j)
2. **OpenCTI Dependencies** (Elasticsearch, MinIO, RabbitMQ)
3. **OpenCTI Platform**
4. **SecureChain Backend**

The docker-compose files handle this automatically with `depends_on` and health checks.

## Service URLs and Credentials

### Core Services
- **SecureChain Backend**: http://localhost:8001
- **PostgreSQL**: localhost:5432
  - User: `securechain`
  - Password: `password`
  - Database: `securechain`
- **Neo4j**: http://localhost:7474
  - User: `neo4j`
  - Password: `neo4j_password`
- **Redis**: localhost:6379

### OpenCTI Stack (Full Mode Only)
- **OpenCTI Platform**: http://localhost:8080
  - Email: `admin@opencti.io`
  - Password: `ChangeMe`
  - API Token: `ChangeMe`
- **MinIO Console**: http://localhost:9001
  - Access Key: `ChangeMeAccessKey`
  - Secret Key: `ChangeMeSecretKey`
- **RabbitMQ Management**: http://localhost:15672
  - User: `guest`
  - Password: `guest`
- **Elasticsearch**: http://localhost:9200

## Startup Time Expectations

- **Minimal Setup**: ~30-60 seconds
- **Full Setup**: ~3-5 minutes (OpenCTI takes time to initialize)

## Health Checks

Check if services are ready:

```bash
# Backend health
curl http://localhost:8001/health

# OpenCTI health
curl http://localhost:8080/health

# PostgreSQL
docker exec securechain_postgres pg_isready -U securechain

# Neo4j
curl http://localhost:7474
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Check what's using ports
   netstat -tulpn | grep :8080
   
   # Stop conflicting services
   sudo systemctl stop apache2  # if using port 80
   ```

2. **Memory Issues**
   ```bash
   # Increase Docker memory limit to at least 8GB
   # Docker Desktop -> Settings -> Resources -> Memory
   ```

3. **OpenCTI Won't Start**
   ```bash
   # Check logs
   docker logs securechain_opencti
   
   # Common fix: wait longer (can take 5+ minutes)
   # Or restart just OpenCTI
   docker restart securechain_opencti
   ```

4. **Database Connection Issues**
   ```bash
   # Check if containers are running
   docker ps
   
   # Check network connectivity
   docker network ls
   docker network inspect backend_securechain_network
   ```

### Reset Everything

```bash
# Windows PowerShell
.\scripts\start-services.ps1 -Clean

# Linux/Mac
./scripts/start-services.sh full true true

# Or manually
docker-compose -f docker-compose.full.yml down -v
docker system prune -f
```

## Production Deployment

For production, consider:

1. **Separate OpenCTI Deployment**
   - Use existing OpenCTI instance
   - Update `OPENCTI_URL` and `OPENCTI_TOKEN` in backend

2. **External Databases**
   - Use managed PostgreSQL (AWS RDS, etc.)
   - Use managed Neo4j (Neo4j Aura, etc.)

3. **Security**
   - Change all default passwords
   - Use environment-specific secrets
   - Enable SSL/TLS
   - Configure firewalls

4. **Scaling**
   - Use multiple backend instances
   - Load balancer for API
   - Redis cluster for background tasks

## Development Workflow

1. **Start Services**
   ```bash
   ./scripts/start-services.sh minimal
   ```

2. **Run Backend Locally**
   ```bash
   cd SecureChain/backend
   pip install -r requirements.txt
   uvicorn main:app --reload --port 8000
   ```

3. **Test Integration**
   ```bash
   cd SecureChain/AI-Vuln-Scanner
   python integration_client.py
   ```

## Environment Variables

Create `.env` file in backend directory:

```bash
# Copy template
cp .env.example .env

# Edit configuration
nano .env
```

Key variables:
- `POSTGRES_URL`: Database connection
- `NEO4J_URI`: Neo4j connection
- `OPENCTI_URL`: OpenCTI platform URL
- `OPENCTI_TOKEN`: OpenCTI API token

## Monitoring

### Service Status
```bash
# All services
docker-compose -f docker-compose.full.yml ps

# Logs
docker-compose -f docker-compose.full.yml logs -f backend
docker-compose -f docker-compose.full.yml logs -f opencti
```

### Resource Usage
```bash
# Container stats
docker stats

# Disk usage
docker system df
```

## Backup and Recovery

### Database Backups
```bash
# PostgreSQL backup
docker exec securechain_postgres pg_dump -U securechain securechain > backup.sql

# Neo4j backup
docker exec securechain_neo4j neo4j-admin dump --database=neo4j --to=/tmp/neo4j-backup.dump
docker cp securechain_neo4j:/tmp/neo4j-backup.dump ./neo4j-backup.dump
```

### Volume Backups
```bash
# Backup all volumes
docker run --rm -v backend_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz -C /data .
docker run --rm -v backend_neo4j_data:/data -v $(pwd):/backup alpine tar czf /backup/neo4j_backup.tar.gz -C /data .
```

This deployment guide should help you get SecureChain running in any configuration you need!