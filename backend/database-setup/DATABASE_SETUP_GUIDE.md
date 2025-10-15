# Database Setup Guide for SecureChain

This guide covers setting up PostgreSQL and Neo4j databases for the SecureChain project.

## 🐘 PostgreSQL Setup

### Option 1: Docker Setup (Recommended)

#### Quick Start with Docker Compose
```bash
cd SecureChain/backend
docker-compose -f docker-compose.minimal.yml up -d postgres
```

#### Manual Docker Setup
```bash
# Pull PostgreSQL image
docker pull postgres:15

# Run PostgreSQL container
docker run -d \
  --name securechain_postgres \
  -e POSTGRES_DB=securechain \
  -e POSTGRES_USER=securechain \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  postgres:15

# Verify it's running
docker ps | grep postgres
```

### Option 2: Local Installation

#### Windows
1. Download PostgreSQL from https://www.postgresql.org/download/windows/
2. Run the installer
3. Set password for postgres user
4. Note the port (default: 5432)

#### macOS
```bash
# Using Homebrew
brew install postgresql@15
brew services start postgresql@15

# Or using MacPorts
sudo port install postgresql15-server
sudo port load postgresql15-server
```

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### CentOS/RHEL/Fedora
```bash
# Install PostgreSQL
sudo dnf install postgresql postgresql-server

# Initialize database
sudo postgresql-setup --initdb

# Start and enable service
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### PostgreSQL Configuration

#### Create Database and User
```bash
# Connect as postgres user
sudo -u postgres psql

# Or with Docker
docker exec -it securechain_postgres psql -U postgres
```

```sql
-- Create database
CREATE DATABASE securechain;

-- Create user
CREATE USER securechain WITH PASSWORD 'password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE securechain TO securechain;

-- Connect to securechain database
\c securechain

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO securechain;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO securechain;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO securechain;

-- Exit
\q
```

#### Test Connection
```bash
# Test connection
psql -h localhost -p 5432 -U securechain -d securechain

# Or with Docker
docker exec -it securechain_postgres psql -U securechain -d securechain
```

## 🔗 Neo4j Setup

### Option 1: Docker Setup (Recommended)

#### Quick Start with Docker Compose
```bash
cd SecureChain/backend
docker-compose -f docker-compose.minimal.yml up -d neo4j
```

#### Manual Docker Setup
```bash
# Pull Neo4j image
docker pull neo4j:5.15

# Run Neo4j container
docker run -d \
  --name securechain_neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/neo4j_password \
  -e NEO4J_PLUGINS='["apoc"]' \
  -e NEO4J_dbms_security_procedures_unrestricted=apoc.* \
  -v neo4j_data:/data \
  -v neo4j_logs:/logs \
  neo4j:5.15

# Verify it's running
docker ps | grep neo4j
```

### Option 2: Local Installation

#### Windows
1. Download Neo4j Desktop from https://neo4j.com/download/
2. Install Neo4j Desktop
3. Create a new project
4. Add a local DBMS
5. Set password and start

#### macOS
```bash
# Using Homebrew
brew install neo4j

# Start Neo4j
neo4j start

# Or install Neo4j Desktop
brew install --cask neo4j
```

#### Ubuntu/Debian
```bash
# Add Neo4j repository
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list

# Update and install
sudo apt update
sudo apt install neo4j

# Start service
sudo systemctl start neo4j
sudo systemctl enable neo4j
```

#### CentOS/RHEL/Fedora
```bash
# Add Neo4j repository
sudo rpm --import https://debian.neo4j.com/neotechnology.gpg.key
sudo tee /etc/yum.repos.d/neo4j.repo <<EOF
[neo4j]
name=Neo4j RPM Repository
baseurl=https://yum.neo4j.com/stable
enabled=1
gpgcheck=1
EOF

# Install Neo4j
sudo dnf install neo4j

# Start service
sudo systemctl start neo4j
sudo systemctl enable neo4j
```

### Neo4j Configuration

#### Access Neo4j Browser
1. Open browser and go to http://localhost:7474
2. Login with:
   - Username: `neo4j`
   - Password: `neo4j_password` (or your chosen password)

#### Install APOC Plugin (if not using Docker)
```bash
# Download APOC plugin
wget https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/5.15.0/apoc-5.15.0-core.jar

# Copy to plugins directory
sudo cp apoc-5.15.0-core.jar /var/lib/neo4j/plugins/

# Edit Neo4j configuration
sudo nano /etc/neo4j/neo4j.conf

# Add these lines:
dbms.security.procedures.unrestricted=apoc.*
dbms.security.procedures.allowlist=apoc.*

# Restart Neo4j
sudo systemctl restart neo4j
```

#### Test Connection
```cypher
// In Neo4j Browser, run:
RETURN "Hello, Neo4j!" as message;

// Check APOC installation
CALL apoc.help("apoc");
```

## 🔧 Database Initialization

### Create Initialization Scripts

#### PostgreSQL Initialization
```bash
# Create init script directory
mkdir -p SecureChain/backend/database-setup/postgres-init
```