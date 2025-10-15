"""
SecureChain Backend Main Application
Integrated vulnerability management with PostgreSQL, Neo4j, and OpenCTI
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import services
from services.database_manager import DatabaseManager
from services.opencti_enricher import OpenCTIEnricher
from services.ingestion_service import IngestionService

# Import API endpoints
from api.ingestion_endpoints import router as ingestion_router
import api.ingestion_endpoints as ingestion_endpoints

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global service instances
db_manager = None
opencti_enricher = None
ingestion_service = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global db_manager, opencti_enricher, ingestion_service
    
    # Startup
    logger.info("Starting SecureChain Backend with integrated vulnerability management...")
    
    try:
        # Initialize database manager
        postgres_url = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/securechain')
        neo4j_uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
        neo4j_password = os.getenv('NEO4J_PASSWORD', 'password')
        
        db_manager = DatabaseManager(
            postgres_url=postgres_url,
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password
        )
        logger.info("Database manager initialized")
        
        # Initialize OpenCTI enricher (optional)
        opencti_url = os.getenv('OPENCTI_URL')
        opencti_token = os.getenv('OPENCTI_TOKEN')
        opencti_enricher = None
        
        if opencti_url and opencti_token:
            try:
                opencti_enricher = OpenCTIEnricher(opencti_url, opencti_token)
                logger.info("OpenCTI enricher initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize OpenCTI enricher: {e}")
                opencti_enricher = None
        else:
            logger.warning("OpenCTI not configured - enrichment will be skipped")
        
        # Initialize ingestion service
        ingestion_service = IngestionService(
            db_manager=db_manager,
            opencti_enricher=opencti_enricher
        )
        logger.info("Ingestion service initialized")
        
        # Set global instances for dependency injection
        ingestion_endpoints.ingestion_service = ingestion_service
        ingestion_endpoints.db_manager = db_manager
        
        logger.info("SecureChain Backend startup complete")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down SecureChain Backend...")
    if db_manager:
        db_manager.close()
    logger.info("Shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="SecureChain Vulnerability Management API",
    description="Integrated vulnerability management with normalization, OpenCTI enrichment, and attack graph generation",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingestion_router)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SecureChain Vulnerability Management API",
        "version": "2.0.0",
        "status": "running",
        "features": [
            "Vulnerability finding normalization",
            "OpenCTI threat intelligence enrichment",
            "PostgreSQL storage",
            "Neo4j attack graph generation",
            "MITRE ATT&CK mapping"
        ],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {}
    }
    
    # Check database connections
    try:
        if db_manager:
            # Test PostgreSQL
            from sqlalchemy import text
            session = db_manager.get_postgres_session()
            session.execute(text("SELECT 1"))
            session.close()
            health_status["services"]["postgresql"] = "healthy"
            
            # Test Neo4j
            neo4j_session = db_manager.get_neo4j_session()
            if neo4j_session:
                neo4j_session.run("RETURN 1")
                neo4j_session.close()
                health_status["services"]["neo4j"] = "healthy"
            else:
                health_status["services"]["neo4j"] = "not_configured"
        else:
            health_status["services"]["database"] = "not_initialized"
    except Exception as e:
        health_status["services"]["database"] = f"unhealthy: {str(e)}"
    
    # Check OpenCTI
    try:
        if opencti_enricher:
            # Simple test query
            result = opencti_enricher.execute_query("query { me { id } }")
            if 'errors' not in result:
                health_status["services"]["opencti"] = "healthy"
            else:
                health_status["services"]["opencti"] = "unhealthy"
        else:
            health_status["services"]["opencti"] = "not_configured"
    except Exception as e:
        health_status["services"]["opencti"] = f"unhealthy: {str(e)}"
    
    # Check ingestion service
    if ingestion_service:
        health_status["services"]["ingestion"] = "healthy"
    else:
        health_status["services"]["ingestion"] = "not_initialized"
    
    return health_status

@app.get("/api/v1/config")
async def get_configuration():
    """Get current configuration"""
    return {
        "database": {
            "postgresql": "configured" if db_manager else "not_configured",
            "neo4j": "configured" if db_manager and db_manager.neo4j_driver else "not_configured"
        },
        "enrichment": {
            "opencti": "configured" if opencti_enricher else "not_configured"
        },
        "services": {
            "ingestion": "configured" if ingestion_service else "not_configured"
        },
        "features": {
            "finding_normalization": True,
            "threat_intelligence_enrichment": opencti_enricher is not None,
            "attack_graph_generation": db_manager and db_manager.neo4j_driver is not None,
            "mitre_attack_mapping": True
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )