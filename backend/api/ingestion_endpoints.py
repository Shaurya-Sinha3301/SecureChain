"""
FastAPI endpoints for vulnerability finding ingestion
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

from services.ingestion_service import IngestionService
from services.database_manager import DatabaseManager
from services.opencti_enricher import OpenCTIEnricher

logger = logging.getLogger(__name__)

# Pydantic models for API
class ScanResultsRequest(BaseModel):
    """Request model for scan results ingestion"""
    scan_results: Dict[str, Any] = Field(..., description="Raw scan results")
    scan_tool: str = Field(..., description="Name of the scanning tool")
    target: str = Field(..., description="Scan target (IP/hostname)")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class IngestionResponse(BaseModel):
    """Response model for ingestion requests"""
    success: bool
    findings_processed: int
    findings: List[str]
    timestamp: str
    scan_tool: str
    target: str
    error: Optional[str] = None

class FindingResponse(BaseModel):
    """Response model for individual findings"""
    finding_id: str
    host: str
    ip: str
    service: Optional[str]
    port: Optional[int]
    version: Optional[str]
    cve: Optional[str]
    cvss: Optional[float]
    evidence: str
    scan_tool: str
    severity: str
    status: str
    created_at: str
    # OpenCTI enrichment fields
    opencti_indicator_id: Optional[str] = None
    opencti_vulnerability_id: Optional[str] = None
    opencti_malware_ids: Optional[List[str]] = None
    opencti_attack_patterns: Optional[List[Dict[str, Any]]] = None
    exploit_available: Optional[bool] = None
    threat_actor_groups: Optional[List[Dict[str, Any]]] = None

class AttackGraphResponse(BaseModel):
    """Response model for attack graph data"""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    timestamp: str

class IngestionStatsResponse(BaseModel):
    """Response model for ingestion statistics"""
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_tool: Dict[str, int]
    findings_by_status: Dict[str, int]
    enriched_findings: int
    findings_with_cve: int
    findings_with_exploits: int

# Global service instances (will be initialized in main app)
ingestion_service: Optional[IngestionService] = None
db_manager: Optional[DatabaseManager] = None

def get_ingestion_service() -> IngestionService:
    """Dependency to get ingestion service"""
    if ingestion_service is None:
        raise HTTPException(status_code=503, detail="Ingestion service not available")
    return ingestion_service

def get_db_manager() -> DatabaseManager:
    """Dependency to get database manager"""
    if db_manager is None:
        raise HTTPException(status_code=503, detail="Database manager not available")
    return db_manager

# Create router
router = APIRouter(prefix="/api/v1/ingestion", tags=["ingestion"])

@router.post("/scan-results", response_model=IngestionResponse)
async def ingest_scan_results(
    request: ScanResultsRequest,
    background_tasks: BackgroundTasks,
    service: IngestionService = Depends(get_ingestion_service)
):
    """
    Ingest scan results and process through complete workflow:
    1. Normalize findings
    2. Enrich with OpenCTI
    3. Store in PostgreSQL
    4. Create attack graph in Neo4j
    """
    try:
        logger.info(f"Received scan results from {request.scan_tool} for target {request.target}")
        
        # Process in background for better performance
        result = await service.process_scan_results_async(
            scan_results=request.scan_results,
            scan_tool=request.scan_tool,
            target=request.target
        )
        
        if result['success']:
            return IngestionResponse(**result)
        else:
            raise HTTPException(status_code=500, detail=result.get('error', 'Processing failed'))
            
    except Exception as e:
        logger.error(f"Scan results ingestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan-results/sync", response_model=IngestionResponse)
async def ingest_scan_results_sync(
    request: ScanResultsRequest,
    service: IngestionService = Depends(get_ingestion_service)
):
    """
    Synchronous version of scan results ingestion
    """
    try:
        logger.info(f"Received sync scan results from {request.scan_tool} for target {request.target}")
        
        result = service.process_scan_results(
            scan_results=request.scan_results,
            scan_tool=request.scan_tool,
            target=request.target
        )
        
        if result['success']:
            return IngestionResponse(**result)
        else:
            raise HTTPException(status_code=500, detail=result.get('error', 'Processing failed'))
            
    except Exception as e:
        logger.error(f"Sync scan results ingestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/findings", response_model=List[FindingResponse])
async def get_findings(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    scan_tool: Optional[str] = None,
    status: Optional[str] = None,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Retrieve vulnerability findings with optional filters
    """
    try:
        findings = db.get_findings(limit=limit, offset=offset)
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f.get('severity') == severity]
        if scan_tool:
            findings = [f for f in findings if f.get('scan_tool') == scan_tool]
        if status:
            findings = [f for f in findings if f.get('status') == status]
        
        return [FindingResponse(**finding) for finding in findings]
        
    except Exception as e:
        logger.error(f"Failed to retrieve findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Retrieve a specific vulnerability finding
    """
    try:
        session = db.get_postgres_session()
        finding = session.query(db.VulnerabilityFinding).filter(
            db.VulnerabilityFinding.finding_id == finding_id
        ).first()
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        return FindingResponse(**finding.to_dict())
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve finding {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/attack-graph", response_model=AttackGraphResponse)
async def get_attack_graph(
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Retrieve attack graph data from Neo4j
    """
    try:
        graph_data = db.get_attack_graph()
        
        return AttackGraphResponse(
            nodes=graph_data['nodes'],
            edges=graph_data['edges'],
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Failed to retrieve attack graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats", response_model=IngestionStatsResponse)
async def get_ingestion_stats(
    service: IngestionService = Depends(get_ingestion_service)
):
    """
    Get ingestion service statistics
    """
    try:
        stats = service.get_ingestion_stats()
        
        if 'error' in stats:
            raise HTTPException(status_code=500, detail=stats['error'])
        
        return IngestionStatsResponse(**stats)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get ingestion stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/findings/{finding_id}/enrich")
async def enrich_finding(
    finding_id: str,
    service: IngestionService = Depends(get_ingestion_service),
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Re-enrich a specific finding with latest OpenCTI data
    """
    try:
        if not service.opencti_enricher:
            raise HTTPException(status_code=503, detail="OpenCTI enricher not available")
        
        # Get finding from database
        session = db.get_postgres_session()
        finding = session.query(db.VulnerabilityFinding).filter(
            db.VulnerabilityFinding.finding_id == finding_id
        ).first()
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Enrich finding
        finding_dict = finding.to_dict()
        enrichment_data = service.opencti_enricher.enrich_finding(finding_dict)
        
        # Update in database
        db.update_finding_opencti_data(finding_id, enrichment_data)
        
        return {
            "success": True,
            "finding_id": finding_id,
            "enrichment_data": enrichment_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enrich finding {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/findings/{finding_id}")
async def delete_finding(
    finding_id: str,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Delete a vulnerability finding
    """
    try:
        session = db.get_postgres_session()
        finding = session.query(db.VulnerabilityFinding).filter(
            db.VulnerabilityFinding.finding_id == finding_id
        ).first()
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        session.delete(finding)
        session.commit()
        
        return {
            "success": True,
            "finding_id": finding_id,
            "message": "Finding deleted successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete finding {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    status: str,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Update finding status (open, investigating, resolved)
    """
    try:
        valid_statuses = ['open', 'investigating', 'resolved']
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
        
        session = db.get_postgres_session()
        finding = session.query(db.VulnerabilityFinding).filter(
            db.VulnerabilityFinding.finding_id == finding_id
        ).first()
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        finding.status = status
        finding.updated_at = datetime.utcnow()
        session.commit()
        
        return {
            "success": True,
            "finding_id": finding_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update finding status {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))