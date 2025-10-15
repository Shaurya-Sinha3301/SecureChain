"""
API Models for SecureChain Backend

Pydantic models for request/response validation and serialization.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ChatMessage(BaseModel):
    """Model for chat message requests."""
    message: str = Field(..., description="The user's message", min_length=1, max_length=2000)
    user_id: Optional[str] = Field(None, description="Optional user identifier")


class ChatResponse(BaseModel):
    """Model for chat response."""
    success: bool = Field(..., description="Whether the request was successful")
    response: str = Field(..., description="The AI's response")
    context_used: bool = Field(..., description="Whether context from knowledge base was used")
    context_count: int = Field(..., description="Number of context documents used")
    user_id: str = Field(..., description="User identifier")
    timestamp: str = Field(..., description="Response timestamp")
    error: Optional[str] = Field(None, description="Error message if request failed")


class KnowledgeDocument(BaseModel):
    """Model for adding documents to knowledge base."""
    content: str = Field(..., description="Document content", min_length=10)
    metadata: Optional[Dict[str, Any]] = Field(None, description="Optional document metadata")


class KnowledgeRequest(BaseModel):
    """Model for adding multiple documents to knowledge base."""
    documents: List[str] = Field(..., description="List of document contents", min_items=1)


class HealthResponse(BaseModel):
    """Model for health check response."""
    service: str = Field(..., description="Overall service status")
    knowledge_db: str = Field(..., description="Knowledge database status")
    chatbot: str = Field(..., description="Chatbot service status")
    timestamp: str = Field(..., description="Health check timestamp")


class ErrorResponse(BaseModel):
    """Model for error responses."""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class VulnerabilityInfo(BaseModel):
    """Model for vulnerability information."""
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    severity: str = Field(..., description="Vulnerability severity")
    description: str = Field(..., description="Vulnerability description")
    remediation: Optional[str] = Field(None, description="Remediation steps")


class ScanResult(BaseModel):
    """Model for scan results."""
    scan_type: str = Field(..., description="Type of scan (nmap, nikto, etc.)")
    target: str = Field(..., description="Scan target")
    findings: List[Dict[str, Any]] = Field(..., description="Scan findings")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())