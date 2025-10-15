"""
SecureChain Backend API

Main FastAPI application for the SecureChain cybersecurity platform.
Provides endpoints for AI chatbot functionality and vulnerability management.
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
from datetime import datetime

from chatbot_service import CybersecurityChatbotService
from api_models import (
    ChatMessage, ChatResponse, KnowledgeRequest, 
    HealthResponse, ErrorResponse
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global chatbot service instance
chatbot_service = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global chatbot_service
    
    # Startup
    logger.info("Starting SecureChain Backend...")
    try:
        chatbot_service = CybersecurityChatbotService()
        logger.info("Chatbot service initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize chatbot service: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down SecureChain Backend...")


# Create FastAPI app
app = FastAPI(
    title="SecureChain API",
    description="Backend API for SecureChain cybersecurity platform",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React/Vite dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_chatbot_service() -> CybersecurityChatbotService:
    """Dependency to get chatbot service instance."""
    if chatbot_service is None:
        raise HTTPException(status_code=503, detail="Chatbot service not available")
    return chatbot_service


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "SecureChain Backend API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health", response_model=HealthResponse)
async def health_check(service: CybersecurityChatbotService = Depends(get_chatbot_service)):
    """Health check endpoint."""
    try:
        health_status = service.health_check()
        return HealthResponse(**health_status)
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Health check failed")


@app.post("/chat", response_model=ChatResponse)
async def chat(
    message: ChatMessage,
    service: CybersecurityChatbotService = Depends(get_chatbot_service)
):
    """
    Process a chat message and return AI response.
    
    This endpoint handles cybersecurity-related questions and provides
    AI-powered responses using the integrated knowledge base.
    """
    try:
        result = service.process_message(message.message, message.user_id)
        return ChatResponse(**result)
    except Exception as e:
        logger.error(f"Chat processing failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to process message")


@app.post("/knowledge/add")
async def add_knowledge(
    request: KnowledgeRequest,
    service: CybersecurityChatbotService = Depends(get_chatbot_service)
):
    """
    Add documents to the knowledge base.
    
    This endpoint allows adding new cybersecurity knowledge documents
    that will be used for context in chat responses.
    """
    try:
        success = service.add_knowledge(request.documents)
        if success:
            return {
                "success": True,
                "message": f"Added {len(request.documents)} documents to knowledge base",
                "timestamp": datetime.now().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to add documents")
    except Exception as e:
        logger.error(f"Knowledge addition failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to add knowledge")


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc)
        ).dict()
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )