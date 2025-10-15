"""
SecureChain Chatbot Service

Core service for handling cybersecurity AI chatbot functionality.
This module provides the main chatbot application class that integrates
the vector database and Gemini AI for security-focused conversations.
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from dotenv import load_dotenv

from database import KnowledgeVectorDatabase
from gemini import CybersecurityChatbot

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))


class CybersecurityChatbotService:
    """
    Main service class for the cybersecurity chatbot.
    
    This class handles the integration between the vector database for context
    retrieval and the Gemini AI for response generation.
    """
    
    def __init__(self):
        """Initialize the chatbot service with knowledge base and AI integration."""
        self.knowledge_db = self._initialize_knowledge_db()
        self.chatbot = self._initialize_chatbot()

    def _initialize_knowledge_db(self) -> KnowledgeVectorDatabase:
        """Initialize and return the knowledge vector database."""
        return KnowledgeVectorDatabase()

    def _initialize_chatbot(self) -> CybersecurityChatbot:
        """Initialize and return the Gemini chatbot instance."""
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("Google API key not found. Please set GOOGLE_API_KEY in your .env file.")
        return CybersecurityChatbot(api_key=api_key)

    def process_message(self, message: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a user message and generate a response.
        
        Args:
            message: The user's message/question
            user_id: Optional user identifier for conversation tracking
            
        Returns:
            Dictionary containing response data and metadata
        """
        if user_id is None:
            user_id = str(uuid.uuid4())
            
        try:
            # Get relevant context from knowledge base
            context_results = self.knowledge_db.get_relevant_context(message, top_k=3)
            context = "\n".join([f"- {doc}" for doc, _ in context_results])
            
            # Generate AI response
            response_data = self.chatbot.generate_response(
                user_id=user_id,
                message=message,
                context=context
            )
            
            return {
                "success": True,
                "response": response_data['text'],
                "context_used": len(context_results) > 0,
                "context_count": len(context_results),
                "user_id": user_id,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "response": f"I encountered an error processing your request: {str(e)}",
                "user_id": user_id,
                "timestamp": datetime.now().isoformat()
            }

    def add_knowledge(self, documents: list) -> bool:
        """
        Add new documents to the knowledge base.
        
        Args:
            documents: List of text documents to add
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.knowledge_db.add_documents(documents)
            return True
        except Exception:
            return False

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on the service components.
        
        Returns:
            Dictionary with health status of each component
        """
        status = {
            "service": "healthy",
            "knowledge_db": "unknown",
            "chatbot": "unknown",
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Test knowledge database
            test_results = self.knowledge_db.get_relevant_context("test", top_k=1)
            status["knowledge_db"] = "healthy" if test_results else "no_data"
        except Exception as e:
            status["knowledge_db"] = f"error: {str(e)}"
        
        try:
            # Test chatbot (simple check)
            if hasattr(self.chatbot, 'model') and self.chatbot.model:
                status["chatbot"] = "healthy"
            else:
                status["chatbot"] = "not_initialized"
        except Exception as e:
            status["chatbot"] = f"error: {str(e)}"
        
        # Overall status
        if status["knowledge_db"] == "healthy" and status["chatbot"] == "healthy":
            status["service"] = "healthy"
        else:
            status["service"] = "degraded"
        
        return status


# Legacy compatibility
CybersecurityChatbotApp = CybersecurityChatbotService