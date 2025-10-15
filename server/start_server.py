#!/usr/bin/env python3
"""
SecureChain Backend Server Starter

Simple script to start the FastAPI backend server with proper configuration.
"""

import os
import sys
import uvicorn
from dotenv import load_dotenv

def main():
    """Start the SecureChain backend server."""
    # Load environment variables
    load_dotenv()
    
    # Get configuration from environment
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    debug = os.getenv("DEBUG", "True").lower() == "true"
    reload = os.getenv("RELOAD", "True").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    
    print("🛡️  Starting SecureChain Backend Server")
    print("=" * 40)
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Debug: {debug}")
    print(f"Reload: {reload}")
    print(f"Log Level: {log_level}")
    print("=" * 40)
    
    try:
        uvicorn.run(
            "main:app",
            host=host,
            port=port,
            reload=reload,
            log_level=log_level,
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()