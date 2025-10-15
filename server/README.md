# SecureChain Backend Server

Clean, production-ready backend API for the SecureChain cybersecurity platform.

## 🏗️ Architecture

The backend is built with FastAPI and provides:
- **AI Chatbot Service**: Cybersecurity-focused AI assistant
- **Vector Database**: Semantic search for security knowledge
- **RESTful API**: Clean endpoints for frontend integration
- **CORS Support**: Ready for web application integration

## 📁 Project Structure

```
server/
├── main.py              # FastAPI application and routes
├── chatbot_service.py   # Core chatbot service logic
├── database.py          # Vector database for knowledge storage
├── gemini.py           # Google Gemini AI integration
├── api_models.py       # Pydantic models for API validation
├── start_server.py     # Server startup script
├── requirements.txt    # Python dependencies
├── .env               # Environment configuration
└── README.md          # This file
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Update `.env` with your Google API key:
```env
GOOGLE_API_KEY=your_actual_api_key_here
```

### 3. Start the Server
```bash
python start_server.py
```

Or directly with uvicorn:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 📡 API Endpoints

### Health Check
```http
GET /health
```

### Chat with AI
```http
POST /chat
Content-Type: application/json

{
  "message": "What is SQL injection?",
  "user_id": "optional-user-id"
}
```

### Add Knowledge
```http
POST /knowledge/add
Content-Type: application/json

{
  "documents": [
    "New security vulnerability information...",
    "Additional cybersecurity knowledge..."
  ]
}
```

## 🔧 Configuration

Environment variables in `.env`:

- `GOOGLE_API_KEY` - Google Gemini API key (required)
- `HOST` - Server host (default: 0.0.0.0)
- `PORT` - Server port (default: 8000)
- `DEBUG` - Debug mode (default: True)
- `ALLOWED_ORIGINS` - CORS allowed origins

## 🧪 Testing

The server includes built-in health checks and error handling. Test the API:

```bash
# Health check
curl http://localhost:8000/health

# Chat test
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is a vulnerability?"}'
```

## 🔌 Integration

This backend is designed to integrate with:
- React/Vue/Angular frontends
- Mobile applications
- Other microservices
- CI/CD pipelines for security scanning

## 🛡️ Security Features

- Input validation with Pydantic models
- CORS configuration for web security
- Error handling and logging
- Environment-based configuration
- API key protection

## 📈 Scaling

The backend is designed to be:
- **Stateless**: Easy to scale horizontally
- **Containerizable**: Ready for Docker deployment
- **Cloud-native**: Compatible with cloud platforms
- **Modular**: Easy to extend and modify

## 🔄 Development

For development with auto-reload:
```bash
python start_server.py
```

The server will automatically restart when code changes are detected.