# Healthcare GenAI Security-First Implementation

A comprehensive Healthcare GenAI Application that demonstrates security implementation following the OWASP Top 10 for LLM Applications 2025.

## 🛡️ Security Features

### OWASP LLM Top 10 Coverage
- **LLM01:2025 Prompt Injection** - Input validation and filtering
- **LLM02:2025 Sensitive Information Disclosure** - Data sanitization
- **LLM03:2025 Supply Chain** - Secure dependencies and model sourcing
- **LLM05:2025 Improper Output Handling** - Output validation and encoding
- **LLM06:2025 Excessive Agency** - Least privilege access
- **LLM07:2025 System Prompt Leakage** - Secure prompt management
- **LLM08:2025 Vector and Embedding Weaknesses** - RAG security
- **LLM09:2025 Misinformation** - Output verification and disclaimers
- **LLM10:2025 Unbounded Consumption** - Rate limiting and resource management

## 🏗️ Architecture

```
Frontend (Next.js) → Backend (FastAPI) → LLM Service (Groq)
                            ↓
                    Security Layer + Database (PostgreSQL + Redis)
```

## 🚀 Quick Start

### Prerequisites
- **Python 3.9+** - [Download Python](https://python.org/downloads/)
- **Node.js 18+** - [Download Node.js](https://nodejs.org/)
- **PostgreSQL** - [Download PostgreSQL](https://postgresql.org/download/)
- **Redis** - [Download Redis](https://redis.io/download)

### Automated Setup
```bash
# Windows
setup-windows.bat

# macOS/Linux
./setup-unix.sh
```

### Manual Setup
1. **Install Dependencies**
   ```bash
   # Backend
   cd backend
   pip install -r requirements.txt
   
   # Frontend
   cd frontend
   npm install
   ```

2. **Configure Environment**
   - Copy `.env.example` to `.env`
   - Update with your Groq API key and database settings

3. **Start Services**
   ```bash
   # Terminal 1: Backend
   cd backend
   uvicorn main:app --reload
   
   # Terminal 2: Frontend
   cd frontend
   npm run dev
   ```

4. **Access Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## 🔐 User Roles & Access Control

- **Guest User**: Limited chat access (5 queries/day)
- **Registered User**: Full chat access with rate limits
- **Healthcare Professional**: Enhanced query limits, professional resources
- **Admin User**: System monitoring, user management
- **Super Admin**: Full system access, security configuration

## 📊 Security Dashboard Features

- Real-time threat detection
- Security metrics visualization
- Compliance tracking
- Interactive security demos
- Educational tooltips

## 🧪 Testing

```bash
# Security testing
cd backend
pytest tests/security/

# Frontend testing
cd frontend
npm run test
```

## 📈 Monitoring

- Real-time security alerts
- Performance metrics
- Compliance status
- Threat landscape overview

## 🔒 Compliance

- OWASP Top 10 for LLM Applications 2025
- Healthcare data protection standards
- HIPAA compliance considerations
- GDPR compliance features

## 📚 Documentation

- [Complete Setup Guide](SETUP.md)
- [Security Implementation Guide](docs/security.md)
- [API Documentation](docs/api.md)
- [Client Showcase Guide](docs/showcase.md)

## 🆘 Need Help?

1. **Check SETUP.md** for detailed installation steps
2. **Verify prerequisites** are installed correctly
3. **Check service status** (PostgreSQL, Redis)
4. **Review logs** for error messages
5. **Ensure ports** 3000, 8000, 5432, 6379 are available 