# Healthcare GenAI Security - Complete Setup Guide

This guide provides step-by-step instructions for setting up the Healthcare GenAI Security Application without Docker.

## 🎯 Prerequisites

### System Requirements
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 10GB free space
- **OS**: Windows 10/11, macOS 10.15+, or Ubuntu 18.04+

### Required Software
- **Python 3.9+** - [Download](https://python.org/downloads/)
- **Node.js 18+** - [Download](https://nodejs.org/)
- **PostgreSQL 12+** - [Download](https://postgresql.org/download/)
- **Redis 6+** - [Download](https://redis.io/download)

## 🚀 Installation Steps

### Step 1: Install Python
1. Download Python 3.9+ from [python.org](https://python.org/downloads/)
2. **Important**: Check "Add Python to PATH" during installation
3. Verify installation:
   ```bash
   python --version
   pip --version
   ```

### Step 2: Install Node.js
1. Download Node.js 18+ from [nodejs.org](https://nodejs.org/)
2. Install with default settings
3. Verify installation:
   ```bash
   node --version
   npm --version
   ```

### Step 3: Install PostgreSQL
1. Download from [postgresql.org](https://postgresql.org/download/)
2. Install with default settings
3. **Remember the password** you set for the postgres user
4. Verify installation:
   ```bash
   psql --version
   ```

### Step 4: Install Redis
1. **Windows**: Download from [GitHub releases](https://github.com/microsoftarchive/redis/releases)
2. **macOS**: `brew install redis`
3. **Linux**: `sudo apt-get install redis-server`
4. Verify installation:
   ```bash
   redis-cli --version
   ```

## ⚙️ Configuration

### Step 1: Clone Repository
```bash
git clone <your-repository-url>
cd healthcare-genai-security
```

### Step 2: Create Environment File
1. Copy `.env.example` to `.env`
2. Update with your settings:
   ```bash
   # Groq API Configuration
   GROQ_MODEL=llama-3.1-8b-instant
   
   # Database Configuration
   DATABASE_URL=postgresql://healthcare_user:secure_password_123@localhost/healthcare_ai
   REDIS_URL=redis://localhost:6379
   
   # Security Configuration
   JWT_SECRET=your-super-secret-jwt-key-change-in-production
   ENVIRONMENT=development
   DEBUG=true
   ```

### Step 3: Set Up Database
1. Start PostgreSQL service
2. Open psql:
   ```bash
   psql -U postgres
   ```
3. Create database and user:
   ```sql
   CREATE DATABASE healthcare_ai;
   CREATE USER healthcare_user WITH PASSWORD 'secure_password_123';
   GRANT ALL PRIVILEGES ON DATABASE healthcare_ai TO healthcare_user;
   \q
   ```

### Step 4: Start Redis
1. **Windows**: Start Redis service
2. **macOS**: `brew services start redis`
3. **Linux**: `sudo systemctl start redis`

## 📦 Install Dependencies

### Backend Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Frontend Dependencies
```bash
cd frontend
npm install
```

## 🚀 Start the Application

### Terminal 1: Backend
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Terminal 2: Frontend
```bash
cd frontend
npm run dev
```

## ✅ Verification

### Check Services
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Test Security Features
1. Go to http://localhost:3000/chat
2. Try the security test buttons
3. Check the security dashboard
4. Verify OWASP compliance

## 🐛 Troubleshooting

### Common Issues

#### Python Not Found
```bash
# Windows: Add Python to PATH
# macOS: brew install python3
# Linux: sudo apt-get install python3
```

#### Node.js Not Found
```bash
# Windows: Reinstall Node.js
# macOS: brew install node
# Linux: sudo apt-get install nodejs npm
```

#### PostgreSQL Connection Failed
```bash
# Check if service is running
# Windows: Services app
# macOS: brew services list
# Linux: sudo systemctl status postgresql
```

#### Redis Connection Failed
```bash
# Check if service is running
# Windows: Services app
# macOS: brew services list
# Linux: sudo systemctl status redis
```

#### Port Already in Use
```bash
# Check what's using the port
netstat -an | findstr :8000  # Windows
lsof -i :8000                # macOS/Linux
```

### Error Messages

#### "Module not found"
```bash
# Reinstall dependencies
cd backend && pip install -r requirements.txt
cd ../frontend && npm install
```

#### "Database connection failed"
```bash
# Check PostgreSQL is running
# Verify connection string in .env
# Check firewall settings
```

#### "Redis connection failed"
```bash
# Check Redis is running
# Verify Redis URL in .env
# Check Redis configuration
```

## 🔧 Development Workflow

### Making Changes
1. **Backend**: Changes auto-reload with `--reload` flag
2. **Frontend**: Changes auto-reload with `npm run dev`
3. **Database**: Restart backend after schema changes

### Testing Changes
1. **Security Features**: Use test buttons in chat interface
2. **API Endpoints**: Use http://localhost:8000/docs
3. **Frontend**: Check browser console for errors

### Debugging
1. **Backend Logs**: Check terminal running uvicorn
2. **Frontend Logs**: Check browser console
3. **Database**: Use `psql -U healthcare_user -d healthcare_ai`

## 📚 Additional Resources

### Documentation
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [PostgreSQL Documentation](https://postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)

### Security Resources
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Healthcare Security Best Practices](https://www.hhs.gov/hipaa/for-professionals/security/)
- [AI Security Guidelines](https://www.nist.gov/ai)

## 🆘 Getting Help

### Before Asking for Help
1. ✅ Check this guide thoroughly
2. ✅ Verify all prerequisites are installed
3. ✅ Check service status (PostgreSQL, Redis)
4. ✅ Review error logs
5. ✅ Ensure ports are available

### When Asking for Help
1. **Describe your issue** clearly
2. **Include error messages** exactly as shown
3. **Mention your OS** and versions
4. **Share relevant logs** or screenshots
5. **List what you've already tried**

---

**Happy coding! 🚀**

This setup gives you full control over your development environment and helps you understand how each component works together. 