"""
Main FastAPI application for Healthcare GenAI Security Application
Implements comprehensive security measures and API endpoints
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, Request, HTTPException, status, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import uvicorn

from app.core.config import settings
from app.core.security import security_manager, SecurityLevel, ThreatType, SecurityEvent
from app.core.auth import auth_manager, UserRole, Permission
from app.services.llm_service import llm_service, ChatMessage
from fastapi import APIRouter
from app.api.v1 import chat, security, users, admin

# Request timeout middleware
class TimeoutMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import asyncio
        try:
            return await asyncio.wait_for(call_next(request), timeout=settings.request_timeout_seconds)
        except asyncio.TimeoutError:
            return JSONResponse(status_code=504, content={"error": "Request timeout"})

# Basic per-IP rate limiting (fallback; recommend Redis-backed in production)
class PerIpRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.cache: Dict[str, Dict[str, Any]] = {}

    async def dispatch(self, request: Request, call_next):
        import time as _t
        ip = request.client.host if request.client else "unknown"
        now = _t.time()
        window = settings.per_ip_rate_window
        max_req = settings.per_ip_rate_limit
        entry = self.cache.get(ip)
        if entry is None or now - entry["start"] > window:
            self.cache[ip] = {"start": now, "count": 1}
        else:
            entry["count"] += 1
            if entry["count"] > max_req:
                return JSONResponse(status_code=429, content={"error": "Too Many Requests"})
        return await call_next(request)

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting Healthcare GenAI Security Application")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Security features enabled: {settings.enable_prompt_injection_detection}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Healthcare GenAI Security Application")
    await llm_service.close()


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="A comprehensive Healthcare GenAI Application with OWASP Top 10 security implementation",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# CORS middleware MUST be outermost for proper preflight and error responses
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=r"https?://(localhost|127\\.0\\.0\\.1)(:\\d+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*", "Authorization", "Content-Type", "Accept"],
    expose_headers=["*"],
)

# Add middleware after app is created
app.add_middleware(TimeoutMiddleware)
app.add_middleware(PerIpRateLimitMiddleware)


# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security middleware for request processing"""
    start_time = time.time()
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Log environment and CSP profile for debugging
    logger.debug(f"Environment: {settings.environment}, CSP Profile: {settings.csp_profile}")
    
    # Security headers
    response = await call_next(request)
    
    # Add security headers (more permissive in development)
    if settings.environment != "development":
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # Force development-friendly CSP for local development
    if settings.secure_headers:
        # Always use development CSP when running locally or in debug mode
        if settings.environment == "development" or settings.debug or "localhost" in str(request.url) or "127.0.0.1" in str(request.url):
            # Very permissive CSP for development - allows all Next.js features including 'unsafe-eval'
            response.headers["Content-Security-Policy"] = (
                "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "
                "script-src * 'unsafe-inline' 'unsafe-eval' blob:; "
                "style-src * 'unsafe-inline' 'unsafe-eval'; "
                "img-src * data: blob: https:; "
                "connect-src * ws: wss:; "
                "frame-ancestors *; "
                "base-uri *; "
                "form-action *; "
                "worker-src * blob:; "
                "child-src * blob:; "
                "font-src * data:; "
                "media-src * blob:; "
                "object-src *; "
                "manifest-src *;"
            )
        else:
            # Production CSP
            if settings.environment != "development":
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            
            if settings.csp_profile == "strict":
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self'; "
                    "img-src 'self' data:; "
                    "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000; "
                    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                )
            else:
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000; "
                    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                )

    # Advisory headers to reduce overreliance (LLM09)
    response.headers["AI-Advice-Only"] = "true"
    response.headers["AI-Requires-Verification"] = "true"
    response.headers["RateLimit-Policy"] = f"ip; window={settings.per_ip_rate_window}; max={settings.per_ip_rate_limit}"
    
    # Log security events
    processing_time = time.time() - start_time
    if processing_time > 5.0:  # Log slow requests
        logger.warning(f"Slow request detected: {request.url} took {processing_time:.2f}s from {client_ip}")
    
    return response


 

# Trusted host middleware
if settings.environment == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure with actual domains in production
    )


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with security logging"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    
    # Log security event for unexpected errors
    from datetime import datetime
    security_manager.log_security_event(
        SecurityEvent(
            timestamp=datetime.utcnow(),
            threat_type=ThreatType.MALICIOUS_INPUT,
            security_level=SecurityLevel.MEDIUM,
            description=f"Unhandled exception: {str(exc)}",
            user_id=None,
            ip_address=request.client.host if request.client else None,
            request_data={"url": str(request.url), "method": request.method},
            mitigation_applied="Exception caught and logged",
            success=False
        )
    )
    
    from datetime import datetime
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    from datetime import datetime
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.app_version,
        "environment": settings.environment,
        "security_features": {
            "prompt_injection_detection": settings.enable_prompt_injection_detection,
            "sensitive_data_filtering": settings.enable_sensitive_data_filtering,
            "output_validation": settings.enable_output_validation,
            "rate_limiting": settings.enable_rate_limiting,
            "audit_logging": settings.enable_audit_logging
        }
    }


# Security status endpoint
@app.get("/security/status")
async def security_status():
    """Security status endpoint for monitoring"""
    from datetime import datetime
    try:
        security_report = security_manager.generate_security_report()
        return {
            "status": "secure",
            "timestamp": datetime.utcnow().isoformat(),
            "security_report": security_report,
            "owasp_coverage": {
                "LLM01": "Prompt Injection Prevention - ✅ Implemented",
                "LLM02": "Sensitive Information Disclosure - ✅ Implemented",
                "LLM03": "Supply Chain Security - ✅ Implemented",
                "LLM05": "Improper Output Handling - ✅ Implemented",
                "LLM06": "Excessive Agency - ✅ Implemented",
                "LLM07": "System Prompt Leakage - ✅ Implemented",
                "LLM08": "Vector and Embedding Weaknesses - ✅ Implemented",
                "LLM09": "Misinformation - ✅ Implemented",
                "LLM10": "Unbounded Consumption - ✅ Implemented"
            }
        }
    except Exception as e:
        logger.error(f"Error generating security status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error generating security status"
        )


# Include API routers
app.include_router(chat.router, prefix="/api/v1/chat", tags=["Chat"])
app.include_router(security.router, prefix="/api/v1/security", tags=["Security"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin"])


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with application information"""
    return {
        "application": settings.app_name,
        "version": settings.app_version,
        "description": "Healthcare GenAI Security Application",
        "security_features": "OWASP Top 10 for LLM Applications 2025",
        "documentation": "/docs",
        "health_check": "/health",
        "security_status": "/security/status"
    }


# Basic metrics endpoint (JSON)
@app.get("/metrics")
async def metrics():
    try:
        report = security_manager.generate_security_report()
    except Exception:
        report = {}
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "uptime_hint": "see logs",
        "security_events_total": len(security_manager.security_events),
        "security_report": report,
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    ) 