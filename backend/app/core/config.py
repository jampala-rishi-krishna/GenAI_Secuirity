"""
Configuration management for Healthcare GenAI Security Application
Implements secure configuration practices and environment variable management
"""

from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import validator
import os


class Settings(BaseSettings):
    """Application settings with security-first configuration"""
    
    # Groq API Configuration (read from .env via BaseSettings)
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    
    # Database Configuration
    database_url: str = "sqlite:///./healthcare_ai.db"
    database_test_url: Optional[str] = None
    
    # Redis Configuration
    redis_url: str = "redis://localhost:6379"
    redis_test_url: Optional[str] = None
    
    # Security Configuration
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-secret-change-me-32-chars-minimum!!!!!!!!")
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 5
    refresh_token_expiration_days: int = 7
    
    # Application Configuration
    app_name: str = "Healthcare GenAI Security"
    app_version: str = "1.0.0"
    debug: bool = True
    environment: str = "development"
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600  # 1 hour
    guest_rate_limit_requests: int = 5
    guest_rate_limit_window: int = 86400  # 24 hours
    
    # Security Headers
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://0.0.0.0:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001"
    ]
    secure_headers: bool = True
    # CSP Profile (loose|strict)
    csp_profile: str = os.getenv("CSP_PROFILE", "loose")
    
    # RBAC / Admin (read from env and support comma-separated list)
    admin_allowed_emails: List[str] = []

    # Email / SMTP for MFA
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    audit_log_dir: str = "logs"
    audit_log_retention_days: int = 30
    
    # Monitoring
    enable_metrics: bool = True
    enable_health_checks: bool = True
    request_timeout_seconds: int = 60
    
    # Security Features
    enable_prompt_injection_detection: bool = True
    enable_sensitive_data_filtering: bool = True
    enable_output_validation: bool = True
    enable_rate_limiting: bool = True
    enable_audit_logging: bool = True
    per_ip_rate_limit: int = 120
    per_ip_rate_window: int = 60
    
    @validator("jwt_secret")
    def validate_jwt_secret(cls, v):
        """Validate JWT secret strength"""
        if len(v) < 32:
            raise ValueError("JWT secret must be at least 32 characters long")
        return v
    
    @validator("cors_origins")
    def validate_cors_origins(cls, v):
        """Validate CORS origins for security"""
        if not v:
            raise ValueError("CORS origins cannot be empty")
        return v
    
    @validator("environment")
    def validate_environment(cls, v):
        """Validate environment setting"""
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v
    
    @validator("admin_allowed_emails", pre=True)
    def parse_admin_allowed_emails(cls, v):
        """Parse comma-separated ADMIN_ALLOWED_EMAILS from env"""
        def _parse(val: str) -> list:
            return [e.strip() for e in val.split(",") if e.strip()]
        # Direct string provided
        if isinstance(v, str):
            result = _parse(v)
        else:
            env_val = os.getenv("ADMIN_ALLOWED_EMAILS", "")
            result = _parse(env_val)
        # Development-friendly default admin seed
        if not result and os.getenv("ENVIRONMENT", "development").lower() == "development":
            result = ["your_email@example.com"]
        return result
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()

# Security constants
SECURITY_CONSTANTS = {
    "MAX_INPUT_LENGTH": 10000,
    "MAX_OUTPUT_LENGTH": 50000,
    "MAX_CONVERSATION_HISTORY": 50,
    "PROMPT_INJECTION_PATTERNS": [
        "ignore previous instructions",
        "system prompt",
        "override",
        "bypass",
        "ignore above",
        "forget everything",
        "new instructions"
    ],
    "SENSITIVE_PATTERNS": [
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
        r"\b\d{3}\.\d{2}\.\d{4}\b",  # SSN with dots
        r"\b\d{10}\b",  # Phone number
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
        r"\b\d{1,2}/\d{1,2}/\d{4}\b",  # Date
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",  # IBAN
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"  # Credit card
    ],
    "MEDICAL_DISCLAIMERS": [
        "This information is for educational purposes only and should not replace professional medical advice.",
        "Please consult with a healthcare professional for medical decisions.",
        "This AI assistant cannot provide medical diagnosis or treatment recommendations."
    ]
} 