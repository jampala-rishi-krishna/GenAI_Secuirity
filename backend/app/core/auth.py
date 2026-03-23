"""
Authentication and Authorization system for Healthcare GenAI Application
Implements RBAC (Role-Based Access Control) and secure JWT token management
"""

import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from enum import Enum
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import logging

from app.core.config import settings


class UserRole(Enum):
    """User role enumeration for RBAC"""
    GUEST = "guest"
    USER = "user"
    HEALTHCARE_PROFESSIONAL = "healthcare_professional"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class Permission(Enum):
    """Permission enumeration for fine-grained access control"""
    # Chat permissions
    BASIC_CHAT = "basic_chat"
    ADVANCED_CHAT = "advanced_chat"
    CHAT_HISTORY = "chat_history"
    
    # User management
    VIEW_USERS = "view_users"
    MANAGE_USERS = "manage_users"
    DELETE_USERS = "delete_users"
    
    # Security and monitoring
    VIEW_SECURITY_LOGS = "view_security_logs"
    MANAGE_SECURITY = "manage_security"
    VIEW_SYSTEM_METRICS = "view_system_metrics"
    
    # System configuration
    MANAGE_SYSTEM = "manage_system"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    CONFIGURE_SECURITY = "configure_security"


# Role-Permission mapping
ROLE_PERMISSIONS = {
    UserRole.GUEST: [
        Permission.BASIC_CHAT
    ],
    UserRole.USER: [
        Permission.BASIC_CHAT,
        Permission.CHAT_HISTORY
    ],
    UserRole.HEALTHCARE_PROFESSIONAL: [
        Permission.BASIC_CHAT,
        Permission.ADVANCED_CHAT,
        Permission.CHAT_HISTORY
    ],
    UserRole.ADMIN: [
        Permission.BASIC_CHAT,
        Permission.ADVANCED_CHAT,
        Permission.CHAT_HISTORY,
        Permission.VIEW_USERS,
        Permission.MANAGE_USERS,
        Permission.VIEW_SECURITY_LOGS,
        Permission.VIEW_SYSTEM_METRICS
    ],
    UserRole.SUPER_ADMIN: [
        Permission.BASIC_CHAT,
        Permission.ADVANCED_CHAT,
        Permission.CHAT_HISTORY,
        Permission.VIEW_USERS,
        Permission.MANAGE_USERS,
        Permission.DELETE_USERS,
        Permission.VIEW_SECURITY_LOGS,
        Permission.MANAGE_SECURITY,
        Permission.VIEW_SYSTEM_METRICS,
        Permission.MANAGE_SYSTEM,
        Permission.VIEW_AUDIT_LOGS,
        Permission.CONFIGURE_SECURITY
    ]
}


class User(BaseModel):
    """User model for authentication"""
    id: str
    email: str
    username: str
    role: UserRole
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False


class TokenData(BaseModel):
    """Token data structure"""
    user_id: str
    email: str
    role: UserRole
    permissions: List[Permission]
    exp: datetime


class AuthManager:
    """Authentication and authorization manager"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security = HTTPBearer()
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_access_token(self, user: User) -> str:
        """Create JWT access token"""
        permissions = ROLE_PERMISSIONS.get(user.role, [])
        permissions_str = [p.value for p in permissions]
        
        token_data = {
            "user_id": user.id,
            "email": user.email,
            "role": user.role.value,
            "permissions": permissions_str,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expiration_minutes)
        }
        
        token = jwt.encode(token_data, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return token
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        token_data = {
            "user_id": user.id,
            "email": user.email,
            "exp": datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expiration_days)
        }
        
        token = jwt.encode(token_data, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return token
    
    def verify_token(self, token: str) -> TokenData:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
            
            # Convert permissions back to enum
            permissions = [Permission(p) for p in payload.get("permissions", [])]
            
            token_data = TokenData(
                user_id=payload["user_id"],
                email=payload["email"],
                role=UserRole(payload["role"]),
                permissions=permissions,
                exp=datetime.fromtimestamp(payload["exp"])
            )
            
            return token_data
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> TokenData:
        """Get current authenticated user from token"""
        token = credentials.credentials
        return self.verify_token(token)
    
    def get_current_user_optional(self, credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[TokenData]:
        """Get current authenticated user from token (optional for guest access)"""
        if not credentials:
            return None
        try:
            token = credentials.credentials
            return self.verify_token(token)
        except HTTPException:
            return None
    
    def check_permission(self, user: TokenData, required_permission: Permission) -> bool:
        """Check if user has required permission"""
        return required_permission in user.permissions
    
    def require_permission(self, permission: Permission):
        """Dependency to require specific permission"""
        def permission_checker(user: TokenData = Depends(AuthManager().get_current_user)):
            if not self.check_permission(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permission.value}"
                )
            return user
        return permission_checker
    
    def require_role(self, required_role: UserRole):
        """Dependency to require specific role"""
        def role_checker(user: TokenData = Depends(AuthManager().get_current_user)):
            if user.role.value < required_role.value:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient role. Required: {required_role.value}, Current: {user.role.value}"
                )
            return user
        return role_checker
    
    def get_user_permissions(self, role: UserRole) -> List[Permission]:
        """Get permissions for a specific role"""
        return ROLE_PERMISSIONS.get(role, [])
    
    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength"""
        validation_result = {
            "is_valid": True,
            "errors": [],
            "strength_score": 0
        }
        
        # Length check
        if len(password) < 8:
            validation_result["errors"].append("Password must be at least 8 characters long")
            validation_result["is_valid"] = False
        
        # Complexity checks
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not has_upper:
            validation_result["errors"].append("Password must contain at least one uppercase letter")
            validation_result["is_valid"] = False
        
        if not has_lower:
            validation_result["errors"].append("Password must contain at least one lowercase letter")
            validation_result["is_valid"] = False
        
        if not has_digit:
            validation_result["errors"].append("Password must contain at least one digit")
            validation_result["is_valid"] = False
        
        if not has_special:
            validation_result["errors"].append("Password must contain at least one special character")
            validation_result["is_valid"] = False
        
        # Calculate strength score
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if has_upper and has_lower:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1
        
        validation_result["strength_score"] = score
        
        return validation_result


# Global auth manager instance
auth_manager = AuthManager()


# Common permission dependencies
require_basic_chat = auth_manager.require_permission(Permission.BASIC_CHAT)
require_advanced_chat = auth_manager.require_permission(Permission.ADVANCED_CHAT)
require_chat_history = auth_manager.require_permission(Permission.CHAT_HISTORY)
require_view_users = auth_manager.require_permission(Permission.VIEW_USERS)
require_manage_users = auth_manager.require_permission(Permission.MANAGE_USERS)
require_view_security_logs = auth_manager.require_permission(Permission.VIEW_SECURITY_LOGS)
require_manage_security = auth_manager.require_permission(Permission.MANAGE_SECURITY)
require_view_system_metrics = auth_manager.require_permission(Permission.VIEW_SYSTEM_METRICS)
require_manage_system = auth_manager.require_permission(Permission.MANAGE_SYSTEM)
require_configure_security = auth_manager.require_permission(Permission.CONFIGURE_SECURITY)

# Common role dependencies
require_user_role = auth_manager.require_role(UserRole.USER)
require_healthcare_professional = auth_manager.require_role(UserRole.HEALTHCARE_PROFESSIONAL)
require_admin = auth_manager.require_role(UserRole.ADMIN)
require_super_admin = auth_manager.require_role(UserRole.SUPER_ADMIN) 