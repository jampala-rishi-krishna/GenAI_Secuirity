"""
Users API router for Healthcare GenAI Application
Provides user management and authentication endpoints
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, Field, EmailStr
import uuid

from app.core.auth import auth_manager, UserRole, Permission, require_view_users, require_manage_users, User, TokenData
from app.core.config import settings
from app.services.otp_service import otp_service
from app.services.email_service import email_service
from app.core.security import security_manager, SecurityLevel, ThreatType, SecurityEvent

router = APIRouter()


class UserCreateRequest(BaseModel):
    """User creation request model"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    role: str = Field("user", description="User role")


class UserResponse(BaseModel):
    """User response model"""
    id: str
    email: str
    username: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime]
    mfa_enabled: bool


class UserUpdateRequest(BaseModel):
    """User update request model"""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    role: Optional[str] = Field(None, description="User role")
    is_active: Optional[bool] = Field(None, description="User active status")


class LoginRequest(BaseModel):
    """Login request model"""
    email: EmailStr
    password: str


class LoginStep1Response(BaseModel):
    """Response for login step 1 (OTP sent)"""
    requires_otp: bool = True
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


class OTPVerifyResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class LoginResponse(BaseModel):
    """Login response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


# In-memory user storage (replace with database in production)
users_db: Dict[str, Dict] = {}
user_sessions: Dict[str, Dict] = {}


@router.post("/register", response_model=UserResponse)
async def register_user(request: UserCreateRequest):
    """Register a new user"""
    try:
        # Check if user already exists
        if any(user["email"] == request.email for user in users_db.values()):
            raise HTTPException(
                status_code=400,
                detail="User with this email already exists"
            )
        
        if any(user["username"] == request.username for user in users_db.values()):
            raise HTTPException(
                status_code=400,
                detail="Username already taken"
            )
        
        # Validate password strength
        password_validation = auth_manager.validate_password_strength(request.password)
        if not password_validation["is_valid"]:
            raise HTTPException(
                status_code=400,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )
        
        # Validate role
        try:
            user_role = UserRole(request.role)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid role: {request.role}"
            )
        
        # Create user
        user_id = str(uuid.uuid4())
        hashed_password = auth_manager.hash_password(request.password)
        
        user = {
            "id": user_id,
            "email": request.email,
            "username": request.username,
            "password_hash": hashed_password,
            "role": user_role.value,
            "is_active": True,
            "is_verified": False,
            "created_at": datetime.now(timezone.utc),
            "last_login": None,
            "mfa_enabled": False
        }
        
        users_db[user_id] = user
        
        # Log security event
        security_manager.log_security_event(
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                security_level=SecurityLevel.LOW,
                description=f"New user registered: {request.email}",
                user_id=user_id,
                ip_address=None,
                request_data={"email": request.email, "role": request.role},
                mitigation_applied="User account created",
                success=True
            )
        )
        
        return UserResponse(
            id=user["id"],
            email=user["email"],
            username=user["username"],
            role=user["role"],
            is_active=user["is_active"],
            is_verified=user["is_verified"],
            created_at=user["created_at"],
            last_login=user["last_login"],
            mfa_enabled=user["mfa_enabled"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error registering user: {str(e)}"
        )


@router.post("/login", response_model=LoginStep1Response)
async def login_user(request: LoginRequest, http_request: Request):
    """Login step 1: validate user exists and email is allowed for admin if needed, send OTP via email"""
    try:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Login request for email: {request.email}")
        
        # Find user by email (case-insensitive)
        user = None
        for u in users_db.values():
            if u["email"].lower() == request.email.lower():
                user = u
                break
        
        if not user:
            logger.info(f"User not found, creating new user for: {request.email}")
            # For this interim flow, allow first-time login to self-register BASIC user
            user_id = str(uuid.uuid4())
            user = {
                "id": user_id,
                "email": request.email,
                "username": request.email.split("@")[0],
                "password_hash": auth_manager.hash_password(request.password),
                "role": UserRole.USER.value,
                "is_active": True,
                "is_verified": False,
                "created_at": datetime.now(timezone.utc),
                "last_login": None,
                "mfa_enabled": True,
            }
            # Elevate role if email is in admin allow-list
            if settings.admin_allowed_emails and request.email.lower() in [e.strip().lower() for e in settings.admin_allowed_emails]:
                user["role"] = UserRole.SUPER_ADMIN.value
            users_db[user_id] = user
            logger.info(f"New user created: {user_id} - {request.email}")
        else:
            logger.info(f"Existing user found: {user['id']} - {user['email']}")
            # Elevate role if email is in admin allow-list
            if settings.admin_allowed_emails and user["email"].lower() in [e.strip().lower() for e in settings.admin_allowed_emails]:
                if user.get("role") != UserRole.SUPER_ADMIN.value:
                    user["role"] = UserRole.SUPER_ADMIN.value
        
        if not user["is_active"]:
            raise HTTPException(
                status_code=401,
                detail="User account is deactivated"
            )
        
        # Temporary: do not enforce password (as requested); proceed to MFA OTP
        # If you want to still check password when provided, uncomment:
        # if request.password and not auth_manager.verify_password(request.password, user["password_hash"]):
        #     raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # If admin route access is desired later, ensure email is in allowed list
        if settings.admin_allowed_emails and user["email"].lower() not in [e.strip().lower() for e in settings.admin_allowed_emails]:
            # User can still login, but won't pass admin RBAC later
            pass

        # Generate and send OTP
        logger.info(f"Generating OTP for user: {user['email']}")
        otp = otp_service.generate_otp(user["email"], ttl_seconds=300)
        email_sent = email_service.send_otp(user["email"], otp)
        logger.info(f"OTP generated and email service result: {email_sent}")

        return LoginStep1Response(requires_otp=True, email=user["email"])
        
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error during login: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error during login: {str(e)}"
        )


@router.post("/login/verify", response_model=OTPVerifyResponse)
async def verify_login_otp(request: OTPVerifyRequest, http_request: Request):
    """Login step 2: verify OTP and issue tokens if valid"""
    try:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"OTP verification request for email: {request.email}, OTP: {request.otp}")
        
        # Find user by email
        user = None
        logger.info(f"Searching for user with email: {request.email}")
        logger.info(f"Available users in DB: {[{'id': u['id'], 'email': u['email']} for u in users_db.values()]}")
        
        for u in users_db.values():
            if u["email"].lower() == request.email.lower():
                user = u
                break
                
        if not user:
            logger.error(f"User not found for email: {request.email}")
            raise HTTPException(status_code=401, detail="Invalid session")

        logger.info(f"User found: {user['id']} - {user['email']}")

        # Verify OTP
        otp_valid = otp_service.verify_otp(request.email, request.otp)
        logger.info(f"OTP verification result for {request.email}: {otp_valid}")
        
        if not otp_valid:
            logger.warning(f"Invalid OTP for {request.email}: {request.otp}")
            raise HTTPException(status_code=401, detail="Invalid or expired OTP")

        logger.info(f"OTP verification successful for {request.email}")

        user["last_login"] = datetime.now(timezone.utc)
        logger.info(f"Creating User object with data: {user}")
        logger.info(f"Data types: id={type(user['id'])}, email={type(user['email'])}, username={type(user['username'])}, role={type(user['role'])}, is_active={type(user['is_active'])}, is_verified={type(user['is_verified'])}, created_at={type(user['created_at'])}, last_login={type(user['last_login'])}")
        
        try:
            user_obj = User(
                id=user["id"],
                email=user["email"],
                username=user["username"],
                role=UserRole(user["role"]),
                is_active=user["is_active"],
                is_verified=user["is_verified"],
                created_at=user["created_at"],
                last_login=user["last_login"],
                mfa_enabled=True,
            )
            logger.info(f"User object created successfully: {user_obj}")
        except Exception as e:
            logger.error(f"Error creating User object: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Error creating user object: {str(e)}"
            )
        
        logger.info(f"Creating tokens for user: {user['id']}")
        try:
            access_token = auth_manager.create_access_token(user_obj)
            refresh_token = auth_manager.create_refresh_token(user_obj)
            logger.info(f"Tokens created successfully")
        except Exception as e:
            logger.error(f"Error creating tokens: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Error creating authentication tokens: {str(e)}"
            )

        security_manager.log_security_event(
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                security_level=SecurityLevel.LOW,
                description=f"Successful MFA login for user: {request.email}",
                user_id=user["id"],
                ip_address=http_request.client.host if http_request.client else "unknown",
                request_data={"email": request.email, "role": user["role"]},
                mitigation_applied="Login successful",
                success=True,
            )
        )

        logger.info(f"Login successful for {request.email}")
        # Ensure elevated role is reflected in response payload
        elevated_role = user.get("role", UserRole.USER.value)
        return OTPVerifyResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=30 * 60,
            user=UserResponse(
                id=user["id"],
                email=user["email"],
                username=user["username"],
                role=elevated_role,
                is_active=user["is_active"],
                is_verified=user["is_verified"],
                created_at=user["created_at"],
                last_login=user["last_login"],
                mfa_enabled=True,
            ),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Unexpected error during OTP verification: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error during login: {str(e)}"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Get current user information"""
    try:
        user_id = current_user.user_id
        
        if user_id not in users_db:
            # Fallback: construct minimal user info from token when in-memory store was reset
            from datetime import datetime, timezone
            return UserResponse(
                id=user_id,
                email=current_user.email,
                username=current_user.email.split("@")[0],
                role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                is_active=True,
                is_verified=True,
                created_at=datetime.now(timezone.utc),
                last_login=None,
                mfa_enabled=True
            )
        
        user = users_db[user_id]
        
        return UserResponse(
            id=user["id"],
            email=user["email"],
            username=user["username"],
            role=user["role"],
            is_active=user["is_active"],
            is_verified=user["is_verified"],
            created_at=user["created_at"],
            last_login=user["last_login"],
            mfa_enabled=user["mfa_enabled"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving user information: {str(e)}"
        )


@router.get("/", response_model=List[UserResponse])
async def get_users(
    skip: int = 0,
    limit: int = 100,
    current_user: Dict = Depends(require_view_users)
):
    """Get list of users (paginated)"""
    try:
        user_list = list(users_db.values())[skip:skip + limit]
        
        return [
            UserResponse(
                id=user["id"],
                email=user["email"],
                username=user["username"],
                role=user["role"],
                is_active=user["is_active"],
                is_verified=user["is_verified"],
                created_at=user["created_at"],
                last_login=user["last_login"],
                mfa_enabled=user["mfa_enabled"]
            )
            for user in user_list
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving users: {str(e)}"
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: Dict = Depends(require_view_users)
):
    """Get specific user by ID"""
    try:
        if user_id not in users_db:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        user = users_db[user_id]
        
        return UserResponse(
            id=user["id"],
            email=user["email"],
            username=user["username"],
            role=user["role"],
            is_active=user["is_active"],
            is_verified=user["is_verified"],
            created_at=user["created_at"],
            last_login=user["last_login"],
            mfa_enabled=user["mfa_enabled"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving user: {str(e)}"
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    request: UserUpdateRequest,
    current_user: Dict = Depends(require_manage_users)
):
    """Update user information"""
    try:
        if user_id not in users_db:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        user = users_db[user_id]
        
        # Update fields if provided
        if request.username is not None:
            # Check if username is already taken
            if any(u["username"] == request.username and u["id"] != user_id for u in users_db.values()):
                raise HTTPException(
                    status_code=400,
                    detail="Username already taken"
                )
            user["username"] = request.username
        
        if request.role is not None:
            try:
                UserRole(request.role)  # Validate role
                user["role"] = request.role
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid role: {request.role}"
                )
        
        if request.is_active is not None:
            user["is_active"] = request.is_active
        
        # Log security event
        security_manager.log_security_event(
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                security_level=SecurityLevel.LOW,
                description=f"User updated: {user_id} by {current_user.user_id}",
                user_id=current_user.user_id,
                ip_address=None,
                request_data={"updated_user": user_id, "changes": request.dict()},
                mitigation_applied="User updated",
                success=True
            )
        )
        
        return UserResponse(
            id=user["id"],
            email=user["email"],
            username=user["username"],
            role=user["role"],
            is_active=user["is_active"],
            is_verified=user["is_verified"],
            created_at=user["created_at"],
            last_login=user["last_login"],
            mfa_enabled=user["mfa_enabled"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error updating user: {str(e)}"
        )


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user: Dict = Depends(require_manage_users)
):
    """Delete a user (soft delete)"""
    try:
        if user_id not in users_db:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # Prevent self-deletion
        if user_id == current_user.user_id:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete your own account"
            )
        
        # Soft delete by deactivating
        users_db[user_id]["is_active"] = False
        
        # Log security event
        security_manager.log_security_event(
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                security_level=SecurityLevel.MEDIUM,
                description=f"User deactivated: {user_id} by {current_user.user_id}",
                user_id=current_user.user_id,
                ip_address=None,
                request_data={"deactivated_user": user_id},
                mitigation_applied="User deactivated",
                success=True
            )
        )
        
        return {"message": "User deactivated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error deactivating user: {str(e)}"
        ) 