"""
Session Management System for Healthcare GenAI Application
Implements session monitoring, timeout management, and concurrent session limits
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from enum import Enum
from pydantic import BaseModel
import logging
from dataclasses import dataclass, field
import uuid

from app.core.config import settings


class SessionStatus(Enum):
    """Session status enumeration"""
    ACTIVE = "active"
    EXPIRED = "expired"
    FORCE_LOGOUT = "force_logout"
    SUSPICIOUS = "suspicious"


class SessionType(Enum):
    """Session type enumeration"""
    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    ADMIN = "admin"


@dataclass
class UserSession:
    """User session data structure"""
    session_id: str
    user_id: str
    username: str
    role: str
    session_type: SessionType
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE
    is_admin: bool = False
    mfa_verified: bool = False
    device_fingerprint: Optional[str] = None
    location_data: Optional[Dict] = None
    risk_score: float = 0.0
    flags: Set[str] = field(default_factory=set)


class SessionManager:
    """Session management system with monitoring and control capabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.active_sessions: Dict[str, UserSession] = {}
        self.user_sessions: Dict[str, List[str]] = {}  # user_id -> [session_ids]
        self.session_timeouts = {
            SessionType.WEB: timedelta(hours=8),
            SessionType.MOBILE: timedelta(days=30),
            SessionType.API: timedelta(hours=24),
            SessionType.ADMIN: timedelta(hours=4)  # Stricter for admin
        }
        self.max_concurrent_sessions = {
            SessionType.WEB: 3,
            SessionType.MOBILE: 2,
            SessionType.API: 5,
            SessionType.ADMIN: 1  # Only one admin session at a time
        }
        
    def create_session(
        self, 
        user_id: str, 
        username: str, 
        role: str, 
        session_type: SessionType,
        ip_address: str,
        user_agent: str,
        device_fingerprint: Optional[str] = None,
        location_data: Optional[Dict] = None
    ) -> UserSession:
        """Create a new user session"""
        session_id = str(uuid.uuid4())
        now = datetime.utcnow()
        expires_at = now + self.session_timeouts[session_type]
        
        # Check concurrent session limits
        if not self._can_create_session(user_id, session_type):
            raise Exception(f"Maximum concurrent {session_type.value} sessions reached")
        
        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            role=role,
            session_type=session_type,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            last_activity=now,
            expires_at=expires_at,
            is_admin=role in ['admin', 'super_admin'],
            device_fingerprint=device_fingerprint,
            location_data=location_data
        )
        
        # Store session
        self.active_sessions[session_id] = session
        
        # Update user sessions mapping
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)
        
        self.logger.info(f"Created session {session_id} for user {username} ({session_type.value})")
        return session
    
    def _can_create_session(self, user_id: str, session_type: SessionType) -> bool:
        """Check if user can create a new session of given type"""
        if user_id not in self.user_sessions:
            return True
        
        current_sessions = [
            sid for sid in self.user_sessions[user_id]
            if sid in self.active_sessions and 
            self.active_sessions[sid].session_type == session_type and
            self.active_sessions[sid].status == SessionStatus.ACTIVE
        ]
        
        return len(current_sessions) < self.max_concurrent_sessions[session_type]
    
    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get session by ID"""
        return self.active_sessions.get(session_id)
    
    def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity and check expiration"""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        now = datetime.utcnow()
        
        # Check if session expired
        if now > session.expires_at:
            session.status = SessionStatus.EXPIRED
            self.logger.info(f"Session {session_id} expired")
            return False
        
        # Update last activity
        session.last_activity = now
        return True
    
    def force_logout_session(self, session_id: str, reason: str = "Admin force logout") -> bool:
        """Force logout a specific session"""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        session.status = SessionStatus.FORCE_LOGOUT
        session.flags.add(f"force_logout_{datetime.utcnow().isoformat()}")
        
        self.logger.warning(f"Force logout session {session_id}: {reason}")
        return True
    
    def force_logout_user(self, user_id: str, reason: str = "Admin force logout") -> int:
        """Force logout all sessions for a user"""
        if user_id not in self.user_sessions:
            return 0
        
        logged_out_count = 0
        for session_id in self.user_sessions[user_id]:
            if self.force_logout_session(session_id, reason):
                logged_out_count += 1
        
        self.logger.warning(f"Force logout {logged_out_count} sessions for user {user_id}: {reason}")
        return logged_out_count
    
    def get_user_sessions(self, user_id: str) -> List[UserSession]:
        """Get all active sessions for a user"""
        if user_id not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in self.user_sessions[user_id]:
            session = self.active_sessions.get(session_id)
            if session and session.status == SessionStatus.ACTIVE:
                sessions.append(session)
        
        return sessions
    
    def get_active_sessions_summary(self) -> Dict:
        """Get summary of all active sessions for admin dashboard"""
        total_sessions = len(self.active_sessions)
        active_sessions = sum(1 for s in self.active_sessions.values() if s.status == SessionStatus.ACTIVE)
        expired_sessions = sum(1 for s in self.active_sessions.values() if s.status == SessionStatus.EXPIRED)
        force_logout_sessions = sum(1 for s in self.active_sessions.values() if s.status == SessionStatus.FORCE_LOGOUT)
        
        # Session type breakdown
        type_breakdown = {}
        for session_type in SessionType:
            type_breakdown[session_type.value] = sum(
                1 for s in self.active_sessions.values() 
                if s.session_type == session_type and s.status == SessionStatus.ACTIVE
            )
        
        # Admin sessions
        admin_sessions = sum(1 for s in self.active_sessions.values() if s.is_admin and s.status == SessionStatus.ACTIVE)
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "expired_sessions": expired_sessions,
            "force_logout_sessions": force_logout_sessions,
            "type_breakdown": type_breakdown,
            "admin_sessions": admin_sessions,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count of cleaned sessions"""
        now = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if now > session.expires_at and session.status == SessionStatus.ACTIVE:
                session.status = SessionStatus.EXPIRED
                expired_sessions.append(session_id)
        
        self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        return len(expired_sessions)
    
    def get_session_analytics(self, hours: int = 24) -> Dict:
        """Get session analytics for the specified time period"""
        now = datetime.utcnow()
        cutoff_time = now - timedelta(hours=hours)
        
        # Filter sessions within time period
        recent_sessions = [
            s for s in self.active_sessions.values()
            if s.created_at >= cutoff_time
        ]
        
        # Calculate metrics
        total_sessions = len(recent_sessions)
        unique_users = len(set(s.user_id for s in recent_sessions))
        admin_sessions = sum(1 for s in recent_sessions if s.is_admin)
        
        # Session duration analysis
        session_durations = []
        for session in recent_sessions:
            if session.status != SessionStatus.ACTIVE:
                duration = (session.last_activity - session.created_at).total_seconds() / 3600  # hours
                session_durations.append(duration)
        
        avg_duration = sum(session_durations) / len(session_durations) if session_durations else 0
        
        return {
            "period_hours": hours,
            "total_sessions": total_sessions,
            "unique_users": unique_users,
            "admin_sessions": admin_sessions,
            "average_session_duration_hours": round(avg_duration, 2),
            "session_type_distribution": {
                session_type.value: sum(1 for s in recent_sessions if s.session_type == session_type)
                for session_type in SessionType
            }
        }


# Global session manager instance
session_manager = SessionManager()
