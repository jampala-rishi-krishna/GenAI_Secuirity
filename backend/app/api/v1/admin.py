"""
Admin API router for Healthcare GenAI Application
Provides system administration and monitoring endpoints
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, Field

from app.core.auth import auth_manager, require_view_system_metrics, require_manage_system, require_configure_security
from app.core.config import settings
from app.core.security import security_manager, SecurityLevel, ThreatType, SecurityEvent
from app.core.mfa_manager import mfa_manager
from app.core.session_manager import session_manager
from app.core.compliance_manager import compliance_manager, ComplianceStandard
from app.services.llm_service import llm_service
from app.core.config import settings

router = APIRouter()


class SystemStatusResponse(BaseModel):
    """System status response model"""
    status: str
    uptime: str
    version: str
    environment: str
    security_features: Dict[str, bool]
    last_updated: str


class SystemMetricsResponse(BaseModel):
    """System metrics response model"""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    active_connections: int
    requests_per_minute: float
    average_response_time: float
    error_rate: float
    last_updated: str


class SecurityDashboardResponse(BaseModel):
    """Security dashboard response model"""
    threat_landscape: Dict[str, Any]
    recent_security_events: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    last_updated: str


class SystemConfigRequest(BaseModel):
    """System configuration request model"""
    setting_name: str
    setting_value: Any
    description: Optional[str] = None


class SystemConfigResponse(BaseModel):
    """System configuration response model"""
    setting_name: str
    setting_value: Any
    description: Optional[str]
    updated_at: datetime
    updated_by: str


class MFAManagementRequest(BaseModel):
    """MFA management request model"""
    user_id: str
    action: str  # enable, disable, force_enable
    reason: Optional[str] = None


class MFAManagementResponse(BaseModel):
    """MFA management response model"""
    user_id: str
    action: str
    success: bool
    message: str
    mfa_status: Dict[str, Any]


class SessionManagementRequest(BaseModel):
    """Session management request model"""
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    action: str  # force_logout, extend, restrict
    reason: Optional[str] = None
    duration_hours: Optional[int] = None


class SessionManagementResponse(BaseModel):
    """Session management response model"""
    action: str
    success: bool
    message: str
    affected_sessions: int


class ComplianceUpdateRequest(BaseModel):
    """Compliance update request model"""
    rule_id: str
    compliance_status: str
    last_audited: Optional[str] = None
    notes: Optional[str] = None


class ComplianceUpdateResponse(BaseModel):
    """Compliance update response model"""
    rule_id: str
    success: bool
    message: str
    updated_status: Dict[str, Any]


# Mock data functions (replace with actual database queries)
async def get_threat_landscape_data():
    """Mock threat landscape data"""
    return {
        "risk_level": "medium",
        "active_threats": 3,
        "threat_categories": {
            "prompt_injection": {"count": 1, "severity": "high"},
            "data_leakage": {"count": 1, "severity": "medium"},
            "rate_limit_abuse": {"count": 1, "severity": "low"}
        },
        "trends": {
            "prompt_injection": "increasing",
            "data_leakage": "stable",
            "rate_limit_abuse": "decreasing"
        }
    }


def generate_security_recommendations(threat_landscape, security_events):
    """Generate security recommendations based on threat landscape and events"""
    recommendations = []
    
    if threat_landscape.get("risk_level") == "high":
        recommendations.append({
            "priority": "high",
            "category": "threat_response",
            "description": "High risk level detected. Review security logs and implement additional controls.",
            "action_items": ["Review recent security events", "Update threat detection rules", "Implement additional monitoring"]
        })
    
    # Add more recommendations based on specific threats
    return recommendations


@router.get("/system/status", response_model=SystemStatusResponse)
async def get_system_status(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get overall system status and health
    
    Requires view system metrics permission
    """
    try:
        # Calculate uptime (simplified)
        uptime = "24h"  # In production, calculate actual uptime
        
        # Get security features status
        security_features = {
            "prompt_injection_detection": settings.enable_prompt_injection_detection,
            "sensitive_data_filtering": settings.enable_sensitive_data_filtering,
            "output_validation": settings.enable_output_validation,
            "rate_limiting": settings.enable_rate_limiting,
            "audit_logging": settings.enable_audit_logging
        }
        
        return SystemStatusResponse(
            status="healthy",
            uptime=uptime,
            version=settings.app_version,
            environment=settings.environment,
            security_features=security_features,
            last_updated=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving system status: {str(e)}"
        )


@router.get("/system/metrics", response_model=SystemMetricsResponse)
async def get_system_metrics(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get system performance metrics
    
    Requires view system metrics permission
    """
    try:
        # Mock metrics (replace with actual system monitoring)
        return SystemMetricsResponse(
            cpu_usage=45.2,
            memory_usage=67.8,
            disk_usage=23.1,
            active_connections=127,
            requests_per_minute=45.6,
            average_response_time=0.23,
            error_rate=0.5,
            last_updated=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving system metrics: {str(e)}"
        )


@router.get("/security/dashboard", response_model=SecurityDashboardResponse)
async def get_security_dashboard(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get comprehensive security dashboard data
    
    Requires view system metrics permission
    """
    try:
        # RBAC: optional admin email allow-list as additional control
        if settings.admin_allowed_emails and getattr(current_user, 'email', '').lower() not in [e.lower() for e in settings.admin_allowed_emails]:
            raise HTTPException(status_code=403, detail="Admin access restricted")
        
        # Get threat landscape
        threat_landscape = await get_threat_landscape_data()
        
        # Get recent security events
        recent_events = security_manager.security_events[-20:]  # Last 20 events
        security_events = [
            {
                "timestamp": event.timestamp.isoformat(),
                "threat_type": event.threat_type.value,
                "security_level": event.security_level.value,
                "description": event.description,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "mitigation_applied": event.mitigation_applied
            }
            for event in recent_events
        ]
        
        # Get compliance status
        compliance_status = compliance_manager.get_overall_compliance_status()
        
        # Generate recommendations
        recommendations = generate_security_recommendations(threat_landscape, security_events)
        
        return SecurityDashboardResponse(
            threat_landscape=threat_landscape,
            recent_security_events=security_events,
            compliance_status=compliance_status,
            recommendations=recommendations,
            last_updated=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving security dashboard: {str(e)}"
        )


@router.get("/security/audit-log")
async def get_security_audit_log(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    threat_type: Optional[str] = None,
    security_level: Optional[str] = None,
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get filtered security audit log
    
    Requires view system metrics permission
    """
    try:
        # Get all security events
        events = security_manager.security_events
        
        # Apply filters
        if start_date:
            start_dt = datetime.fromisoformat(start_date)
            events = [e for e in events if e.timestamp >= start_dt]
        
        if end_date:
            end_dt = datetime.fromisoformat(end_date)
            events = [e for e in events if e.timestamp <= end_dt]
        
        if threat_type:
            events = [e for e in events if e.threat_type.value == threat_type]
        
        if security_level:
            events = [e for e in events if e.security_level.value == security_level]
        
        # Format events for response
        audit_log = [
            {
                "timestamp": event.timestamp.isoformat(),
                "threat_type": event.threat_type.value,
                "security_level": event.security_level.value,
                "description": event.description,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "request_data": event.request_data,
                "mitigation_applied": event.mitigation_applied,
                "success": event.success
            }
            for event in events[-100:]  # Limit to last 100 events
        ]
        
        return {
            "audit_log": audit_log,
            "total_events": len(audit_log),
            "filters_applied": {
                "start_date": start_date,
                "end_date": end_date,
                "threat_type": threat_type,
                "security_level": security_level
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving audit log: {str(e)}"
        )


@router.post("/system/configure", response_model=SystemConfigResponse)
async def configure_system_setting(
    request: SystemConfigRequest,
    current_user: Dict = Depends(require_manage_system)
):
    """
    Configure system settings
    
    Requires manage system permission
    """
    try:
        # Validate setting name
        valid_settings = [
            "enable_prompt_injection_detection",
            "enable_sensitive_data_filtering",
            "enable_output_validation",
            "enable_rate_limiting",
            "enable_audit_logging",
            "log_level",
            "rate_limit_requests",
            "guest_rate_limit_requests"
        ]
        
        if request.setting_name not in valid_settings:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid setting name. Valid settings: {valid_settings}"
            )
        
        # Update setting (in production, this would update a database)
        # For now, we'll just return the configuration
        
        # Log configuration change
        security_manager.log_security_event(
            SecurityEvent(
                timestamp=datetime.utcnow(),
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                security_level=SecurityLevel.LOW,
                description=f"System configuration updated: {request.setting_name}",
                user_id=current_user.user_id,
                ip_address=None,
                request_data={"setting": request.setting_name, "value": request.setting_value},
                mitigation_applied="Configuration updated",
                success=True
            )
        )
        
        return SystemConfigResponse(
            setting_name=request.setting_name,
            setting_value=request.setting_value,
            description=request.description,
            updated_at=datetime.utcnow(),
            updated_by=current_user.user_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error configuring system: {str(e)}"
        )


# New MFA Management Endpoints
@router.post("/mfa/manage", response_model=MFAManagementResponse)
async def manage_user_mfa(
    request: MFAManagementRequest,
    current_user: Dict = Depends(require_manage_system)
):
    """
    Manage MFA for users
    
    Requires manage system permission
    """
    try:
        # Mock user data (replace with database query)
        user = {"id": request.user_id, "role": "user", "mfa_enabled": False}
        
        if request.action == "enable":
            # Enable MFA for user
            user["mfa_enabled"] = True
            message = f"MFA enabled for user {request.user_id}"
        elif request.action == "disable":
            # Check if user is admin (MFA required for admins)
            if user.get("role") in ["admin", "super_admin"]:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot disable MFA for admin users"
                )
            user["mfa_enabled"] = False
            message = f"MFA disabled for user {request.user_id}"
        elif request.action == "force_enable":
            user["mfa_enabled"] = True
            message = f"MFA force enabled for user {request.user_id}"
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid action. Use: enable, disable, or force_enable"
            )
        
        # Get MFA status summary
        mfa_status = mfa_manager.get_mfa_status_summary([user])
        
        return MFAManagementResponse(
            user_id=request.user_id,
            action=request.action,
            success=True,
            message=message,
            mfa_status=mfa_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error managing MFA: {str(e)}"
        )


@router.get("/mfa/status")
async def get_mfa_status(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get MFA status summary for all users
    
    Requires view system metrics permission
    """
    try:
        # Mock users data (replace with database query)
        users = [
            {"role": "user", "mfa_enabled": False},
            {"role": "admin", "mfa_enabled": True},
            {"role": "super_admin", "mfa_enabled": True}
        ]
        
        mfa_status = mfa_manager.get_mfa_status_summary(users)
        return mfa_status
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving MFA status: {str(e)}"
        )


# New Session Management Endpoints
@router.post("/sessions/manage", response_model=SessionManagementResponse)
async def manage_user_sessions(
    request: SessionManagementRequest,
    current_user: Dict = Depends(require_manage_system)
):
    """
    Manage user sessions
    
    Requires manage system permission
    """
    try:
        affected_sessions = 0
        
        if request.action == "force_logout":
            if request.session_id:
                # Force logout specific session
                if session_manager.force_logout_session(request.session_id, request.reason or "Admin force logout"):
                    affected_sessions = 1
            elif request.user_id:
                # Force logout all sessions for user
                affected_sessions = session_manager.force_logout_user(request.user_id, request.reason or "Admin force logout")
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Must provide either session_id or user_id"
                )
            
            message = f"Force logout completed. {affected_sessions} sessions affected."
            
        elif request.action == "extend":
            if not request.session_id:
                raise HTTPException(
                    status_code=400,
                    detail="session_id required for extend action"
                )
            # Extend session (mock implementation)
            affected_sessions = 1
            message = "Session extended successfully"
            
        elif request.action == "restrict":
            if not request.user_id:
                raise HTTPException(
                    status_code=400,
                    detail="user_id required for restrict action"
                )
            # Restrict user sessions (mock implementation)
            affected_sessions = 1
            message = "User sessions restricted successfully"
            
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid action. Use: force_logout, extend, or restrict"
            )
        
        return SessionManagementResponse(
            action=request.action,
            success=True,
            message=message,
            affected_sessions=affected_sessions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error managing sessions: {str(e)}"
        )


@router.get("/sessions/active")
async def get_active_sessions(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get active sessions summary
    
    Requires view system metrics permission
    """
    try:
        sessions_summary = session_manager.get_active_sessions_summary()
        return sessions_summary
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving active sessions: {str(e)}"
        )


@router.get("/sessions/analytics")
async def get_session_analytics(
    hours: int = 24,
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get session analytics for specified time period
    
    Requires view system metrics permission
    """
    try:
        if hours < 1 or hours > 168:  # Max 1 week
            raise HTTPException(
                status_code=400,
                detail="Hours must be between 1 and 168"
            )
        
        analytics = session_manager.get_session_analytics(hours)
        return analytics
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving session analytics: {str(e)}"
        )


# New Compliance Management Endpoints
@router.get("/compliance/status")
async def get_compliance_status(
    standard: Optional[str] = None,
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get compliance status for specific standard or overall
    
    Requires view system metrics permission
    """
    try:
        if standard:
            # Get specific standard compliance
            if standard.upper() == "HIPAA":
                status = compliance_manager.get_compliance_status(ComplianceStandard.HIPAA)
            elif standard.upper() == "GDPR":
                status = compliance_manager.get_compliance_status(ComplianceStandard.GDPR)
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid standard. Use: HIPAA or GDPR"
                )
            return status
        else:
            # Get overall compliance status
            return compliance_manager.get_overall_compliance_status()
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving compliance status: {str(e)}"
        )


@router.post("/compliance/update", response_model=ComplianceUpdateResponse)
async def update_compliance_rule(
    request: ComplianceUpdateRequest,
    current_user: Dict = Depends(require_manage_system)
):
    """
    Update compliance rule status
    
    Requires manage system permission
    """
    try:
        updates = {
            "compliance_status": request.compliance_status
        }
        
        if request.last_audited:
            updates["last_audited"] = request.last_audited
        
        success = compliance_manager.update_compliance_rule(request.rule_id, updates)
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"Compliance rule {request.rule_id} not found"
            )
        
        # Get updated status
        rule = compliance_manager.compliance_rules.get(request.rule_id)
        updated_status = {
            "rule_id": rule.rule_id,
            "standard": rule.standard.value,
            "category": rule.category,
            "compliance_status": rule.compliance_status,
            "last_audited": rule.last_audited.isoformat() if rule.last_audited else None
        }
        
        return ComplianceUpdateResponse(
            rule_id=request.rule_id,
            success=True,
            message=f"Compliance rule {request.rule_id} updated successfully",
            updated_status=updated_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error updating compliance rule: {str(e)}"
        )


@router.get("/compliance/recommendations")
async def get_compliance_recommendations(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get compliance improvement recommendations
    
    Requires view system metrics permission
    """
    try:
        recommendations = compliance_manager.get_compliance_recommendations()
        return {
            "recommendations": recommendations,
            "total_recommendations": len(recommendations),
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving compliance recommendations: {str(e)}"
        )


@router.get("/system/health-check")
async def run_system_health_check(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Run comprehensive system health check
    
    Requires view system metrics permission
    """
    try:
        # Mock health check results
        health_results = {
            "database": {"status": "healthy", "response_time": "2ms"},
            "redis": {"status": "healthy", "response_time": "1ms"},
            "external_apis": {"status": "healthy", "response_time": "150ms"},
            "security_services": {"status": "healthy", "last_check": datetime.utcnow().isoformat()},
            "overall_status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return health_results
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error running health check: {str(e)}"
        )


@router.get("/system/backup-status")
async def get_backup_status(
    current_user: Dict = Depends(require_view_system_metrics)
):
    """
    Get system backup status
    
    Requires view system metrics permission
    """
    try:
        # Mock backup status
        backup_status = {
            "last_backup": "2024-01-15T02:00:00Z",
            "next_backup": "2024-01-16T02:00:00Z",
            "backup_type": "full",
            "status": "successful",
            "size": "2.3GB",
            "retention_days": 30,
            "backup_location": "secure_cloud_storage"
        }
        
        return backup_status
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving backup status: {str(e)}"
        ) 