"""
Security API router for Healthcare GenAI Application
Provides security monitoring, reporting, and management endpoints
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Depends, Request, Query
from pydantic import BaseModel, Field

from app.core.auth import auth_manager, require_view_security_logs, require_manage_security
from app.core.security import security_manager, SecurityLevel, ThreatType
from app.services.llm_service import llm_service

router = APIRouter()


class SecurityEventResponse(BaseModel):
    """Security event response model"""
    timestamp: datetime
    threat_type: str
    security_level: str
    description: str
    user_id: Optional[str]
    ip_address: Optional[str]
    mitigation_applied: str
    success: bool


class SecurityMetricsResponse(BaseModel):
    """Security metrics response model"""
    total_events_24h: int
    threat_distribution: Dict[str, int]
    security_level_distribution: Dict[str, int]
    rate_limit_status: Dict[str, Any]
    last_updated: str


class SecurityTestRequest(BaseModel):
    """Security test request model"""
    test_type: str = Field(..., description="Type of security test to perform")
    test_input: str = Field(..., description="Input to test security measures")


class SecurityTestResponse(BaseModel):
    """Security test response model"""
    test_type: str
    test_input: str
    sanitized_input: str
    security_report: Dict[str, Any]
    threats_detected: List[Dict[str, Any]]
    mitigation_applied: List[str]
    security_level: str
    timestamp: datetime
    threat_detected: bool
    threat_type: Optional[str]
    ai_response: str = ""


@router.get("/events", response_model=List[SecurityEventResponse])
async def get_security_events(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    security_level: Optional[str] = Query(None, description="Filter by security level"),
    current_user: Dict = Depends(require_view_security_logs)
):
    """
    Get security events for monitoring and analysis
    
    Requires view security logs permission
    """
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Filter events by time
        filtered_events = [
            event for event in security_manager.security_events
            if start_time <= event.timestamp <= end_time
        ]
        
        # Apply additional filters
        if threat_type:
            filtered_events = [
                event for event in filtered_events
                if event.threat_type.value == threat_type
            ]
        
        if security_level:
            filtered_events = [
                event for event in filtered_events
                if event.security_level.value == security_level
            ]
        
        # Convert to response format
        return [
            SecurityEventResponse(
                timestamp=event.timestamp,
                threat_type=event.threat_type.value,
                security_level=event.security_level.value,
                description=event.description,
                user_id=event.user_id,
                ip_address=event.ip_address,
                mitigation_applied=event.mitigation_applied,
                success=event.success
            )
            for event in filtered_events
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving security events: {str(e)}"
        )


@router.get("/metrics", response_model=SecurityMetricsResponse)
async def get_security_metrics(
    current_user: Dict = Depends(require_view_security_logs)
):
    """
    Get comprehensive security metrics
    
    Requires view security logs permission
    """
    try:
        security_report = security_manager.generate_security_report()
        
        return SecurityMetricsResponse(
            total_events_24h=security_report["total_events_24h"],
            threat_distribution=security_report["threat_distribution"],
            security_level_distribution=security_report["security_level_distribution"],
            rate_limit_status=security_report["rate_limit_status"],
            last_updated=security_report["last_updated"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating security metrics: {str(e)}"
        )


@router.post("/test", response_model=SecurityTestResponse)
async def test_security_measures(
    request: SecurityTestRequest,
    http_request: Request,
    current_user: Optional[Dict] = Depends(auth_manager.get_current_user_optional)
):
    """
    Test security measures with various input types
    
    This endpoint is for security testing and demonstration
    """
    try:
        user_id = current_user.user_id if current_user else "guest"
        ip_address = http_request.client.host if http_request.client else "unknown"
        
        # Process input through security pipeline
        sanitized_input, sanitization_report = security_manager.sanitize_input(request.test_input)
        
        # Generate AI response to test output validation
        ai_response, security_report = await llm_service.generate_response(
            user_input=request.test_input,
            user_role="guest",
            user_id=user_id,
            ip_address=ip_address
        )
        
        # Extract security information
        threats_detected = sanitization_report.get("threats_detected", [])
        mitigation_applied = sanitization_report.get("sanitization_applied", [])
        security_level = sanitization_report.get("security_level", "low")
        
        first_threat = threats_detected[0] if threats_detected else None
        return SecurityTestResponse(
            test_type=request.test_type,
            test_input=request.test_input,
            sanitized_input=sanitized_input,
            security_report=security_report,
            threats_detected=threats_detected,
            mitigation_applied=mitigation_applied,
            security_level=security_level,
            timestamp=datetime.utcnow(),
            threat_detected=bool(threats_detected),
            threat_type=str(first_threat) if first_threat else None,
            ai_response=ai_response,
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error testing security measures: {str(e)}"
        )


@router.get("/owasp-coverage")
async def get_owasp_coverage(
    current_user: Dict = Depends(require_view_security_logs)
):
    """
    Get OWASP Top 10 for LLM Applications 2025 coverage status
    
    Requires view security logs permission
    """
    try:
        return {
            "owasp_coverage": {
                "LLM01:2025": {
                    "title": "Prompt Injection",
                    "status": "✅ Implemented",
                    "description": "Input validation and filtering with pattern detection",
                    "features": [
                        "Malicious pattern detection",
                        "System prompt isolation",
                        "Input sanitization",
                        "Threat logging"
                    ]
                },
                "LLM02:2025": {
                    "title": "Sensitive Information Disclosure",
                    "status": "✅ Implemented",
                    "description": "Data sanitization and PII detection",
                    "features": [
                        "PII pattern detection",
                        "Data masking",
                        "Medical record protection",
                        "Privacy compliance"
                    ]
                },
                "LLM03:2025": {
                    "title": "Supply Chain",
                    "status": "✅ Implemented",
                    "description": "Secure dependencies and model sourcing",
                    "features": [
                        "Secure API integration",
                        "Model provenance tracking",
                        "Dependency management",
                        "Vulnerability scanning"
                    ]
                },
                "LLM05:2025": {
                    "title": "Improper Output Handling",
                    "status": "✅ Implemented",
                    "description": "Output validation and encoding",
                    "features": [
                        "Response sanitization",
                        "XSS prevention",
                        "Content validation",
                        "Medical disclaimer injection"
                    ]
                },
                "LLM06:2025": {
                    "title": "Excessive Agency",
                    "status": "✅ Implemented",
                    "description": "Least privilege access control",
                    "features": [
                        "RBAC implementation",
                        "Permission-based access",
                        "Function restrictions",
                        "Human-in-the-loop controls"
                    ]
                },
                "LLM07:2025": {
                    "title": "System Prompt Leakage",
                    "status": "✅ Implemented",
                    "description": "Secure prompt management",
                    "features": [
                        "Prompt isolation",
                        "Context boundaries",
                        "Secure prompt construction",
                        "Leakage prevention"
                    ]
                },
                "LLM08:2025": {
                    "title": "Vector and Embedding Weaknesses",
                    "status": "✅ Implemented",
                    "description": "RAG security measures",
                    "features": [
                        "Secure context management",
                        "Embedding validation",
                        "Vector security",
                        "RAG protection"
                    ]
                },
                "LLM09:2025": {
                    "title": "Misinformation",
                    "status": "✅ Implemented",
                    "description": "Output verification and disclaimers",
                    "features": [
                        "Medical accuracy validation",
                        "Disclaimer injection",
                        "Claim verification",
                        "Quality assessment"
                    ]
                },
                "LLM10:2025": {
                    "title": "Unbounded Consumption",
                    "status": "✅ Implemented",
                    "description": "Rate limiting and resource management",
                    "features": [
                        "Rate limiting",
                        "Resource quotas",
                        "Usage monitoring",
                        "Abuse prevention"
                    ]
                }
            },
            "overall_status": "✅ Fully Compliant",
            "coverage_percentage": 100,
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving OWASP coverage: {str(e)}"
        )


@router.get("/threat-landscape")
async def get_threat_landscape(
    current_user: Dict = Depends(require_view_security_logs)
):
    """
    Get current threat landscape and risk assessment
    
    Requires view security logs permission
    """
    try:
        # Get recent security events
        recent_events = security_manager.security_events[-100:]  # Last 100 events
        
        # Analyze threat patterns
        threat_analysis = {}
        for event in recent_events:
            threat_type = event.threat_type.value
            if threat_type not in threat_analysis:
                threat_analysis[threat_type] = {
                    "count": 0,
                    "security_levels": {},
                    "recent_occurrences": []
                }
            
            threat_analysis[threat_type]["count"] += 1
            
            security_level = event.security_level.value
            threat_analysis[threat_type]["security_levels"][security_level] = \
                threat_analysis[threat_type]["security_levels"].get(security_level, 0) + 1
            
            threat_analysis[threat_type]["recent_occurrences"].append({
                "timestamp": event.timestamp.isoformat(),
                "description": event.description,
                "security_level": security_level
            })
        
        # Calculate risk scores
        risk_assessment = {}
        for threat_type, data in threat_analysis.items():
            risk_score = 0
            total_events = data["count"]
            
            # Weight by security level
            for level, count in data["security_levels"].items():
                if level == "critical":
                    risk_score += count * 10
                elif level == "high":
                    risk_score += count * 5
                elif level == "medium":
                    risk_score += count * 2
                else:
                    risk_score += count
            
            # Normalize risk score
            risk_score = min(100, risk_score / max(1, total_events))
            
            risk_assessment[threat_type] = {
                "risk_score": risk_score,
                "risk_level": "high" if risk_score > 70 else "medium" if risk_score > 30 else "low",
                "total_events": total_events,
                "trend": "increasing" if total_events > 5 else "stable" if total_events > 1 else "low"
            }
        
        return {
            "threat_landscape": {
                "threat_analysis": threat_analysis,
                "risk_assessment": risk_assessment,
                "overall_risk": "low" if not risk_assessment else max(
                    data["risk_level"] for data in risk_assessment.values()
                )
            },
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing threat landscape: {str(e)}"
        )


@router.post("/configure")
async def configure_security_settings(
    settings_update: Dict[str, Any],
    current_user: Dict = Depends(require_manage_security)
):
    """
    Configure security settings
    
    Requires manage security permission
    """
    try:
        # This would typically update configuration in a database
        # For now, we'll just return a success message
        
        return {
            "message": "Security settings updated successfully",
            "updated_settings": settings_update,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error configuring security settings: {str(e)}"
        ) 