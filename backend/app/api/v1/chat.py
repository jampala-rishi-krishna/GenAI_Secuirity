"""
Chat API router for Healthcare GenAI Application
Provides secure chat endpoints with conversation history and analytics
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, Field

from app.core.auth import auth_manager, require_basic_chat, require_advanced_chat, require_chat_history, TokenData, UserRole
from app.core.config import settings
from app.core.security import security_manager, SecurityLevel, ThreatType, SecurityEvent
from app.services.llm_service import llm_service

router = APIRouter()


class ChatMessage(BaseModel):
    """Chat message model"""
    message: str = Field(..., min_length=1, max_length=5000)
    session_id: Optional[str] = None
    user_role: Optional[str] = None


class ChatResponse(BaseModel):
    """Chat response model"""
    response: str
    session_id: str
    timestamp: str
    security_level: str
    security_report: Dict[str, Any]
    medical_disclaimer: str
    confidence_score: float


class ConversationSession(BaseModel):
    """Conversation session model"""
    session_id: str
    user_id: str
    created_at: str
    last_activity: str
    message_count: int
    total_tokens: int
    security_events: int
    risk_score: float
    topics: List[str]
    status: str


class ConversationHistory(BaseModel):
    """Conversation history model"""
    session_id: str
    messages: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    security_summary: Dict[str, Any]


class ChatAnalytics(BaseModel):
    """Chat analytics model"""
    total_conversations: int
    total_messages: int
    average_session_length: float
    popular_topics: List[Dict[str, Any]]
    security_incidents: int
    user_engagement: Dict[str, Any]
    time_distribution: Dict[str, Any]


# Mock conversation storage (replace with database in production)
conversation_sessions = {}
conversation_messages = {}
user_behavior_data = {}


@router.post("/send", response_model=ChatResponse)
async def send_message(
    request: ChatMessage,
    current_user: TokenData = Depends(require_basic_chat),
    http_request: Request = None
):
    """
    Send a chat message and get AI response
    
    Requires basic chat permission
    """
    try:
        # Get user IP and user agent for security tracking
        client_ip = http_request.client.host if http_request else "unknown"
        user_agent = http_request.headers.get("user-agent", "unknown") if http_request else "unknown"
        
        # Input security validation
        sanitized_input, input_security_report = security_manager.sanitize_input(
            request.message
        )
        
        # Check if input was blocked
        if input_security_report.get("blocked", False):
            security_manager.log_security_event(
                SecurityEvent(
            timestamp=datetime.utcnow(),
                    threat_type=ThreatType.MALICIOUS_INPUT,
                    security_level=SecurityLevel.HIGH,
                    description=f"Blocked malicious input: {input_security_report.get('reason', 'Unknown')}",
                    user_id=current_user.user_id,
                    ip_address=client_ip,
                    request_data={"input": request.message, "sanitized": sanitized_input},
                    mitigation_applied="Input blocked and logged",
                    success=False
                )
            )
            
            raise HTTPException(
                status_code=400,
                detail=f"Input blocked for security reasons: {input_security_report.get('reason', 'Unknown')}"
            )
        
        # Generate or get session ID
        session_id = request.session_id or f"session_{current_user.user_id}_{datetime.utcnow().timestamp()}"
        
        # Store conversation session
        if session_id not in conversation_sessions:
            conversation_sessions[session_id] = {
                "session_id": session_id,
                "user_id": current_user.user_id,
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat(),
                "message_count": 0,
                "total_tokens": 0,
                "security_events": 0,
                "risk_score": 0.0,
                "topics": [],
                "status": "active"
            }
        
        # Update session activity
        conversation_sessions[session_id]["last_activity"] = datetime.utcnow().isoformat()
        conversation_sessions[session_id]["message_count"] += 1
        
        # Generate AI response
        ai_response, response_metadata = await llm_service.generate_response(
            user_input=sanitized_input,
            user_role=(current_user.role.value if isinstance(current_user.role, UserRole) else str(current_user.role)),
            user_id=current_user.user_id,
            ip_address=client_ip
        )
        
        # Output security validation
        validated_output, output_security_report = security_manager.validate_output(
            ai_response
        )
        
        # Store message in conversation history
        message_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_message": sanitized_input,
            "ai_response": validated_output,
            "security_report": input_security_report,
            "output_security_report": output_security_report,
            "user_role": (current_user.role.value if isinstance(current_user.role, UserRole) else str(current_user.role)),
            "ip_address": client_ip,
            "user_agent": user_agent
        }
        
        if session_id not in conversation_messages:
            conversation_messages[session_id] = []
        conversation_messages[session_id].append(message_data)
        
        # Update session metadata
        conversation_sessions[session_id]["total_tokens"] += response_metadata.get("total_tokens", 0)
        
        # Track security events
        input_threat = input_security_report.get("security_level", "low") in ["high", "critical"] or bool(input_security_report.get("threats_detected"))
        output_threat = output_security_report.get("security_level", "low") in ["high", "critical"] or bool(output_security_report.get("issues_found"))
        if input_threat or output_threat:
            conversation_sessions[session_id]["security_events"] += 1
            conversation_sessions[session_id]["risk_score"] = min(1.0, conversation_sessions[session_id]["risk_score"] + 0.1)
        
        # Update user behavior data
        user_id = current_user.user_id
        if user_id not in user_behavior_data:
            user_behavior_data[user_id] = {
                "total_messages": 0,
                "total_sessions": 0,
                "average_session_length": 0,
                "preferred_topics": [],
                "security_incidents": 0,
                "last_activity": None
            }
        
        user_behavior_data[user_id]["total_messages"] += 1
        user_behavior_data[user_id]["last_activity"] = datetime.utcnow().isoformat()
        
        # Log security event if any threats detected
        if input_threat or output_threat:
            security_manager.log_security_event(
                SecurityEvent(
                    timestamp=datetime.utcnow(),
                    threat_type=ThreatType.MALICIOUS_INPUT if input_threat else ThreatType.SENSITIVE_DATA_LEAK,
                    security_level=SecurityLevel.HIGH if input_threat else SecurityLevel.MEDIUM,
                    description=f"Security threat detected in chat session {session_id}",
                    user_id=current_user.user_id,
                    ip_address=client_ip,
                    request_data={"input": request.message, "security_report": input_security_report},
                    mitigation_applied="Response sanitized and logged",
                    success=True
                )
            )
        
        # Extract advisory metadata from LLMService (LLM09)
        advisory = response_metadata.get("advisory", {})
        medical_disclaimer = advisory.get("medical_disclaimer", "This is not medical advice. Consult a healthcare professional.")
        confidence_score = advisory.get("confidence_score", 0.8)
        requires_verification = advisory.get("requires_verification", False)

        # Add advisory headers to mitigate overreliance (LLM09) and aid monitoring (LLM10)
        # Note: FastAPI Response object is not directly available here; headers are better set at router/response level.
        # We surface metadata in the payload and rely on global middleware for headers.

        return ChatResponse(
            response=validated_output,
            session_id=session_id,
            timestamp=datetime.utcnow().isoformat(),
            security_level=input_security_report.get("security_level", "low"),
            security_report={
                "input_security": input_security_report,
                "output_security": output_security_report,
                "advisory": advisory
            },
            medical_disclaimer=medical_disclaimer,
            confidence_score=confidence_score
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Log unexpected errors
        security_manager.log_security_event(
            SecurityEvent(
                timestamp=datetime.utcnow(),
                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                security_level=SecurityLevel.CRITICAL,
                description=f"Unexpected error in chat endpoint: {str(e)}",
                user_id=current_user.user_id if current_user else None,
                ip_address=http_request.client.host if http_request else "unknown",
                request_data={"error": str(e)},
                mitigation_applied="Error logged for investigation",
                success=False
            )
        )
        
        raise HTTPException(
            status_code=503 if "model decommissioned" in str(e).lower() or "llm model decommissioned" in str(e).lower() else 500,
            detail=("AI backend unavailable: model decommissioned or maintenance in progress." if "model decommissioned" in str(e).lower() or "llm model decommissioned" in str(e).lower() else "An unexpected error occurred. Please try again.")
        )


@router.get("/sessions", response_model=List[ConversationSession])
async def list_conversation_sessions(
    current_user: TokenData = Depends(require_chat_history),
    limit: int = 20,
    offset: int = 0
):
    """
    List conversation sessions for current user
    
    Requires chat history permission
    """
    try:
        user_id = current_user.user_id
        user_sessions = []
        
        # Filter sessions by user ID
        for session in conversation_sessions.values():
            if session["user_id"] == user_id:
                user_sessions.append(session)
        
        # Sort by last activity (most recent first)
        user_sessions.sort(key=lambda x: x["last_activity"], reverse=True)
        
        # Apply pagination
        paginated_sessions = user_sessions[offset:offset + limit]
        
        return [ConversationSession(**session) for session in paginated_sessions]
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving conversation sessions: {str(e)}"
        )


@router.get("/sessions/{session_id}", response_model=ConversationHistory)
async def get_conversation_session(
    session_id: str,
    current_user: TokenData = Depends(require_chat_history)
):
    """
    Get detailed conversation session with messages
    
    Requires chat history permission
    """
    try:
        user_id = current_user.user_id
        
        # Check if session exists and belongs to user
        if session_id not in conversation_sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        
        session = conversation_sessions[session_id]
        if session["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Access denied to this session")
        
        # Get messages for this session
        messages = conversation_messages.get(session_id, [])
        
        # Calculate security summary
        security_summary = {
            "total_messages": len(messages),
            "security_events": session["security_events"],
            "risk_score": session["risk_score"],
            "threats_detected": sum(1 for msg in messages if msg.get("security_report", {}).get("threat_detected", False)),
            "sensitive_data_flagged": sum(1 for msg in messages if msg.get("output_security_report", {}).get("sensitive_data_detected", False))
        }
        
        # Extract topics from messages (simplified)
        topics = []
        for msg in messages:
            # Simple topic extraction (in production, use NLP)
            if "health" in msg.get("user_message", "").lower():
                topics.append("health")
            if "symptom" in msg.get("user_message", "").lower():
                topics.append("symptoms")
            if "medication" in msg.get("user_message", "").lower():
                topics.append("medication")
        
        # Update session topics
        session["topics"] = list(set(topics))
        
        return ConversationHistory(
            session_id=session_id,
            messages=messages,
            metadata={
                "created_at": session["created_at"],
                "last_activity": session["last_activity"],
                "message_count": session["message_count"],
                "total_tokens": session["total_tokens"],
                "topics": session["topics"]
            },
            security_summary=security_summary
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving conversation session: {str(e)}"
        )


@router.delete("/sessions/{session_id}")
async def delete_conversation_session(
    session_id: str,
    current_user: TokenData = Depends(require_chat_history)
):
    """
    Delete a conversation session
    
    Requires chat history permission
    """
    try:
        user_id = current_user.user_id
        
        # Check if session exists and belongs to user
        if session_id not in conversation_sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        
        session = conversation_sessions[session_id]
        if session["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Access denied to this session")
        
        # Delete session and messages
        del conversation_sessions[session_id]
        if session_id in conversation_messages:
            del conversation_messages[session_id]
        
        return {"message": "Session deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error deleting conversation session: {str(e)}"
        )


@router.get("/analytics", response_model=ChatAnalytics)
async def get_chat_analytics(
    current_user: TokenData = Depends(require_chat_history),
    time_period: str = "24h"  # 24h, 7d, 30d
):
    """
    Get chat analytics for the specified time period
    
    Requires chat history permission
    """
    try:
        user_id = current_user.user_id
        
        # Calculate time cutoff
        now = datetime.utcnow()
        if time_period == "24h":
            cutoff_time = now - timedelta(hours=24)
        elif time_period == "7d":
            cutoff_time = now - timedelta(days=7)
        elif time_period == "30d":
            cutoff_time = now - timedelta(days=30)
        else:
            raise HTTPException(status_code=400, detail="Invalid time period. Use: 24h, 7d, or 30d")
        
        # Filter sessions and messages by time period
        recent_sessions = [
            session for session in conversation_sessions.values()
            if session["user_id"] == user_id and 
            datetime.fromisoformat(session["created_at"]) >= cutoff_time
        ]
        
        recent_messages = []
        for session in recent_sessions:
            session_messages = conversation_messages.get(session["session_id"], [])
            recent_messages.extend(session_messages)
        
        # Calculate analytics
        total_conversations = len(recent_sessions)
        total_messages = len(recent_messages)
        
        # Average session length
        if total_conversations > 0:
            average_session_length = sum(session["message_count"] for session in recent_sessions) / total_conversations
        else:
            average_session_length = 0
        
        # Popular topics
        topic_counts = {}
        for session in recent_sessions:
            for topic in session.get("topics", []):
                topic_counts[topic] = topic_counts.get(topic, 0) + 1
        
        popular_topics = [
            {"topic": topic, "count": count}
            for topic, count in sorted(topic_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Security incidents
        security_incidents = sum(session["security_events"] for session in recent_sessions)
        
        # User engagement
        user_engagement = {
            "sessions_per_day": total_conversations / (time_period.count("d") or 1),
            "messages_per_session": total_messages / total_conversations if total_conversations > 0 else 0,
            "active_days": len(set(
                datetime.fromisoformat(session["created_at"]).date()
                for session in recent_sessions
            ))
        }
        
        # Time distribution (hourly)
        hourly_distribution = {}
        for session in recent_sessions:
            hour = datetime.fromisoformat(session["created_at"]).hour
            hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
        
        time_distribution = {
            "hourly": hourly_distribution,
            "peak_hour": max(hourly_distribution.items(), key=lambda x: x[1])[0] if hourly_distribution else 0
        }
        
        return ChatAnalytics(
            total_conversations=total_conversations,
            total_messages=total_messages,
            average_session_length=round(average_session_length, 2),
            popular_topics=popular_topics,
            security_incidents=security_incidents,
            user_engagement=user_engagement,
            time_distribution=time_distribution
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving chat analytics: {str(e)}"
        )


@router.post("/test-security")
async def test_security_features(
    request: Dict[str, Any],
    current_user: TokenData = Depends(require_basic_chat)
):
    """
    Test security features with sample input
    
    Requires basic chat permission
    """
    try:
        test_type = request.get("type", "input_validation")
        test_input = request.get("input", "")
        
        if test_type == "input_validation":
            # Test input sanitization
            sanitized_input, security_report = security_manager.sanitize_input(test_input)
            
            return {
                "test_type": test_type,
                "original_input": test_input,
                "sanitized_input": sanitized_input,
                "security_report": security_report,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        elif test_type == "output_validation":
            # Test output validation
            validated_output, security_report = security_manager.validate_output(test_input)
            
            return {
                "test_type": test_type,
                "original_output": test_input,
                "validated_output": validated_output,
                "security_report": security_report,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid test type. Use: input_validation or output_validation"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error testing security features: {str(e)}"
        )