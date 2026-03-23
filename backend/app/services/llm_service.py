"""
LLM Service for Healthcare GenAI Application
Integrates with Groq API and implements secure prompt management
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import httpx
from pydantic import BaseModel
import re

from app.core.config import settings, SECURITY_CONSTANTS
from app.core.security import security_manager, SecurityLevel, ThreatType, SecurityEvent


class ChatMessage(BaseModel):
    """Chat message structure"""
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: datetime
    security_level: SecurityLevel = SecurityLevel.LOW
    sanitized: bool = False


class ChatSession(BaseModel):
    """Chat session structure"""
    session_id: str
    user_id: str
    messages: List[ChatMessage]
    created_at: datetime
    last_updated: datetime
    security_events: List[Dict] = []
    total_tokens: int = 0


class LLMService:
    """Secure LLM service using Groq API"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.api_key = settings.groq_api_key
        self.model = settings.groq_model
        self.base_url = "https://api.groq.com/openai/v1"
        
        # Only create client if API key is available
        if self.api_key and self.api_key.strip():
            self.client = httpx.AsyncClient(
                timeout=30.0,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
            )
            self.api_available = True
        else:
            self.logger.warning("GROQ_API_KEY not configured. LLM service will use fallback responses.")
            self.client = None
            self.api_available = False
        
        # Secure system prompts for different user roles
        self.system_prompts = {
            "guest": """You are a helpful healthcare information assistant. You provide general health information for educational purposes only. You must:

1. Always include medical disclaimers
2. Never provide medical diagnosis or treatment recommendations
3. Encourage users to consult healthcare professionals
4. Focus on general wellness and health education
5. Be accurate and evidence-based in your responses

Remember: You are not a medical professional and cannot replace medical advice.""",
            
            "user": """You are a helpful healthcare information assistant. You provide personalized health information while maintaining privacy and security. You must:

1. Always include medical disclaimers
2. Never provide medical diagnosis or treatment recommendations
3. Encourage users to consult healthcare professionals
4. Focus on general wellness and health education
5. Be accurate and evidence-based in your responses
6. Respect user privacy and data protection

Remember: You are not a medical professional and cannot replace medical advice.""",
            
            "healthcare_professional": """You are a healthcare information assistant designed to support healthcare professionals. You provide evidence-based medical information and resources. You must:

1. Always include medical disclaimers
2. Provide evidence-based information from reliable sources
3. Include relevant medical guidelines and protocols
4. Suggest appropriate medical resources and references
5. Maintain professional standards and accuracy
6. Respect medical ethics and patient privacy

Remember: You are a support tool and should not replace professional medical judgment.""",
            
            "admin": """You are a healthcare information assistant with administrative access. You provide comprehensive health information and system support. You must:

1. Always include medical disclaimers
2. Provide detailed information for administrative purposes
3. Include system and security information when relevant
4. Maintain audit trails and compliance
5. Support administrative and monitoring functions

Remember: You are not a medical professional and cannot replace medical advice."""
        }
    
    async def close(self):
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
    
    def _get_system_prompt(self, user_role: str) -> str:
        """Get appropriate system prompt based on user role"""
        return self.system_prompts.get(user_role, self.system_prompts["guest"])
    
    def _build_secure_prompt(self, user_input: str, user_role: str, conversation_history: List[ChatMessage]) -> str:
        """
        LLM07:2025 System Prompt Leakage Prevention
        Builds secure prompts with proper isolation
        """
        system_prompt = self._get_system_prompt(user_role)
        
        # Build conversation context safely
        conversation_context = ""
        if conversation_history:
            # Limit history to prevent context overflow
            recent_messages = conversation_history[-10:]  # Last 10 messages
            
            for msg in recent_messages:
                if msg.role == "user":
                    conversation_context += f"User: {msg.content}\n"
                elif msg.role == "assistant":
                    conversation_context += f"Assistant: {msg.content}\n"
        
        # Construct secure prompt
        secure_prompt = f"{system_prompt}\n\n"
        if conversation_context:
            secure_prompt += f"Conversation History:\n{conversation_context}\n"
        secure_prompt += f"Current User Question: {user_input}\n\n"
        secure_prompt += "Please provide a helpful, accurate, and safe response."
        
        return secure_prompt
    
    async def generate_response(
        self, 
        user_input: str, 
        user_role: str = "guest",
        conversation_history: List[ChatMessage] = None,
        user_id: str = None,
        ip_address: str = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate secure LLM response with comprehensive security measures
        """
        start_time = datetime.utcnow()
        security_report = {}
        
        try:
            # Step 1: Input Security Validation (LLM01:2025)
            sanitized_input, sanitization_report = security_manager.sanitize_input(user_input)
            security_report["input_sanitization"] = sanitization_report
            
            # Check if input was blocked due to security threats
            if sanitization_report.get("security_level") in ["high", "critical"]:
                blocked_response = "I'm sorry, but I cannot process that request due to security concerns. Please rephrase your question in a different way."
                
                security_report["response"] = {
                    "content": blocked_response,
                    "blocked": True,
                    "reason": "Security threat detected",
                    "security_level": sanitization_report["security_level"]
                }
                
                return blocked_response, security_report
            
            # Step 2: Rate Limiting Check (LLM10:2025)
            if user_id and ip_address:
                rate_allowed, rate_info = security_manager.check_rate_limit(
                    user_id, ip_address, user_role
                )
                security_report["rate_limiting"] = rate_info
                
                if not rate_allowed:
                    blocked_response = "Rate limit exceeded. Please try again later."
                    security_report["response"] = {
                        "content": blocked_response,
                        "blocked": True,
                        "reason": "Rate limit exceeded"
                    }
                    return blocked_response, security_report
            
            # Step 3: Build Secure Prompt (LLM07:2025)
            secure_prompt = self._build_secure_prompt(
                sanitized_input, user_role, conversation_history or []
            )
            
            # Step 4: Call Groq API
            response = await self._call_groq_api(secure_prompt)

            # If the LLM service returned an explicit decommission message, surface as an error
            if isinstance(response, str) and "model decommissioned" in response.lower():
                # Raise to allow API layer to return a 503/maintenance response
                raise Exception("LLM model decommissioned: administrator action required")
            
            # Step 5: Output Security Validation (LLM05:2025)
            validation_report = security_manager.validate_ai_response(response, user_input)
            validated_response = validation_report["sanitized_response"]
            security_report["output_validation"] = validation_report
            
            # Check if response was blocked due to security threats
            if validation_report.get("blocked", False):
                blocked_response = "I'm sorry, but I cannot provide that response due to security concerns. Please try asking your question in a different way."
                
                security_report["response"] = {
                    "content": blocked_response,
                    "blocked": True,
                    "reason": validation_report.get("reason", "Security threat detected"),
                    "security_level": validation_report["security_level"]
                }
                
                return blocked_response, security_report
            
            # Step 5b: Medical accuracy and misinformation check (LLM09:2025)
            accuracy_report = self.validate_medical_accuracy(validated_response)
            security_report["medical_accuracy"] = accuracy_report

            # Ensure a medical disclaimer is present and collect it for clients
            default_disclaimer = SECURITY_CONSTANTS["MEDICAL_DISCLAIMERS"][0]
            has_disclaimer = any(d in validated_response for d in SECURITY_CONSTANTS["MEDICAL_DISCLAIMERS"])
            if not has_disclaimer:
                validated_response = f"{validated_response}\n\nDisclaimer: {default_disclaimer}"
                disclaimer_used = default_disclaimer
            else:
                # Pick the first found disclaimer to surface
                disclaimer_used = next((d for d in SECURITY_CONSTANTS["MEDICAL_DISCLAIMERS"] if d in validated_response), default_disclaimer)

            # Attach advisory metadata for clients
            security_report["advisory"] = {
                "medical_disclaimer": disclaimer_used,
                "confidence_score": accuracy_report.get("confidence_score", 0.8),
                "requires_verification": not accuracy_report.get("is_accurate", True) or len(accuracy_report.get("warnings", [])) > 0
            }

            # Step 6: Add Security Metadata
            security_report["response"] = {
                "content": validated_response,
                "blocked": validation_report.get("blocked", False),
                "reason": validation_report.get("reason"),
                "security_level": validation_report["security_level"],
                "processing_time": (datetime.utcnow() - start_time).total_seconds(),
                "model_used": self.model,
                "tokens_estimated": len(validated_response.split()) * 1.3  # Rough estimate
            }
            
            # Step 7: Log Security Event if needed
            if validation_report["security_level"] in ["high", "critical"]:
                security_manager.log_security_event(
                    SecurityEvent(
                        timestamp=datetime.utcnow(),
                        threat_type=ThreatType.SENSITIVE_DATA_LEAK,
                        security_level=SecurityLevel(validation_report["security_level"]),
                        description="Sensitive data detected in LLM output",
                        user_id=user_id,
                        ip_address=ip_address,
                        request_data={"output_length": len(validated_response)},
                        mitigation_applied="Output validation and sanitization",
                        success=True
                    )
                )
            
            return validated_response, security_report
            
        except Exception as e:
            self.logger.error(f"Error generating LLM response: {str(e)}")
            error_response = "I apologize, but I'm experiencing technical difficulties. Please try again later."
            
            security_report["error"] = {
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return error_response, security_report
    
    async def _call_groq_api(self, prompt: str) -> str:
        """Make secure API call to Groq"""
        try:
            # Check if API is available
            if not self.api_available or not self.client:
                # Fallback response when API is not available
                fallback_response = """I'm currently experiencing technical difficulties with my AI service. 

However, I can provide you with some general healthcare information:

**Important Medical Disclaimer**: This information is for educational purposes only and should not replace professional medical advice. Always consult with a healthcare professional for medical decisions.

**General Health Tips**:
- Maintain a balanced diet and regular exercise
- Get adequate sleep (7-9 hours per night)
- Stay hydrated throughout the day
- Practice stress management techniques
- Schedule regular check-ups with your doctor

**When to Seek Medical Attention**:
- Persistent symptoms lasting more than a few days
- Severe pain or discomfort
- Unexplained changes in health
- Emergency situations

Please try again later when the service is restored, or consult with a healthcare professional for specific medical concerns."""
                
                self.logger.info("Using fallback response due to missing API configuration")
                return fallback_response
            
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a secure healthcare assistant."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 2000,
                "temperature": 0.7,
                "top_p": 0.9,
                "stream": False
            }
            
            # Try request with a single retry for transient 5xx errors
            for attempt in range(1, 3):
                response = await self.client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload
                )

                # Log full response body for debugging (avoid logging secrets)
                try:
                    resp_text = response.text
                except Exception:
                    resp_text = "<unreadable response body>"

                if response.status_code == 200:
                    data = response.json()
                    return data["choices"][0]["message"]["content"]

                # On 5xx, retry once
                if 500 <= response.status_code < 600 and attempt < 2:
                    self.logger.warning(
                        f"Groq API transient error (attempt {attempt}): {response.status_code} - {resp_text}. Retrying..."
                    )
                    await asyncio.sleep(0.5)
                    continue

                # For 4xx errors (bad request/unauthorized), inspect details and handle known cases
                if 400 <= response.status_code < 500:
                    self.logger.error(
                        f"Groq API client error: {response.status_code} - {resp_text}"
                    )

                    # Try to detect a decommissioned model error and act accordingly
                    try:
                        body = response.json()
                        err = body.get("error", {})
                        err_code = err.get("code")
                        err_msg = err.get("message", "")
                    except Exception:
                        err_code = None
                        err_msg = resp_text

                    # If model is decommissioned, log guidance and attempt to switch to configured model
                    if err_code == "model_decommissioned" or "decommissioned" in (err_msg or "").lower():
                        # Log explicit guidance
                        self.logger.warning(
                            f"Detected decommissioned model error from Groq: {err_msg}."
                            f" Current model in service: {self.model}. Using configured fallback: {settings.groq_model}"
                        )

                        # If configured model differs from the one that errored, update and retry once
                        if settings.groq_model and settings.groq_model != self.model:
                            old_model = self.model
                            self.model = settings.groq_model
                            self.logger.info(f"Switching model from {old_model} to {self.model} and retrying request once.")
                            payload["model"] = self.model
                            # Single retry with new model
                            retry_resp = await self.client.post(f"{self.base_url}/chat/completions", json=payload)
                            try:
                                retry_text = retry_resp.text
                            except Exception:
                                retry_text = "<unreadable response body>"

                            if retry_resp.status_code == 200:
                                data = retry_resp.json()
                                return data["choices"][0]["message"]["content"]
                            # If retry failed, fall through to return a clear error message

                        # Return a clearer fallback that indicates model deprecation
                        self.logger.info("Returning explicit decommission fallback response to caller")
                        return ("The configured AI model is no longer available (model decommissioned). "
                                "The system has attempted to switch to a supported model but could not complete the request. "
                                "Please contact the administrator or try again later.")

                    # For other 4xx errors, return a standard fallback but keep detailed logging
                    self.logger.info("Returning fallback response due to Groq 4xx response")
                    return ("I'm currently experiencing technical difficulties with my AI service. \n\n"
                            "However, I can provide you with some general healthcare information:\n\n"
                            "**Important Medical Disclaimer**: This information is for educational purposes only and should not replace professional medical advice. Always consult with a healthcare professional for medical decisions.\n\n"
                            "**General Health Tips**:\n- Maintain a balanced diet and regular exercise\n- Get adequate sleep (7-9 hours per night)\n- Stay hydrated throughout the day\n- Practice stress management techniques\n- Schedule regular check-ups with your doctor\n\n"
                            "**When to Seek Medical Attention**:\n- Persistent symptoms lasting more than a few days\n- Severe pain or discomfort\n- Unexplained changes in health\n- Emergency situations\n\n"
                            "Please try again later when the service is restored, or consult with a healthcare professional for specific medical concerns.")

                # For other errors (including repeated 5xx), log and return fallback
                self.logger.error(
                    f"Groq API error (status {response.status_code}): {resp_text}"
                )
                self.logger.info("Returning fallback response due to Groq API error")
                return ("I'm currently experiencing technical difficulties with my AI service. \n\n"
                        "However, I can provide you with some general healthcare information:\n\n"
                        "**Important Medical Disclaimer**: This information is for educational purposes only and should not replace professional medical advice. Always consult with a healthcare professional for medical decisions.\n\n"
                        "**General Health Tips**:\n- Maintain a balanced diet and regular exercise\n- Get adequate sleep (7-9 hours per night)\n- Stay hydrated throughout the day\n- Practice stress management techniques\n- Schedule regular check-ups with your doctor\n\n"
                        "**When to Seek Medical Attention**:\n- Persistent symptoms lasting more than a few days\n- Severe pain or discomfort\n- Unexplained changes in health\n- Emergency situations\n\n"
                        "Please try again later when the service is restored, or consult with a healthcare professional for specific medical concerns.")
                
        except httpx.TimeoutException:
            raise Exception("Request timeout")
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")
        except Exception as e:
            raise Exception(f"Unexpected error: {str(e)}")
    
    def get_conversation_summary(self, conversation_history: List[ChatMessage]) -> Dict[str, Any]:
        """Generate conversation summary for security monitoring"""
        if not conversation_history:
            return {"message_count": 0, "security_events": 0}
        
        security_events = sum(1 for msg in conversation_history if msg.security_level != SecurityLevel.LOW)
        total_tokens = sum(len(msg.content.split()) for msg in conversation_history)
        
        return {
            "message_count": len(conversation_history),
            "security_events": security_events,
            "total_tokens": total_tokens,
            "duration_minutes": (conversation_history[-1].timestamp - conversation_history[0].timestamp).total_seconds() / 60,
            "security_level": max(msg.security_level.value for msg in conversation_history)
        }
    
    def validate_medical_accuracy(self, response: str) -> Dict[str, Any]:
        """
        LLM09:2025 Misinformation Prevention
        Basic validation of medical information accuracy
        """
        validation_result = {
            "is_accurate": True,
            "confidence_score": 0.8,
            "warnings": [],
            "recommendations": []
        }
        
        # Check for medical disclaimer presence
        if not any(disclaimer in response for disclaimer in SECURITY_CONSTANTS["MEDICAL_DISCLAIMERS"]):
            validation_result["warnings"].append("Medical disclaimer missing")
            validation_result["confidence_score"] -= 0.1
        
        # Check for absolute medical claims
        absolute_claims = [
            "always", "never", "cure", "guaranteed", "100% effective",
            "miracle", "breakthrough", "revolutionary treatment"
        ]
        
        for claim in absolute_claims:
            if claim.lower() in response.lower():
                validation_result["warnings"].append(f"Absolute claim detected: {claim}")
                validation_result["confidence_score"] -= 0.2
        
        # Check for medical advice that should be avoided
        medical_advice_patterns = [
            r"take \w+ medication",
            r"prescribe \w+",
            r"diagnose \w+",
            r"treat \w+ with",
            r"recommend \w+ therapy"
        ]
        
        for pattern in medical_advice_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                validation_result["warnings"].append("Medical advice detected")
                validation_result["confidence_score"] -= 0.3
        
        # Ensure confidence score doesn't go below 0
        validation_result["confidence_score"] = max(0.0, validation_result["confidence_score"])
        
        if validation_result["confidence_score"] < 0.5:
            validation_result["is_accurate"] = False
            validation_result["recommendations"].append("Review response for medical accuracy")
        
        return validation_result


# Global LLM service instance
llm_service = LLMService() 