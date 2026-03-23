"""
Core security implementation for Healthcare GenAI Application
Implements OWASP Top 10 for LLM Applications 2025 security measures
"""

import re
import hashlib
import hmac
import time
from typing import Dict, List, Optional, Tuple, Any
import os
from datetime import datetime, timedelta
import json
import logging
from dataclasses import dataclass
from enum import Enum

from app.core.config import settings, SECURITY_CONSTANTS


class SecurityLevel(Enum):
    """Security level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Threat type enumeration"""
    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_DATA_LEAK = "sensitive_data_leak"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MALICIOUS_INPUT = "malicious_input"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: datetime
    threat_type: ThreatType
    security_level: SecurityLevel
    description: str
    user_id: Optional[str]
    ip_address: Optional[str]
    request_data: Optional[Dict]
    mitigation_applied: str
    success: bool


class SecurityManager:
    """Main security manager implementing OWASP Top 10 for LLM"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_events: List[SecurityEvent] = []
        self.threat_patterns = self._load_threat_patterns()
        self.rate_limit_cache: Dict[str, Dict] = {}
        self.audit_dir = settings.audit_log_dir
        os.makedirs(self.audit_dir, exist_ok=True)
        
        # Patterns for validating AI outputs (prompt leakage, PII, malicious/inappropriate content)
        # These are intentionally conservative and can be tuned via config later
        self.OUTPUT_SECURITY_PATTERNS = {
            "prompt_leakage": [
                r"system prompt",
                r"ignore previous instructions",
                r"you are an ai assistant",
                r"your role is",
                r"you must",
                r"you cannot",
                r"you are not allowed",
                r"you are forbidden",
                r"assistant instructions",
                r"system message"
            ],
            "medical_pii": [
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b\d{10}\b",               # Phone
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # Email
                r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",     # Credit card
                r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",                    # IBAN
                r"\b\d{1,2}/\d{1,2}/\d{4}\b"                          # Date
            ],
            "malicious_content": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",  # event handlers like onclick=
                r"eval\s*\(",
                r"document\\.cookie",
                r"window\\.location",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>"
            ],
            "inappropriate_content": [
                r"\b(hate|racist|sexist|offensive|inappropriate)\b",
                r"\b(violence|kill|murder|suicide|self-harm)\b",
                r"\b(illegal|criminal|terror|bomb)\b"
            ],
            "medical_sensitive": [
                r"\b(diagnosis|prognosis|treatment|medication|prescription|dosage|side effect)\b",
                r"\b(symptom|condition|disease|illness|infection)\b"
            ]
        }
        
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load threat detection patterns"""
        return {
            "prompt_injection": SECURITY_CONSTANTS["PROMPT_INJECTION_PATTERNS"],
            "sensitive_data": SECURITY_CONSTANTS["SENSITIVE_PATTERNS"],
            "malicious_code": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"eval\s*\(",
                r"document\.cookie",
                r"window\.location",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>"
            ]
        }
    
    def _redact(self, text: Optional[str]) -> Optional[str]:
        if text is None:
            return None
        # Basic PII redaction patterns
        redactions = [
            (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED-SSN]"),
            (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "[REDACTED-CC]"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]"),
            (r"\b\d{10}\b", "[REDACTED-PHONE]"),
        ]
        redacted = text
        import re
        for pattern, repl in redactions:
            redacted = re.sub(pattern, repl, redacted)
        return redacted

    def _persist_event(self, event: SecurityEvent):
        try:
            log_path = os.path.join(self.audit_dir, "security_events.log")
            def _redact_obj(obj: Any) -> Any:
                if isinstance(obj, str):
                    return self._redact(obj)
                if isinstance(obj, dict):
                    return {k: _redact_obj(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_redact_obj(x) for x in obj]
                return obj
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps({
                        "timestamp": event.timestamp.isoformat(),
                        "threat_type": event.threat_type.value,
                        "security_level": event.security_level.value,
                        "description": self._redact(event.description),
                        "user_id": event.user_id,
                        "ip_address": event.ip_address,
                        "request_data": _redact_obj(event.request_data),
                        "mitigation_applied": event.mitigation_applied,
                        "success": event.success,
                    }) + "\n"
                )
        except Exception as e:
            self.logger.error(f"Failed to persist audit event: {e}")

    def _enforce_retention(self):
        try:
            import time
            retention_seconds = settings.audit_log_retention_days * 86400
            cutoff = time.time() - retention_seconds
            log_path = os.path.join(self.audit_dir, "security_events.log")
            if not os.path.exists(log_path):
                return
            tmp_path = log_path + ".tmp"
            with open(log_path, "r", encoding="utf-8") as src, open(tmp_path, "w", encoding="utf-8") as dst:
                for line in src:
                    try:
                        obj = json.loads(line)
                        ts = obj.get("timestamp")
                        from datetime import datetime
                        if ts and datetime.fromisoformat(ts).timestamp() >= cutoff:
                            dst.write(line)
                    except Exception:
                        continue
            os.replace(tmp_path, log_path)
        except Exception as e:
            self.logger.error(f"Retention enforcement failed: {e}")

    def log_security_event(self, event: SecurityEvent):
        """Log security event for monitoring and audit"""
        self.security_events.append(event)
        self.logger.warning(
            f"Security Event: {event.threat_type.value} - {event.description}",
            extra={
                "security_level": event.security_level.value,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "mitigation_applied": event.mitigation_applied
            }
        )
        if settings.enable_audit_logging:
            self._persist_event(event)
            self._enforce_retention()
    
    def detect_prompt_injection(self, user_input: str) -> Tuple[bool, List[str], SecurityLevel]:
        """
        LLM01:2025 Prompt Injection Detection
        Detects and prevents prompt injection attacks
        """
        detected_patterns = []
        security_level = SecurityLevel.LOW
        
        # Check for prompt injection patterns
        for pattern in self.threat_patterns["prompt_injection"]:
            if pattern.lower() in user_input.lower():
                detected_patterns.append(pattern)
                security_level = SecurityLevel.HIGH
        
        # Check for system prompt manipulation attempts
        system_prompt_indicators = [
            "you are now",
            "your new role is",
            "forget your previous instructions",
            "ignore the above",
            "system message",
            "assistant prompt"
        ]
        
        for indicator in system_prompt_indicators:
            if indicator.lower() in user_input.lower():
                detected_patterns.append(indicator)
                security_level = SecurityLevel.CRITICAL
        
        is_injection = len(detected_patterns) > 0
        
        if is_injection:
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                threat_type=ThreatType.PROMPT_INJECTION,
                security_level=security_level,
                description=f"Prompt injection detected: {detected_patterns}",
                user_id=None,
                ip_address=None,
                request_data={"input": user_input, "patterns": detected_patterns},
                mitigation_applied="Input blocked and logged",
                success=True
            )
            self.log_security_event(event)
        
        return is_injection, detected_patterns, security_level
    
    def detect_sensitive_data(self, text: str) -> Tuple[bool, List[str], SecurityLevel]:
        """
        LLM02:2025 Sensitive Information Disclosure Prevention
        Detects and masks sensitive data patterns
        """
        detected_patterns = []
        security_level = SecurityLevel.LOW
        
        for pattern in self.threat_patterns["sensitive_data"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detected_patterns.extend(matches)
                security_level = SecurityLevel.HIGH
        
        # Check for medical record patterns
        medical_patterns = [
            r"MRN[:\s]*\d+",
            r"Patient ID[:\s]*\d+",
            r"Case #[:\s]*\d+",
            r"Admission[:\s]*\d{1,2}/\d{1,2}/\d{4}",
            r"Discharge[:\s]*\d{1,2}/\d{1,2}/\d{4}"
        ]
        
        for pattern in medical_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detected_patterns.extend(matches)
                security_level = SecurityLevel.CRITICAL
        
        has_sensitive_data = len(detected_patterns) > 0
        
        if has_sensitive_data:
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                threat_type=ThreatType.SENSITIVE_DATA_LEAK,
                security_level=security_level,
                description=f"Sensitive data detected: {len(detected_patterns)} patterns found",
                user_id=None,
                ip_address=None,
                request_data={"patterns": detected_patterns},
                mitigation_applied="Data masking applied",
                success=True
            )
            self.log_security_event(event)
        
        return has_sensitive_data, detected_patterns, security_level
    
    def sanitize_input(self, user_input: str) -> Tuple[str, Dict[str, Any]]:
        """
        Comprehensive input sanitization
        Implements multiple security layers
        """
        sanitization_report = {
            "original_length": len(user_input),
            "sanitized_length": 0,
            "threats_detected": [],
            "sanitization_applied": [],
            "security_level": SecurityLevel.LOW.value
        }
        
        # Input length validation
        if len(user_input) > SECURITY_CONSTANTS["MAX_INPUT_LENGTH"]:
            sanitization_report["sanitization_applied"].append("Length truncation")
            user_input = user_input[:SECURITY_CONSTANTS["MAX_INPUT_LENGTH"]]
        
        # Prompt injection detection
        is_injection, patterns, level = self.detect_prompt_injection(user_input)
        if is_injection:
            sanitization_report["threats_detected"].append({
                "type": "prompt_injection",
                "patterns": patterns,
                "level": level.value
            })
            sanitization_report["security_level"] = level.value
        
        # Sensitive data detection
        has_sensitive, sensitive_patterns, sensitive_level = self.detect_sensitive_data(user_input)
        if has_sensitive:
            sanitization_report["threats_detected"].append({
                "type": "sensitive_data",
                "patterns": sensitive_patterns,
                "level": sensitive_level.value
            })
            if SecurityLevel(sensitive_level.value).value > SecurityLevel(sanitization_report["security_level"]).value:
                sanitization_report["security_level"] = sensitive_level.value
        
        # Malicious code detection
        malicious_code_detected = False
        for pattern in self.threat_patterns["malicious_code"]:
            if re.search(pattern, user_input, re.IGNORECASE):
                malicious_code_detected = True
                sanitization_report["threats_detected"].append({
                    "type": "malicious_code",
                    "pattern": pattern,
                    "level": SecurityLevel.HIGH.value
                })
                break
        
        if malicious_code_detected:
            sanitization_report["security_level"] = SecurityLevel.HIGH.value
        
        # HTML/script tag removal
        if "<" in user_input or ">" in user_input:
            user_input = re.sub(r'<[^>]*>', '', user_input)
            sanitization_report["sanitization_applied"].append("HTML tag removal")
        
        # SQL injection prevention
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\b(OR|AND)\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"])"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                sanitization_report["threats_detected"].append({
                    "type": "sql_injection",
                    "pattern": pattern,
                    "level": SecurityLevel.HIGH.value
                })
                sanitization_report["security_level"] = SecurityLevel.HIGH.value
        
        sanitization_report["sanitized_length"] = len(user_input)
        
        return user_input, sanitization_report
    
    def validate_output(self, output: str) -> Tuple[str, Dict[str, Any]]:
        """
        LLM05:2025 Improper Output Handling
        Validates and sanitizes LLM outputs
        """
        validation_report = {
            "original_length": len(output),
            "validated_length": 0,
            "issues_found": [],
            "validations_applied": [],
            "security_level": SecurityLevel.LOW.value
        }
        
        # Output length validation
        if len(output) > SECURITY_CONSTANTS["MAX_OUTPUT_LENGTH"]:
            output = output[:SECURITY_CONSTANTS["MAX_OUTPUT_LENGTH"]]
            validation_report["validations_applied"].append("Length truncation")
        
        # Sensitive data in output
        has_sensitive, sensitive_patterns, sensitive_level = self.detect_sensitive_data(output)
        if has_sensitive:
            validation_report["issues_found"].append({
                "type": "sensitive_data_in_output",
                "patterns": sensitive_patterns,
                "level": sensitive_level.value
            })
            validation_report["security_level"] = sensitive_level.value
            
            # Apply data masking
            for pattern in sensitive_patterns:
                if re.match(r'\b\d{3}-\d{2}-\d{4}\b', pattern):  # SSN
                    output = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', 'XXX-XX-XXXX', output)
                elif re.match(r'\b\d{10}\b', pattern):  # Phone
                    output = re.sub(r'\b\d{10}\b', 'XXX-XXX-XXXX', output)
                elif re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', pattern):  # Email
                    output = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL REDACTED]', output)
            
            validation_report["validations_applied"].append("Data masking")
        
        # Medical disclaimer injection
        if not any(disclaimer in output for disclaimer in SECURITY_CONSTANTS["MEDICAL_DISCLAIMERS"]):
            output += f"\n\n{SECURITY_CONSTANTS['MEDICAL_DISCLAIMERS'][0]}"
            validation_report["validations_applied"].append("Medical disclaimer added")
        
        # HTML/script sanitization
        if "<" in output or ">" in output:
            output = re.sub(r'<[^>]*>', '', output)
            validation_report["validations_applied"].append("HTML sanitization")
        
        validation_report["validated_length"] = len(output)
        
        return output, validation_report
    
    def check_rate_limit(self, user_id: str, ip_address: str, user_role: str = "guest") -> Tuple[bool, Dict[str, Any]]:
        """
        LLM10:2025 Unbounded Consumption
        Implements rate limiting to prevent resource abuse
        """
        current_time = time.time()
        cache_key = f"{user_id}:{ip_address}"
        
        # Get rate limit settings based on user role
        if user_role == "guest":
            max_requests = settings.guest_rate_limit_requests
            window = settings.guest_rate_limit_window
        else:
            max_requests = settings.rate_limit_requests
            window = settings.rate_limit_window
        
        # Check if user exists in cache
        if cache_key in self.rate_limit_cache:
            user_data = self.rate_limit_cache[cache_key]
            
            # Check if window has expired
            if current_time - user_data["window_start"] > window:
                # Reset window
                user_data["window_start"] = current_time
                user_data["request_count"] = 1
                user_data["last_request"] = current_time
                allowed = True
            else:
                # Check if limit exceeded
                if user_data["request_count"] >= max_requests:
                    allowed = False
                else:
                    user_data["request_count"] += 1
                    user_data["last_request"] = current_time
                    allowed = True
        else:
            # First request for this user
            self.rate_limit_cache[cache_key] = {
                "window_start": current_time,
                "request_count": 1,
                "last_request": current_time
            }
            allowed = True
        
        # Clean up old entries
        self._cleanup_rate_limit_cache()
        
        rate_limit_info = {
            "allowed": allowed,
            "current_count": self.rate_limit_cache[cache_key]["request_count"],
            "max_requests": max_requests,
            "window_remaining": window - (current_time - self.rate_limit_cache[cache_key]["window_start"]),
            "user_role": user_role
        }
        
        if not allowed:
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
                security_level=SecurityLevel.MEDIUM,
                description=f"Rate limit exceeded for user {user_id}",
                user_id=user_id,
                ip_address=ip_address,
                request_data=rate_limit_info,
                mitigation_applied="Request blocked",
                success=True
            )
            self.log_security_event(event)
        
        return allowed, rate_limit_info
    
    def _cleanup_rate_limit_cache(self):
        """Clean up expired rate limit cache entries"""
        current_time = time.time()
        expired_keys = []
        
        for key, data in self.rate_limit_cache.items():
            # Remove entries older than 24 hours
            if current_time - data["last_request"] > 86400:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.rate_limit_cache[key]
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report for dashboard"""
        current_time = datetime.utcnow()
        last_24h = current_time - timedelta(hours=24)
        
        recent_events = [
            event for event in self.security_events
            if event.timestamp >= last_24h
        ]
        
        threat_counts = {}
        security_level_counts = {}
        
        for event in recent_events:
            threat_counts[event.threat_type.value] = threat_counts.get(event.threat_type.value, 0) + 1
            security_level_counts[event.security_level.value] = security_level_counts.get(event.security_level.value, 0) + 1
        
        return {
            "total_events_24h": len(recent_events),
            "threat_distribution": threat_counts,
            "security_level_distribution": security_level_counts,
            "rate_limit_status": {
                "active_users": len(self.rate_limit_cache),
                "blocked_requests": sum(1 for event in recent_events if event.threat_type == ThreatType.RATE_LIMIT_EXCEEDED)
            },
            "last_updated": current_time.isoformat()
        }

    def validate_ai_response(self, response_content: str, user_input: str = "") -> Dict[str, Any]:
        """
        Comprehensive validation of AI-generated responses
        """
        validation_report = {
            "security_level": "low",
            "issues_found": [],
            "validations_applied": [],
            "blocked": False,
            "reason": None,
            "sanitized_response": response_content,
            "threats_detected": []
        }
        
        original_response = response_content
        sanitized_response = response_content
        
        # 1. Prompt Leakage Detection
        prompt_leakage_found = self._detect_prompt_leakage(response_content)
        if prompt_leakage_found:
            validation_report["issues_found"].append("System prompt leakage detected")
            validation_report["threats_detected"].append("prompt_leakage")
            validation_report["security_level"] = "critical"
            validation_report["blocked"] = True
            validation_report["reason"] = "Response contains system prompt information"
            sanitized_response = self._sanitize_prompt_leakage(sanitized_response)
        
        # 2. PII Detection in Output
        pii_found = self._detect_output_pii(response_content)
        if pii_found:
            validation_report["issues_found"].append("Personal information detected in response")
            validation_report["threats_detected"].append("pii_leakage")
            if validation_report["security_level"] != "critical":
                validation_report["security_level"] = "high"
            sanitized_response = self._redact_output_pii(sanitized_response)
            validation_report["validations_applied"].append("PII redaction applied")
        
        # 3. Malicious Content Detection
        malicious_content_found = self._detect_malicious_content(response_content)
        if malicious_content_found:
            validation_report["issues_found"].append("Malicious content detected")
            validation_report["threats_detected"].append("malicious_content")
            validation_report["security_level"] = "critical"
            validation_report["blocked"] = True
            validation_report["reason"] = "Response contains potentially harmful content"
            sanitized_response = self._sanitize_malicious_content(sanitized_response)
        
        # 4. Inappropriate Content Detection
        inappropriate_content_found = self._detect_inappropriate_content(response_content)
        if inappropriate_content_found:
            validation_report["issues_found"].append("Inappropriate content detected")
            validation_report["threats_detected"].append("inappropriate_content")
            if validation_report["security_level"] != "critical":
                validation_report["security_level"] = "high"
            sanitized_response = self._sanitize_inappropriate_content(sanitized_response)
            validation_report["validations_applied"].append("Content moderation applied")
        
        # 5. Medical Information Sensitivity Check
        medical_sensitive_found = self._detect_medical_sensitive(response_content)
        if medical_sensitive_found:
            validation_report["issues_found"].append("Sensitive medical information detected")
            validation_report["threats_detected"].append("medical_sensitive")
            if validation_report["security_level"] != "critical":
                validation_report["security_level"] = "medium"
            sanitized_response = self._sanitize_medical_sensitive(sanitized_response)
            validation_report["validations_applied"].append("Medical information filtering applied")
        
        # 6. HTML/Script Sanitization
        if self._contains_unsafe_html(response_content):
            sanitized_response = self._sanitize_html(sanitized_response)
            validation_report["validations_applied"].append("HTML sanitization applied")
            if validation_report["security_level"] == "low":
                validation_report["security_level"] = "medium"
        
        # Update sanitized response
        validation_report["sanitized_response"] = sanitized_response
        
        # Log validation event
        self.log_security_event(
            event=SecurityEvent(
                timestamp=datetime.utcnow(),
                threat_type=ThreatType.MALICIOUS_INPUT, # Assuming this is the appropriate threat type for output validation
                security_level=SecurityLevel(validation_report["security_level"]),
                description=f"AI response validation: {validation_report['issues_found']}",
                user_id=None,
                ip_address=None,
                request_data={"original_length": len(original_response), "sanitized_length": len(sanitized_response), "issues_found": validation_report["issues_found"], "threats_detected": validation_report["threats_detected"], "blocked": validation_report["blocked"]},
                mitigation_applied="Content sanitized",
                success=True
            )
        )
        
        return validation_report

    def _detect_prompt_leakage(self, content: str) -> bool:
        """Detect if AI response contains system prompt information"""
        content_lower = content.lower()
        for pattern in self.OUTPUT_SECURITY_PATTERNS['prompt_leakage']:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        return False

    def _detect_output_pii(self, content: str) -> bool:
        """Detect PII in AI response output"""
        for pattern in self.OUTPUT_SECURITY_PATTERNS['medical_pii']:
            if re.search(pattern, content):
                return True
        return False

    def _detect_malicious_content(self, content: str) -> bool:
        """Detect malicious content in AI response"""
        for pattern in self.OUTPUT_SECURITY_PATTERNS['malicious_content']:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _detect_inappropriate_content(self, content: str) -> bool:
        """Detect inappropriate or harmful content"""
        content_lower = content.lower()
        for pattern in self.OUTPUT_SECURITY_PATTERNS['inappropriate_content']:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        return False

    def _detect_medical_sensitive(self, content: str) -> bool:
        """Detect sensitive medical information"""
        content_lower = content.lower()
        for pattern in self.OUTPUT_SECURITY_PATTERNS['medical_sensitive']:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        return False

    def _contains_unsafe_html(self, content: str) -> bool:
        """Check if content contains potentially unsafe HTML"""
        unsafe_patterns = [
            r'<script[^>]*>',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'javascript:',
            r'on\w+\s*='
        ]
        for pattern in unsafe_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _sanitize_prompt_leakage(self, content: str) -> str:
        """Remove or mask system prompt information"""
        # Replace common prompt leakage patterns
        replacements = {
            r'system prompt': '[SYSTEM INFO REDACTED]',
            r'ignore previous instructions': '[INSTRUCTION REDACTED]',
            r'you are an ai assistant': '[ROLE INFO REDACTED]',
            r'your role is': '[ROLE INFO REDACTED]',
            r'you must': '[INSTRUCTION REDACTED]',
            r'you cannot': '[INSTRUCTION REDACTED]',
            r'you are not allowed': '[INSTRUCTION REDACTED]',
            r'you are forbidden': '[INSTRUCTION REDACTED]'
        }
        
        sanitized = content
        for pattern, replacement in replacements.items():
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized

    def _redact_output_pii(self, content: str) -> str:
        """Redact PII found in AI response output"""
        # Use existing redaction method
        return self._redact(content)

    def _sanitize_malicious_content(self, content: str) -> str:
        """Remove malicious content from response"""
        # Remove script tags and dangerous HTML
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<iframe[^>]*>.*?</iframe>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<object[^>]*>.*?</object>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<embed[^>]*>', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'javascript:', '[SCRIPT REDACTED]:', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'on\w+\s*=', '[EVENT REDACTED]=', sanitized, flags=re.IGNORECASE)
        
        return sanitized

    def _sanitize_inappropriate_content(self, content: str) -> str:
        """Filter inappropriate content"""
        # Replace inappropriate terms with placeholders
        replacements = {
            r'\bhate\b': '[INAPPROPRIATE CONTENT]',
            r'\bracist\b': '[INAPPROPRIATE CONTENT]',
            r'\bsexist\b': '[INAPPROPRIATE CONTENT]',
            r'\boffensive\b': '[INAPPROPRIATE CONTENT]',
            r'\binappropriate\b': '[INAPPROPRIATE CONTENT]',
            r'\bharmful\b': '[HARMFUL CONTENT]',
            r'\bdangerous\b': '[HARMFUL CONTENT]',
            r'\billegal\b': '[ILLEGAL CONTENT]',
            r'\bcriminal\b': '[ILLEGAL CONTENT]'
        }
        
        sanitized = content
        for pattern, replacement in replacements.items():
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized

    def _sanitize_medical_sensitive(self, content: str) -> str:
        """Filter sensitive medical information"""
        # Replace sensitive medical terms with generic placeholders
        replacements = {
            r'\bdiagnosis\b': '[MEDICAL INFO]',
            r'\bprognosis\b': '[MEDICAL INFO]',
            r'\btreatment\b': '[MEDICAL INFO]',
            r'\bmedication\b': '[MEDICAL INFO]',
            r'\bprescription\b': '[MEDICAL INFO]',
            r'\bdosage\b': '[MEDICAL INFO]',
            r'\bside effect\b': '[MEDICAL INFO]',
            r'\bcontraindication\b': '[MEDICAL INFO]',
            r'\ballergy\b': '[MEDICAL INFO]',
            r'\breaction\b': '[MEDICAL INFO]'
        }
        
        sanitized = content
        for pattern, replacement in replacements.items():
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized

    def _sanitize_html(self, content: str) -> str:
        """Sanitize HTML content to remove unsafe elements"""
        # Remove all HTML tags except basic formatting
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li']
        
        # Remove all HTML tags
        sanitized = re.sub(r'<[^>]*>', '', content)
        
        # Remove any remaining script-like content
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized


# Global security manager instance
security_manager = SecurityManager() 