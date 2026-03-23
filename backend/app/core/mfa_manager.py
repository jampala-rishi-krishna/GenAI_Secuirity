"""
Multi-Factor Authentication (MFA) Manager for Healthcare GenAI Application
Implements TOTP, recovery codes, and MFA policy management
"""

import pyotp
import secrets
import hashlib
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum
from pydantic import BaseModel
import logging
from dataclasses import dataclass

from app.core.config import settings


class MFAMethod(Enum):
    """MFA method enumeration"""
    TOTP = "totp"
    EMAIL = "email"
    SMS = "sms"
    BIOMETRIC = "biometric"


class MFAPolicy(Enum):
    """MFA policy enumeration"""
    OPTIONAL = "optional"
    REQUIRED_FOR_ADMIN = "required_for_admin"
    REQUIRED_FOR_ALL = "required_for_all"
    CONDITIONAL = "conditional"


@dataclass
class MFARecoveryCode:
    """MFA recovery code data structure"""
    code: str
    is_used: bool = False
    created_at: datetime = None
    used_at: Optional[datetime] = None


class MFAManager:
    """MFA management system with TOTP and recovery codes"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.recovery_codes_count = 10
        self.totp_issuer = "Healthcare GenAI"
        self.totp_algorithm = "sha1"
        self.totp_digits = 6
        self.totp_period = 30
        
    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_totp_uri(self, username: str, secret: str) -> str:
        """Generate TOTP URI for QR code generation"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name=self.totp_issuer
        )
    
    def generate_qr_code(self, uri: str) -> str:
        """Generate QR code as base64 string"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception as e:
            self.logger.error(f"TOTP verification error: {e}")
            return False
    
    def generate_recovery_codes(self) -> List[MFARecoveryCode]:
        """Generate recovery codes for MFA backup"""
        codes = []
        for _ in range(self.recovery_codes_count):
            # Generate 8-character alphanumeric codes
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            codes.append(MFARecoveryCode(
                code=code,
                created_at=datetime.utcnow()
            ))
        return codes
    
    def verify_recovery_code(self, codes: List[MFARecoveryCode], input_code: str) -> Tuple[bool, Optional[MFARecoveryCode]]:
        """Verify recovery code and mark as used"""
        input_code = input_code.upper().strip()
        for code_obj in codes:
            if code_obj.code == input_code and not code_obj.is_used:
                code_obj.is_used = True
                code_obj.used_at = datetime.utcnow()
                return True, code_obj
        return False, None
    
    def get_mfa_policy(self, user_role: str, is_admin: bool) -> MFAPolicy:
        """Get MFA policy based on user role and admin status"""
        if is_admin:
            return MFAPolicy.REQUIRED_FOR_ADMIN
        elif user_role in ['healthcare_professional', 'super_admin']:
            return MFAPolicy.REQUIRED_FOR_ADMIN
        else:
            return MFAPolicy.OPTIONAL
    
    def is_mfa_required(self, user_role: str, is_admin: bool) -> bool:
        """Check if MFA is required for the user"""
        policy = self.get_mfa_policy(user_role, is_admin)
        return policy in [MFAPolicy.REQUIRED_FOR_ADMIN, MFAPolicy.REQUIRED_FOR_ALL]
    
    def get_mfa_status_summary(self, users: List[Dict]) -> Dict:
        """Get MFA status summary for admin dashboard"""
        total_users = len(users)
        mfa_enabled = sum(1 for user in users if user.get('mfa_enabled', False))
        mfa_required = sum(1 for user in users if self.is_mfa_required(
            user.get('role', 'user'), 
            user.get('role') in ['admin', 'super_admin']
        ))
        mfa_compliant = sum(1 for user in users if (
            user.get('mfa_enabled', False) or 
            not self.is_mfa_required(user.get('role', 'user'), user.get('role') in ['admin', 'super_admin'])
        ))
        
        return {
            "total_users": total_users,
            "mfa_enabled": mfa_enabled,
            "mfa_required": mfa_required,
            "mfa_compliant": mfa_compliant,
            "compliance_rate": (mfa_compliant / total_users * 100) if total_users > 0 else 0
        }


# Global MFA manager instance
mfa_manager = MFAManager()
