from __future__ import annotations

import time
import secrets
import logging
from typing import Optional, Dict
from datetime import datetime, timezone

import redis

from app.core.config import settings


class OTPService:
    """Service to generate, store, and verify short-lived OTP codes.

    Prefers Redis for storage; falls back to in-memory cache if Redis is unavailable.
    """

    def __init__(self) -> None:
        self._redis: Optional[redis.Redis] = None
        self._memory_store: Dict[str, Dict[str, float]] = {}
        self.logger = logging.getLogger(__name__)
        
        try:
            self._redis = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1)
            # Quick connectivity check
            self._redis.ping()
            self.logger.info("Redis connection established successfully")
        except Exception as e:
            self.logger.warning(f"Redis connection failed, falling back to in-memory storage: {str(e)}")
            self._redis = None

    def _otp_key(self, email: str) -> str:
        return f"otp:{email.lower()}"

    def generate_otp(self, email: str, ttl_seconds: int = 300) -> str:
        code = f"{secrets.randbelow(1_000_000):06d}"
        key = self._otp_key(email)
        
        if self._redis:
            try:
                self._redis.setex(key, ttl_seconds, code)
                self.logger.info(f"OTP stored in Redis for {email}")
            except Exception as e:
                self.logger.error(f"Failed to store OTP in Redis for {email}: {str(e)}")
                # Fallback to memory storage
                self._memory_store[key] = {"code": code, "exp": time.time() + ttl_seconds}
        else:
            self._memory_store[key] = {"code": code, "exp": time.time() + ttl_seconds}
            self.logger.info(f"OTP stored in memory for {email}")
            
        # Development convenience: log OTP when in debug (do not enable in production)
        if settings.debug:
            self.logger.info(f"[DEV ONLY] OTP for {email}: {code}")
        return code

    def verify_otp(self, email: str, code: str) -> bool:
        key = self._otp_key(email)
        self.logger.info(f"Verifying OTP for {email}: {code}")
        
        if self._redis:
            try:
                stored = self._redis.get(key)
                if stored:
                    stored_code = stored.decode()
                    self.logger.info(f"Redis OTP for {email}: stored={stored_code}, provided={code}")
                    if stored_code == code:
                        self._redis.delete(key)
                        self.logger.info(f"OTP verification successful for {email}")
                        return True
                    else:
                        self.logger.warning(f"OTP verification failed for {email}: stored={stored_code}, provided={code}")
                        return False
                else:
                    self.logger.warning(f"No OTP found in Redis for {email}")
                    return False
            except Exception as e:
                self.logger.error(f"Redis error during OTP verification for {email}: {str(e)}")
                # Fallback to memory storage
                pass
        
        # Fallback to memory storage
        entry = self._memory_store.get(key)
        if not entry:
            self.logger.warning(f"No OTP found in memory for {email}")
            return False
            
        if time.time() > entry["exp"]:
            self.logger.warning(f"OTP expired for {email}")
            self._memory_store.pop(key, None)
            return False
            
        if entry["code"] == code:
            self.logger.info(f"OTP verification successful for {email} (memory)")
            self._memory_store.pop(key, None)
            return True
        else:
            self.logger.warning(f"OTP verification failed for {email}: stored={entry['code']}, provided={code}")
            return False


otp_service = OTPService()


