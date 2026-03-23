#!/usr/bin/env python3
"""
Test script to debug OTP generation and verification
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.otp_service import otp_service
from app.core.config import settings

async def test_otp():
    """Test OTP generation and verification"""
    print("🔍 Testing OTP Service...")
    print(f"Debug mode: {settings.debug}")
    print(f"Redis URL: {settings.redis_url}")
    
    # Test email
    test_email = "test@example.com"
    
    print(f"\n📧 Testing with email: {test_email}")
    
    # Generate OTP
    print("\n1️⃣ Generating OTP...")
    otp = otp_service.generate_otp(test_email, ttl_seconds=300)
    print(f"Generated OTP: {otp}")
    
    # Verify OTP immediately
    print("\n2️⃣ Verifying OTP immediately...")
    result = otp_service.verify_otp(test_email, otp)
    print(f"Verification result: {result}")
    
    # Verify with wrong OTP
    print("\n3️⃣ Verifying with wrong OTP...")
    wrong_result = otp_service.verify_otp(test_email, "000000")
    print(f"Wrong OTP verification result: {wrong_result}")
    
    # Verify with correct OTP again (should fail as it was consumed)
    print("\n4️⃣ Verifying with correct OTP again (should fail)...")
    result_again = otp_service.verify_otp(test_email, otp)
    print(f"Second verification result: {result_again}")
    
    print("\n✅ OTP test completed!")

if __name__ == "__main__":
    asyncio.run(test_otp())
