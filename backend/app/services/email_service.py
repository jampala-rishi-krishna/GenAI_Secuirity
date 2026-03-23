from __future__ import annotations

import smtplib
import logging
from email.message import EmailMessage
from typing import Optional

from app.core.config import settings


class EmailService:
    def __init__(self) -> None:
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password
        self.from_email = settings.smtp_from_email
        self.use_tls = settings.smtp_use_tls
        self.logger = logging.getLogger(__name__)

    def send_otp(self, to_email: str, code: str) -> bool:
        # Check if SMTP is properly configured
        if not all([self.host, self.port, self.from_email]):
            self.logger.warning(f"SMTP not configured. Cannot send OTP to {to_email}. OTP code: {code}")
            # In development, we'll return True to allow the flow to continue
            # The OTP is already logged in the OTP service
            return True
            
        msg = EmailMessage()
        msg["Subject"] = "Your One-Time Passcode"
        msg["From"] = self.from_email
        msg["To"] = to_email
        msg.set_content(f"Your OTP code is: {code}\nIt expires in 5 minutes.")

        try:
            if self.use_tls:
                with smtplib.SMTP(self.host, self.port, timeout=10) as s:
                    s.starttls()
                    if self.username and self.password:
                        s.login(self.username, self.password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=10) as s:
                    if self.username and self.password:
                        s.login(self.username, self.password)
                    s.send_message(msg)
            self.logger.info(f"OTP email sent successfully to {to_email}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send OTP email to {to_email}: {str(e)}")
            # In development, we'll return True to allow the flow to continue
            # The OTP is already logged in the OTP service
            return True


email_service = EmailService()


