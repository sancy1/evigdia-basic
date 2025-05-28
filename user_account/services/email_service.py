import logging
from django.conf import settings
import requests
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_verification_email(user):
        try:
            verification_url = f"{settings.FRONTEND_URL}/api/user/verify-email?token={user.verification_token}"
            
            headers = {
                "accept": "application/json",
                "api-key": settings.BREVO_API_KEY,
                "content-type": "application/json"
            }
            
            email_data = {
                "sender": {
                    "name": settings.EMAIL_SENDER_NAME,
                    "email": settings.EMAIL_SENDER_EMAIL
                },
                "to": [{"email": user.email, "name": user.username}],
                "subject": "Verify Your Email Address",
                "htmlContent": f"""
                    <p>Hello {user.username},</p>
                    <p>Please click the link below to verify your email address:</p>
                    <p><a href="{verification_url}">Verify Email</a></p>
                    <p>If you didn't create an account, please ignore this email.</p>
                """
            }
            
            response = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers=headers,
                json=email_data
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to send verification email: {response.text}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending verification email: {str(e)}")
            return False