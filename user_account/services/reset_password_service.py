# backend/apps/user_account/services/reset_password_service.py
import logging
import requests
import uuid
from django.conf import settings
from django.utils import timezone
from ..models import CustomUser

logger = logging.getLogger(__name__)

class ResetPasswordService:
    @staticmethod
    def send_password_reset_email(user):
        """
        Completely standalone password reset email service
        Doesn't depend on EmailService class
        """
        try:
            # Generate reset token
            user.reset_password_token = uuid.uuid4().hex
            user.reset_password_expires = timezone.now() + timezone.timedelta(hours=1)
            user.save()

            # Build reset URL
            reset_url = f"{settings.FRONTEND_URL}/api/user/reset-password?token={user.reset_password_token}&userId={user.id}"

            # Prepare email content
            email_data = {
                "sender": {
                    "name": settings.EMAIL_SENDER_NAME,
                    "email": settings.EMAIL_SENDER_EMAIL
                },
                "to": [{"email": user.email, "name": user.username}],
                "subject": "Password Reset Request",
                "htmlContent": f"""
                    <p>Hello {user.username},</p>
                    <p>We received a request to reset your password. Click the link below to proceed:</p>
                    <p><a href="{reset_url}">Reset Password</a></p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <p>The link will expire in 1 hour.</p>
                """
            }

            # Send email directly using Brevo API
            headers = {
                "accept": "application/json",
                "api-key": settings.BREVO_API_KEY,
                "content-type": "application/json"
            }

            response = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers=headers,
                json=email_data
            )

            if response.status_code != 201:
                logger.error(f"Password reset email failed to send: {response.text}")
                return False

            logger.info(f"Password reset email sent to {user.email}")
            return True

        except Exception as e:
            logger.error(f"Error in password reset process: {str(e)}")
            return False

    @staticmethod
    def validate_reset_token(token, user_id):
        """Validate the reset token"""
        try:
            user = CustomUser.objects.get(
                id=user_id,
                reset_password_token=token,
                reset_password_expires__gt=timezone.now()
            )
            return user
        except CustomUser.DoesNotExist:
            return None

    @staticmethod
    def reset_user_password(user, new_password):
        """Complete the password reset process"""
        try:
            # Save old password to history
            from ..models import PasswordHistory
            PasswordHistory.objects.create(
                user=user,
                password=user.password
            )

            # Update password and clear token
            user.set_password(new_password)
            user.reset_password_token = None
            user.reset_password_expires = None
            user.save()
            return True
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            return False