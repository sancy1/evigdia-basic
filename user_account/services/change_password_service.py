
# backend/apps/user_account/services/change_password_service.py

import logging
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)
User = get_user_model()


class ChangePasswordService:
    @staticmethod
    def change_password(user, current_password, new_password, confirm_new_password):
        """
        Update user's password after validation
        Args:
            user: User object
            current_password: Current password for verification
            new_password: New password to set
            confirm_new_password: Must match new_password
        """
        try:
            # Verify current password first
            if not user.check_password(current_password):
                raise ValidationError("Current password is incorrect")
            
            # Verify new passwords match
            if new_password != confirm_new_password:
                raise ValidationError("New passwords do not match")
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            # Optional: Add password change logging or signal here
            logger.info(f"Password changed for user {user.email}")
            return True
            
        except ValidationError as ve:
            logger.warning(f"Password change validation failed for {user.email}: {str(ve)}")
            raise  # Re-raise validation errors
        except Exception as e:
            logger.error(f"Error changing password for {user.email}: {str(e)}")
            raise Exception("Failed to change password due to server error")


