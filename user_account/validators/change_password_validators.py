
# backend/apps/user_account/validators/change_password_validators.py
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
import re

class ChangePasswordValidator:
    @staticmethod
    def validate_password_complexity(password):
        """Validate password meets complexity requirements"""
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', password):
            raise ValidationError("Password must contain at least one digit")
        if not re.search(r'[^A-Za-z0-9]', password):
            raise ValidationError("Password must contain at least one special character")

    @staticmethod
    def validate_change_password_data(user, data):
        """Validate all change password requirements"""
        errors = {}
        
        # Validate current password
        if not data.get('currentPassword'):
            errors['currentPassword'] = "Current password is required"
        elif not user.check_password(data['currentPassword']):
            errors['currentPassword'] = "Current password is incorrect"
        
        # Validate new password
        if not data.get('newPassword'):
            errors['newPassword'] = "New password is required"
        else:
            try:
                ChangePasswordValidator.validate_password_complexity(data['newPassword'])
            except ValidationError as e:
                errors['newPassword'] = str(e)
        
        # Validate confirmation
        if not data.get('confirmNewPassword'):
            errors['confirmNewPassword'] = "Please confirm your new password"
        elif data['newPassword'] != data['confirmNewPassword']:
            errors['confirmNewPassword'] = "Passwords do not match"
        
        if errors:
            raise ValidationError(errors)