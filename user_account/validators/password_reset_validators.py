
# backend/apps/user_account/validators/password_reset_validators.py
from rest_framework.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password
import re

class PasswordResetValidator:
    @staticmethod
    def validate_password(password):
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
    # def validate_password_not_used_before(user, new_password):
    #     """
    #     Check if the password has been used before by this user
    #     """
    #     for entry in user.password_history.order_by('-created_at')[:5]:  # Check last 5 passwords
    #         if check_password(new_password, entry.password):
    #             raise ValidationError("You cannot use a password you've used before")

    @staticmethod
    def validate_password_reset_data(data):
        errors = {}
        
        if not data.get('token'):
            errors['token'] = "Token is required"
            
        if not data.get('newPassword'):
            errors['newPassword'] = "New password is required"
        else:
            try:
                PasswordResetValidator.validate_password(data['newPassword'])
            except ValidationError as e:
                errors['newPassword'] = str(e)
                
        if not data.get('confirmNewPassword'):
            errors['confirmNewPassword'] = "Please confirm your new password"
        elif data['newPassword'] != data['confirmNewPassword']:
            errors['confirmNewPassword'] = "Passwords do not match"
            
        if not data.get('userId'):
            errors['userId'] = "User ID is required"
            
        if errors:
            raise ValidationError(errors)

    @staticmethod
    def validate_email_exists(email):
        from ..models import CustomUser
        if not CustomUser.objects.filter(email=email).exists():
            raise ValidationError("No account exists with this email address")