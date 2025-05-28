
# user_account/validators/user_validators.py

import re
from rest_framework.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError

class UserValidator:
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
    def validate_email(email):
        try:
            validate_email(email)
        except DjangoValidationError:
            raise ValidationError("Enter a valid email address")
    
    @staticmethod
    def validate_username(username):
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long")
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValidationError("Username can only contain letters, numbers and underscores")

    @staticmethod
    def validate_registration_data(data):
        errors = {}
        
        try:
            UserValidator.validate_email(data.get('email', ''))
        except ValidationError as e:
            errors['email'] = str(e)
        
        try:
            UserValidator.validate_username(data.get('username', ''))
        except ValidationError as e:
            errors['username'] = str(e)
        
        try:
            UserValidator.validate_password(data.get('password', ''))
        except ValidationError as e:
            errors['password'] = str(e)
        
        if data.get('password') != data.get('confirm_password'):
            errors['confirm_password'] = "Passwords do not match"
        
        if errors:
            raise ValidationError(errors)