
# backend/apps/user_account/services/login_service.py
import logging
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from ..models import Profile
from ..validators.user_validators import UserValidator
from rest_framework.exceptions import ValidationError
from ..serializers import ProfileSerializer
from .profile_services import ProfileService
from rest_framework.response import Response
from django.conf import settings  # Import Django settings


logger = logging.getLogger(__name__)
User = get_user_model()

class LoginService:
    @staticmethod
    def validate_login_data(email, password):
        """Validate login data before attempting authentication"""
        errors = {}
        
        try:
            UserValidator.validate_email(email)
        except ValidationError as e:
            errors['email'] = str(e)
        
        if not password:
            errors['password'] = "Password is required"
        
        if errors:
            raise ValueError(errors)

    @staticmethod
    def authenticate_user(email, password):
        try:
            # First validate the input data
            LoginService.validate_login_data(email, password)
            
            user = User.objects.get(email=email)
            logger.info(f"Attempting login for email: {email}")
            
            if not user.check_password(password):
                logger.warning(f"Invalid password attempt for user: {user.email}")
                raise ValueError("Invalid password")
                
            if not user.is_verified:
                logger.warning(f"Login attempt for unverified user: {user.email}")
                raise ValueError("Email not verified. Please verify your email first.")
                
            return user
            
        except User.DoesNotExist:
            raise ValueError("User with this email does not exist")
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise
        
    @staticmethod
    def get_user_profile_response(user):
        """Fetch user profile and generate login response data."""
        try:
            profile = Profile.objects.get(user=user)
            profile_serializer = ProfileSerializer(profile)
            response_data = {
                'success': True,
                'user_id': user.id,
                'email': user.email,
                'profile': profile_serializer.data,
            }
            if settings.DEBUG:
                refresh = RefreshToken.for_user(user)
                response_data['tokens'] = {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            return response_data
        except Profile.DoesNotExist:
            response_data = {
                'success': True,
                'user_id': user.id,
                'email': user.email,
                'message': 'User logged in successfully, but no profile found.',
            }
            if settings.DEBUG:
                refresh = RefreshToken.for_user(user)
                response_data['tokens'] = {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            return response_data
        except Exception as e:
            logger.error(f"Error getting user profile response: {str(e)}")
            return {
                'success': False,
                'error': 'Failed to retrieve user profile.',
                'status_code': 500,
                'code': 'profile_retrieval_error'
            }