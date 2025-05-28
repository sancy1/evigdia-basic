from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)

class ProfileValidator:
    @staticmethod
    def validate_update_data(data, user):
        """
        Validate profile update data with comprehensive checks
        Returns:
            - None if validation passes
            - Response object with error if validation fails
        """
        try:
            errors = {}
            
            if 'email' in data and data.get('email') != user.email:
                errors['email'] = 'Cannot change email via profile update'
            
            if 'bio' in data and len(data['bio']) > 500:
                errors['bio'] = 'Biography cannot exceed 500 characters'
            
            if errors:
                return Response(
                    {
                        'status': 'error',
                        'code': 'profile_validation_error',
                        'message': 'Profile update validation failed',
                        'errors': errors
                    },
                    status=status.HTTP_422_UNPROCESSABLE_ENTITY
                )
            return None
            
        except Exception as e:
            logger.error(f"Profile validation error: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'code': 'profile_validation_exception',
                    'message': 'An error occurred during validation'
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    def validate_profile_complete(profile):
        """
        Validate profile completeness
        Returns:
            - True if profile is complete
            - Response object with error if validation fails
        """
        try:
            required_fields = ['first_name', 'last_name', 'email']
            user = profile.user
            missing_fields = [field for field in required_fields if not getattr(user, field, None)]
            
            if missing_fields:
                return Response(
                    {
                        'status': 'error',
                        'code': 'incomplete_profile',
                        'message': 'Profile is incomplete',
                        'missing_fields': missing_fields
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            return True
            
        except Exception as e:
            logger.error(f"Profile completeness check failed: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'code': 'profile_completeness_check_error',
                    'message': 'An error occurred during completeness check'
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )