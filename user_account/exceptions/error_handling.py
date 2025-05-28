import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError, AuthenticationFailed
from django.core.exceptions import ValidationError as DjangoValidationError
from .custom_exceptions import *

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Handles all API exceptions and ensures JSON responses
    """
    request = context.get('request')
    user_id = request.user.id if request and hasattr(request, 'user') and request.user else 'anonymous'

    # Convert JWT exceptions first
    if isinstance(exc, (InvalidToken, TokenError, AuthenticationFailed)):
        logger.warning(f"JWT authentication failed for user {user_id}: {str(exc)}")
        exc = AuthenticationFailed({
            'error': 'authentication_error',
            'detail': str(exc.detail) if hasattr(exc, 'detail') else 'Invalid authentication credentials',
            'code': 'invalid_token'
        })

    # Let DRF handle the exception first
    response = exception_handler(exc, context)

    # Handle unprocessed exceptions
    if response is None:
        if isinstance(exc, DjangoValidationError):
            return handle_validation_error(exc, user_id)
        elif isinstance(exc, ProfileServiceError):
            return handle_profile_error(exc, user_id)
        return handle_unexpected_error(exc, user_id)

    # Standardize response format
    return standardize_error_response(response, exc)

def handle_validation_error(exc, user_id):
    logger.warning(f"Validation error for user {user_id}: {str(exc)}")
    return Response(
        {
            'success': False,
            'error': 'validation_error',
            'detail': exc.message_dict if hasattr(exc, 'message_dict') else str(exc),
            'code': 'invalid_input',
            'status_code': status.HTTP_422_UNPROCESSABLE_ENTITY
        },
        status=status.HTTP_422_UNPROCESSABLE_ENTITY
    )

def handle_profile_error(exc, user_id):
    logger.error(f"Profile error for user {user_id}: {str(exc)}")
    return Response(
        {
            'success': False,
            'error': exc.default_detail,
            'detail': str(exc.detail) if hasattr(exc, 'detail') else str(exc),
            'code': exc.default_code,
            'status_code': exc.status_code
        },
        status=exc.status_code
    )

def handle_unexpected_error(exc, user_id):
    logger.error(f"Unexpected error for user {user_id}: {str(exc)}", exc_info=True)
    return Response(
        {
            'success': False,
            'error': 'server_error',
            'detail': str(exc) if settings.DEBUG else 'Internal server error',
            'code': 'internal_error',
            'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )

def standardize_error_response(response, exc):
    """Ensures consistent error response format"""
    error_data = {
        'success': False,
        'status_code': response.status_code,
        'code': response.data.get('code') 
                or getattr(exc, 'default_code', None)
                or response.data.get('error', 'unknown_error'),
        'error': response.data.get('error', response.data.get('detail', 'request_failed')),
        'detail': str(response.data.get('detail', ''))
    }
    
    # Clean up redundant fields
    if error_data['detail'] == error_data['error']:
        error_data.pop('detail')
    
    response.data = error_data
    return response