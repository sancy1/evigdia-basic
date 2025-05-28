
# src/utils.py

from rest_framework.response import Response
from rest_framework import status
from axes.helpers import get_lockout_message

def custom_lockout(request, credentials, *args, **kwargs):
    """
    Custom JSON response for locked accounts
    """
    return Response(
        {
            "status": "error",
            "code": "account_locked",
            "message": "Account temporarily locked",
            "detail": str(get_lockout_message()),
            "cooldown_until": request.axes_cooloff_time,  # Exact unlock time
            "attempts": request.axes_failure_count
        },
        status=status.HTTP_403_FORBIDDEN,
        headers={'Retry-After': '3600'}  # HTTP standard for cooldowns
    )
    
    
    
    
    
    
    
    
    
# # backend/utils.py
# from drf_spectacular.plumbing import build_basic_type
# from drf_spectacular.types import OpenApiTypes
# from drf_spectacular.utils import OpenApiParameter, OpenApiExample

# def preprocessing_filter_spec(endpoints):
#     # Filter out endpoints you don't want to document
#     return [
#         (path, path_regex, method, callback)
#         for path, path_regex, method, callback in endpoints
#         if not path.startswith('/admin/')  # Example: exclude admin URLs
#     ]

# def customize_operation_id(operation_id, **kwargs):
#     # Customize operation IDs for better readability
#     return operation_id.replace('_', '-').lower()

# def custom_swagger_settings():
#     # You can return dynamic settings here
#     return {
#         'persistAuthorization': True,
#         'defaultModelsExpandDepth': -1,  # Hide schemas by default
#     }
    