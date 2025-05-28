# backend/apps/user_account/services/logout_service.py
import logging
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)

class LogoutService:
    @staticmethod
    def perform_logout(request):
        """Handle standard JWT logout"""
        try:
            # Blacklist refresh token if provided
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                logger.info(f"Token blacklisted for user: {request.user.id if request.user.is_authenticated else 'unknown'}")

            return Response(
                {'status': 'success', 'message': 'Successfully logged out'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response(
                {'status': 'error', 'message': 'Logout failed'},
                status=status.HTTP_400_BAD_REQUEST
            )


class GoogleLogoutService:
    @staticmethod
    def perform_google_logout(request):
        """Handle Google OAuth2 logout"""
        try:
            # Clear session data
            if 'socialaccount_google' in request.session:
                del request.session['socialaccount_google']
            
            # Clear cookies
            response = Response(
                {'status': 'success', 'message': 'Successfully logged out from Google'},
                status=status.HTTP_200_OK
            )
            
            # Clear the cookies we set during login
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            
            # Additional Google-specific cleanup
            if hasattr(request, 'user') and request.user.is_authenticated:
                logger.info(f"Google user logged out: {request.user.email}")
            
            return response
            
        except Exception as e:
            logger.error(f"Google logout error: {str(e)}")
            return Response(
                {'status': 'error', 'message': 'Google logout failed'},
                status=status.HTTP_400_BAD_REQUEST
            )