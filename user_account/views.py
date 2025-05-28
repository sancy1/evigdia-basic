
# user_account/views.py

import logging
from rest_framework import serializers, generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Profile, UserRole
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.microsoft.views import MicrosoftGraphOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import logout
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
# from apps.payments.models import Payment, Subscription, ActivationKey, HardwareProfile
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from user_account.permissions import IsAdminOrSuperUser
from datetime import timedelta
from django.utils import timezone
from rest_framework.decorators import api_view
from django.views.decorators.http import require_GET

from django.db import transaction
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import OutstandingToken
from django.http import JsonResponse
from django.db import connection

from .services.profile_services import ProfileService
from .validators.profile_validators import ProfileValidator
from .exceptions.error_handling import custom_exception_handler
from .models import Profile
# from ..payments.models import SubscriptionPlan
# from ..payments.models import Payment

from .exceptions.custom_exceptions import (
    ProfileAccessError,
    ProfileRetrieveError,
    ProfileUpdateError,
    ProfileValidationError,
    ProfileDeletionError,
    ProfileServiceError,
    PasswordResetError,
    InvalidTokenError,
    ChangePasswordError,
    UserNotFoundError, 
    DeleteOperationError,
    UserNotFoundError, 
    UpdateOperationError
)

from .serializers import (
    ProfileSerializer,
    UserRegistrationSerializer, 
    UserSerializer, 
    UserLoginSerializer,
    PasswordResetRequestSerializer, 
    PasswordResetTokenValidationSerializer, 
    PasswordResetSerializer,
    ResendVerificationEmailSerializer,
    ChangePasswordSerializer,
    UserDetailSerializer, 
    UpdateUserRoleSerializer
    )

from rest_framework.exceptions import ValidationError
from .services.user_services import UserService
from .models import CustomUser
from .services.email_service import EmailService
from .exceptions.custom_exceptions import RegistrationError, EmailVerificationError
from .services.login_service import LoginService
from .exceptions.custom_exceptions import LoginError
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .services.logout_service import LogoutService, GoogleLogoutService
from .exceptions.custom_exceptions import LogoutError
from .services.change_password_service import ChangePasswordService
from .services.admin_user_deletion_service import AdminUserDeletionService
from .services.admin_user_management_service import AdminUserManagementService

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .swagger_docs import (
    resend_verification_email_schema,
    password_reset_token_validation,
    password_reset_docs,
    password_reset_request_docs,
    change_password_docs,
    delete_account_docs,
    delete_all_users_except_admin_docs,
    delete_single_user_docs,
    delete_unverified_users_docs,
    update_user_role_docs,
    get_single_user_schema,
    get_all_users_schema,
    account_info_schema,
    user_login_schema,
    get_profile_schema,
    verify_email_schema,
    register_schema,
    social_login_redirect_schema,
    google_login_schema,
    google_logout_schema,
    logout_schema
    )



logger = logging.getLogger(__name__)
User = get_user_model()


 # Google OAuth -------------------------------------------------------------------
class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client
    callback_url = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI
    # callback_url = 'http://localhost:8000/accounts/google/login/callback/'
    

    @google_login_schema()
    # @google_logout_schema()
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            user = self.user
            refresh = RefreshToken.for_user(user)
            
            # Set secure cookies
            response.set_cookie(
                'access_token',
                str(refresh.access_token),
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=int(timedelta(minutes=60).total_seconds())  # Closes total_seconds and int
            )  # Closes set_cookie

            response.set_cookie(
                'refresh_token',
                str(refresh),
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=int(timedelta(days=1).total_seconds())  # Closes total_seconds and int
            )  # Closes set_cookie
            
            if settings.DEBUG:
                response.data['access_token'] = str(refresh.access_token)
                response.data['refresh_token'] = str(refresh)
                # Add is_verified status to the response
                if 'user' in response.data:
                    response.data['user']['is_verified'] = True
                response.data['is_verified'] = True
            else:
                if 'access_token' in response.data:
                    del response.data['access_token']
                if 'refresh_token' in response.data:
                    del response.data['refresh_token']
                    
        return response



 # Microsoft OAuth -------------------------------------------------------------------
class MicrosoftLogin(SocialLoginView):
    adapter_class = MicrosoftGraphOAuth2Adapter
    callback_url = settings.LOGIN_REDIRECT_URL
    client_class = OAuth2Client

    def handle_exception(self, exc):
        logger.error(f"Error during Microsoft login: {exc}")
        return super().handle_exception(exc)



# Development Token --------------------------------------------------------------------------
class DevTokenView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not settings.DEBUG:
            raise PermissionDenied("This endpoint is only available in development mode")
            
        refresh = RefreshToken.for_user(request.user)
        return Response({
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        })



# Social Login Redirect ----------------------------------------------------------------
class SocialLoginRedirectView(APIView):
    @social_login_redirect_schema()
    
    def get(self, request, *args, **kwargs):
        try:
            if request.user.is_authenticated:
                profile, created = Profile.objects.get_or_create(user=request.user)
                profile_serializer = ProfileSerializer(profile)
                return Response({
                    'detail': 'Successfully authenticated',
                    'profile': profile_serializer.data
                })
            return redirect('/accounts/login/')
        except Exception as e:
            logger.error(f"Error in social login redirect: {e}")
            raise APIException("An error occurred during the social login redirect.")



 # Logout ---------------------------------------------------------------------------------
class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    @logout_schema()

    def post(self, request, *args, **kwargs):
        try:
            return LogoutService.perform_logout(request)
        except Exception as e:
            raise LogoutError(detail=str(e))
        

@google_logout_schema()
class GoogleLogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # First perform standard logout
            logout_response = LogoutService.perform_logout(request)
            
            # Then perform Google-specific logout
            google_response = GoogleLogoutService.perform_google_logout(request)
            
            # Combine responses
            if logout_response.status_code == 200 and google_response.status_code == 200:
                return Response(
                    {'status': 'success', 'message': 'Successfully logged out from both system and Google'},
                    status=200
                )
            return google_response  # Return the most specific error
            
        except Exception as e:
            raise LogoutError(detail=str(e))


# Switch Account --------------------------------------------------------------------
class SwitchAccountView(APIView):
    """
    Handles switching between Google accounts by logging out current user
    and redirecting to Google login
    """
    def get(self, request, *args, **kwargs):
        try:
            # Logout current user
            logout(request)
            
            # Redirect to Google OAuth URL with prompt=select_account parameter
            # This forces Google to show account selection
            return redirect('/accounts/google/login/?process=login&prompt=select_account')
            
        except Exception as e:
            logger.error(f"Error switching accounts: {str(e)}")
            raise APIException("An error occurred while switching accounts.")
        
        

# User ---------------------------------------------------------------------------------------------

class RegisterView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    @register_schema()
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)  # This calls serializer.create()
            headers = self.get_success_headers(serializer.data)
            user = serializer.instance # get the user

            # Send verification email
            if not EmailService.send_verification_email(user):
                logger.error("Failed to send verification email")

            response_data = {
                'status': 'success',
                'message': 'User registered successfully. Please check your email for verification.',
            }

            if settings.DEBUG:
                response_data['debug'] = {
                    'user_id': user.id,
                    'email': user.email
                }

            user_serializer = UserSerializer(user)  # Use UserSerializer
            response_data['user'] = user_serializer.data
            return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)

        except ValidationError as e:
            raise RegistrationError(detail=str(e), field_errors=e.detail)
        except Exception as e:
            raise RegistrationError(detail=str(e))
        

        
# Verify Email ---------------------------------------------------------------------------------------
class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    @verify_email_schema()
    
    def get(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        if not token:
            return Response(
                {'status': 'error', 'message': 'Verification token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = UserService.verify_email(token)

            response_data = {
                'status': 'success',
                'message': 'Email verified successfully',
            }

            if settings.DEBUG:
                from rest_framework_simplejwt.tokens import RefreshToken
                refresh = RefreshToken.for_user(user)
                response_data['debug'] = {
                    'user_id': user.id,
                    'tokens': {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    }
                }

            return Response(response_data, status=status.HTTP_200_OK)

        except ValueError as e:
            raise EmailVerificationError(detail=str(e))
        except Exception as e:
            raise EmailVerificationError(detail="An error occurred during email verification")



# Profile ------------------------------------------------------------------------------------------
class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'patch', 'put', 'delete']
    
    def get_object(self):
        """Get or create profile with proper social auth handling"""
        try:
            user = self.request.user
            # Check for social auth through proper relation
            is_social_auth = hasattr(user, 'socialaccount') and user.socialaccount.exists()
            
            profile, created = Profile.objects.get_or_create(user=user)
            
            if created:
                # Set defaults based on available data
                name = user.get_full_name() or user.email.split('@')[0]
                profile.headline = f"{name}'s Profile"
                profile.show_email = False
                profile.show_phone = False
                profile.show_location = True
                
                # Set profile picture from social auth if available
                if is_social_auth:
                    social_account = user.socialaccount.first()
                    if social_account and hasattr(social_account, 'extra_data'):
                        picture = social_account.extra_data.get('picture', '')
                        if picture:
                            profile.profile_image_url = picture
                
                profile.save()
            
            return profile
            
        except Exception as e:
            logger.error(f"Profile retrieval error for user {self.request.user.id}: {str(e)}")
            raise ProfileRetrieveError("Failed to retrieve profile data")
        

    @swagger_auto_schema(**get_profile_schema()['retrieve'])
    def retrieve(self, request, *args, **kwargs):
        """Enhanced retrieve with proper error handling"""
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)

            response_data = {
                'status': 'success',
                'data': {
                    'profile': serializer.data,
                    'meta': {
                        'is_complete': ProfileService.is_profile_complete(instance),
                        'last_updated': instance.updated_at
                    }
                }
            }

            if settings.DEBUG:
                refresh = RefreshToken.for_user(request.user)
                response_data['data']['tokens'] = {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }

            return Response(response_data)
            
        except ProfileRetrieveError as e:
            return Response(
                {
                    'status': 'error',
                    'code': 'profile_retrieve_error',
                    'message': str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        #           return Response(response_data)
        # except ProfileAccessError as e:
        #     raise e  # Re-raise the custom exception to be handled by DRF's exception handling
        # except Exception as e:
        #     logger.error(f"Profile retrieve failed: {str(e)}")
        #     raise ProfileRetrieveError(detail='Failed to retrieve profile data.')
            
            
# class ProfileView(generics.RetrieveUpdateAPIView):
#     serializer_class = ProfileSerializer
#     permission_classes = [IsAuthenticated]
#     http_method_names = ['get', 'patch', 'put', 'delete']
    
#     def get_object(self):
#         """Get or create profile using service with custom error handling"""
#         try:
#             return ProfileService.get_or_create_profile(self.request.user)
#         except ProfileServiceError as e:
#             logger.error(f"Profile service error for user {self.request.user.id}: {str(e)}")
#             raise ProfileAccessError(detail=str(e))
#         except Exception as e:
#             logger.error(f"Unexpected error accessing profile for user {self.request.user.id}: {str(e)}")
#             return Response(
#                 {
#                     'status': 'error',
#                     'code': 'unexpected_profile_access_error',
#                     'message': 'An unexpected error occurred while accessing the profile.'
#                 },
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


    # @swagger_auto_schema(**get_profile_schema()['retrieve'])
    # def retrieve(self, request, *args, **kwargs):
    #     """Enhanced retrieve with custom error handling"""
    #     try:
    #         instance = self.get_object()
    #         if isinstance(instance, Response):  # If a generic error occurred in get_object
    #             return instance

    #         serializer = self.get_serializer(instance)

    #         response_data = {
    #             'status': 'success',
    #             'data': {
    #                 'profile': serializer.data,
    #                 'meta': {
    #                     'is_complete': ProfileService.is_profile_complete(instance),
    #                     'last_updated': instance.updated_at if hasattr(instance, 'updated_at') else None
    #                 }
    #             }
    #         }

    #         if settings.DEBUG:
    #             refresh = RefreshToken.for_user(request.user)
    #             response_data['data']['tokens'] = {
    #                 'access': str(refresh.access_token),
    #                 'refresh': str(refresh)
    #             }

        #     return Response(response_data)
        # except ProfileAccessError as e:
        #     raise e  # Re-raise the custom exception to be handled by DRF's exception handling
        # except Exception as e:
        #     logger.error(f"Profile retrieve failed: {str(e)}")
        #     raise ProfileRetrieveError(detail='Failed to retrieve profile data.')



    @swagger_auto_schema(**get_profile_schema()['partial_update'])
    def update(self, request, *args, **kwargs):
        """Enhanced update with custom error handling"""
        try:
            # Validate input data first
            validation_result = ProfileValidator.validate_update_data(request.data, request.user)
            if validation_result is not None:  # If validation failed
                return validation_result

            instance = self.get_object()
            if isinstance(instance, Response):  # If a generic error occurred in get_object
                return instance

            partial = kwargs.pop('partial', False)

            serializer = self.get_serializer(
                instance,
                data=request.data,
                partial=partial,
                context={'request': request}
            )

            if not serializer.is_valid():
                raise ProfileValidationError(detail='Invalid data provided.', errors=serializer.errors)

            self.perform_update(serializer)

            # Log changes using service
            changes = ProfileService.get_changed_fields(
                instance,
                serializer.validated_data,
                self.serializer_class.Meta.fields
            )
            logger.info(
                f"Profile updated for user {request.user.id}. Changes: {changes}"
            )

            return Response({
                'status': 'success',
                'data': serializer.data
            })
        except ProfileAccessError as e:
            raise e
        except ProfileValidationError as e:
            raise e
        except Exception as e:
            logger.error(f"Profile update failed: {str(e)}")
            raise ProfileUpdateError(detail='Failed to update profile data.')


    @swagger_auto_schema(**get_profile_schema()['destroy'])
    def destroy(self, request, *args, **kwargs):
        """Enhanced delete with custom error handling"""
        try:
            instance = self.get_object()
            if isinstance(instance, Response):  # If a generic error occurred in get_object
                return instance
            self.perform_destroy(instance)
            logger.info(f"Profile deleted for user {request.user.id}.")
            return Response({'status': 'success', 'message': 'Profile deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except ProfileAccessError as e:
            raise e
        except Exception as e:
            logger.error(f"Profile deletion failed for user {request.user.id}: {str(e)}")
            raise ProfileDeletionError(detail='Failed to delete profile.')

    def perform_destroy(self, instance):
        try:
            ProfileService.delete_profile(instance)
        except ProfileServiceError as e:
            logger.error(f"Profile service error during deletion: {str(e)}")
            raise ProfileDeletionError(detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error during profile deletion: {str(e)}")
            raise ProfileDeletionError(detail='An unexpected error occurred during profile deletion.')



# Log-In ------------------------------------------------------------------------------------
class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    @user_login_schema()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            # Authenticate user
            user = LoginService.authenticate_user(email, password)
            
            # Get profile response
            response_data = LoginService.get_user_profile_response(user)
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            # Handle serializer validation errors
            raise LoginError(detail=e.detail)
        except ValueError as e:
            # Handle service-level validation errors
            if isinstance(e.args[0], dict):  # If it's a dictionary of errors
                raise LoginError(detail=e.args[0])
            raise LoginError(detail=str(e))
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            raise LoginError(detail="An error occurred during login")
                    


    # Helper methods ------------------------------------------------------------------------------------
    def _is_profile_complete(self, profile):
        """Check if the associated user has all required fields filled"""
        required_fields = ['first_name', 'last_name', 'email']  # Customize as needed
        user = getattr(profile, 'user', None)  # Assuming your Profile model has a 'user' ForeignKey/OneToOneField
        if user:
            return all(getattr(user, field, None) for field in required_fields)
        return False  # Profile might not have a user associated yet

    def _validate_update_data(self, data):
        """Add custom validation logic for updates"""
        if 'email' in data and data['email'] != self.request.user.email:
            raise serializers.ValidationError({
                'email': 'Cannot change email via profile update'
            })

    def _get_changed_fields(self, instance, validated_data):
        """Identify which fields are being changed"""
        return {
            field: {'old': getattr(instance, field), 'new': validated_data[field]}
            for field in validated_data
            if field in self.serializer_class.Meta.fields and 
               getattr(instance, field) != validated_data[field]
        }

        
        
        
 # Password Reset -----------------------------------------------------------------------------------------       
class PasswordResetError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Failed to process password reset request.'
    default_code = 'password_reset_failed'

class InvalidTokenError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Invalid or expired reset token.'
    default_code = 'invalid_reset_token'

# Update your serializer to expect userId as well
class PasswordResetTokenValidationSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
    userId = serializers.CharField() # Or use UUIDField if your user IDs are UUIDs
    

class PasswordResetTokenValidationView(APIView):
    permission_classes = [permissions.AllowAny]
    @password_reset_token_validation()
    
    def post(self, request):
        serializer = PasswordResetTokenValidationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        user_id = serializer.validated_data['userId'] # Get userId from validated data

        user = UserService.validate_reset_token(token, user_id)
        if user:
            return Response({
                'status': 'successful',
                'message': 'Reset verification successful',
                'token': token,
                'userId': str(user.id)
            }, status=status.HTTP_200_OK)

        raise InvalidTokenError("Invalid or expired token")
    

# --------------------------------------------------------------------------------------------------------
class PasswordResetRequestView(APIView): 
    permission_classes = [permissions.AllowAny]
    @password_reset_request_docs()

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            if UserService.request_password_reset(email):
                return Response({
                    'status': 'success',
                    'message': 'Password reset link has been sent to your email.'
                }, status=status.HTTP_200_OK)
            else:
                raise PasswordResetError("Failed to send password reset email.")
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'success',
                'message': 'Password reset link has been sent to your email.'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error during password reset request: {str(e)}")
            raise PasswordResetError("An unexpected error occurred during the password reset request.")


# --------------------------------------------------------------------------------------------------------
class PasswordResetView(APIView):
    permission_classes = [permissions.AllowAny]
    @password_reset_docs()
    
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        user = UserService.validate_reset_token(data['token'], data['userId'])

        if not user:
            raise InvalidTokenError("Invalid or expired token")

        try:
            UserService.reset_password(user, data['newPassword'])
            return Response({
                'success': True,
                'message': 'Password reset successfully. You may login with your new password'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            raise PasswordResetError(str(e))
        
        

# Resend Verification Email -----------------------------------------------------------------------------

class ResendVerificationEmailView(APIView):
    permission_classes = [permissions.AllowAny]  # Or maybe IsAuthenticated if you only want logged-in users to resend
    @resend_verification_email_schema()

    def post(self, request):
        serializer = ResendVerificationEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = UserService.resend_verification_email(email)
            if user:
                return Response({
                    'status': 'success',
                    'message': 'Verification email has been resent to your email address.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': 'failed',
                    'message': 'Failed to resend verification email.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
            
            
# Change Password ----------------------------------------------------------------------------------------
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    @change_password_docs()
    
    def put(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        try:
            ChangePasswordService.change_password(
                user=request.user,
                current_password=serializer.validated_data['currentPassword'],
                new_password=serializer.validated_data['newPassword'],
                confirm_new_password=serializer.validated_data['confirmNewPassword']
            )
            return Response({
                'success': True,
                'message': 'Password changed successfully'
            }, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Password change error for {request.user.email}: {str(e)}")
            return Response({
                'error': 'Failed to change password'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# DELETE USER ACCOUNT AND ASSOCIATED APPLICATIONS -----------------------------------------------------------
class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]
    @delete_account_docs()

    def delete(self, request, *args, **kwargs):
        try:
            deletion_report = AdminUserDeletionService.delete_user_and_related_data(request.user)
            response = Response({
                "status": "success",
                "message": "Account and all associated data deleted successfully",
                "deletion_report": deletion_report,
                "metadata": {
                    "timestamp": timezone.now().isoformat() + "Z",
                    "deletion_complete": True
                }
            }, status=status.HTTP_200_OK)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response
        except DeleteOperationError as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            


# DELETE ALL USERS EXCEPT ADMIN (ADMIN-ONLY) ---------------------------------------------------------------------
class DeleteAllUsersExceptAdminView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    @delete_all_users_except_admin_docs()

    def delete(self, request, *args, **kwargs):
        try:
            deleted_count = AdminUserDeletionService.delete_all_users_except_admin()
            return Response({
                "status": "success",
                "message": f"{deleted_count} user(s) (excluding admins) deleted successfully."
            }, status=status.HTTP_200_OK)
        except DeleteOperationError as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# DELETE SINGLE USERS (ADMIN-ONLY) ---------------------------------------------------------------------
class DeleteSingleUserView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    @delete_single_user_docs()

    def delete(self, request, userId, *args, **kwargs):
        try:
            deleted_report = AdminUserDeletionService.delete_single_user(userId)
            if deleted_report:
                return Response({
                    "status": "success",
                    "message": f"User with ID {userId} and associated data deleted successfully.",
                    "deletion_report": deleted_report
                }, status=status.HTTP_200_OK)
            else:
                raise UserNotFoundError(f"User with ID {userId} not found.")
        except UserNotFoundError as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except DeleteOperationError as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# DELETE UNVERIFIED USERS (ADMIN-ONLY) ---------------------------------------------------------------------
class DeleteUnverifiedUsersView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    @delete_unverified_users_docs()

    def delete(self, request, *args, **kwargs):
        try:
            deleted_count = AdminUserDeletionService.delete_unverified_users()
            return Response({
                "status": "success",
                "message": f"{deleted_count} unverified user(s) deleted successfully."
            }, status=status.HTTP_200_OK)
        except DeleteOperationError as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# PUT: Update user role (Admin Only) ----------------------------------------------------------------------------------
# PUT: Update user role and permissions (Admin Only)
# ----------------------------------------------------------------------------------
class UpdateUserRoleView(APIView):
    permission_classes = [IsAdminOrSuperUser]

    def put(self, request, user_id):
        # Double-check permissions (you might want to rely solely on permission_classes)
        if not (request.user.is_superuser or
                (request.user.role == UserRole.ADMIN.value and request.user.is_staff)):
            logger.warning(f"Unauthorized role/permission change attempt by {request.user.email}")
            return Response(
                {"detail": "You do not have permission to perform this action"},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Prevent privilege escalation
        if user.is_superuser and not request.user.is_superuser:
            return Response(
                {"detail": "Only superusers can modify other superusers"},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = UpdateUserRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Log the changes
        old_role = user.role
        old_is_staff = user.is_staff
        old_is_superuser = user.is_superuser

        new_role = serializer.validated_data.get('role', old_role)
        new_is_staff = serializer.validated_data.get('is_staff', old_is_staff)
        new_is_superuser = serializer.validated_data.get('is_superuser', old_is_superuser)

        logger.info(
            f"Role/permission change by {request.user.email}: "
            f"User {user_id} from role {old_role} to {new_role}, "
            f"staff {old_is_staff} to {new_is_staff}, "
            f"superuser {old_is_superuser} to {new_is_superuser}"
        )

        user.role = new_role
        user.is_staff = new_is_staff
        user.is_superuser = new_is_superuser
        user.save()

        return Response({
            "status": "success",
            "user_id": str(user.id),
            "new_role": user.role,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser,
        })
        

# class UpdateUserRoleView(APIView):
#     permission_classes = [IsAdminOrSuperUser]
    
#     def put(self, request, user_id):
#         # Double-check permissions
#         if not (request.user.is_superuser or 
#                (request.user.role == UserRole.ADMIN.value and request.user.is_staff)):
#             logger.warning(f"Unauthorized role change attempt by {request.user.email}")
#             return Response(
#                 {"detail": "You do not have permission to perform this action"},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         try:
#             user = CustomUser.objects.get(id=user_id)
#         except CustomUser.DoesNotExist:
#             return Response(
#                 {"detail": "User not found"},
#                 status=status.HTTP_404_NOT_FOUND
#             )

#         # Prevent privilege escalation
#         if user.is_superuser and not request.user.is_superuser:
#             return Response(
#                 {"detail": "Only superusers can modify other superusers"},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         serializer = UpdateUserRoleSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         # Log the change
#         logger.info(
#             f"Role change by {request.user.email}: "
#             f"User {user_id} from {user.role} to {serializer.validated_data['role']}"
#         )
        
#         user.role = serializer.validated_data['role']
#         user.save(update_fields=['role'])
        
#         return Response({
#             "status": "success",
#             "user_id": str(user.id),
#             "new_role": user.role
#         })



# class UpdateUserRoleView(APIView):
#     permission_classes = [IsAdminOrSuperUser]
    
#     def put(self, request, user_id):
#         # Double-check permission (defense in depth)
#         if not (request.user.role == UserRole.ADMIN.value or request.user.is_superuser):
#             return Response(
#                 {"detail": "You do not have permission to perform this action"},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         try:
#             user = CustomUser.objects.get(id=user_id)
#         except CustomUser.DoesNotExist:
#             return Response(
#                 {"detail": "User not found"},
#                 status=status.HTTP_404_NOT_FOUND
#             )

#         # Prevent modifying superusers unless current user is superuser
#         if user.is_superuser and not request.user.is_superuser:
#             return Response(
#                 {"detail": "Cannot modify superuser roles"},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         serializer = UpdateUserRoleSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         user.role = serializer.validated_data['role']
#         user.save(update_fields=['role'])
        
#         return Response({
#             "status": "Role updated successfully",
#             "new_role": user.role
#         })


# class UpdateUserRoleView(APIView):
#     permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
#     @update_user_role_docs()

#     def put(self, request, userId):
#         serializer = UpdateUserRoleSerializer(data=request.data)
#         if serializer.is_valid():
#             role = serializer.validated_data['role']
#             try:
#                 updated_user = AdminUserManagementService.update_user_role(userId, role)
#                 if updated_user:
#                     user_serializer = UserDetailSerializer(updated_user)
#                     return Response(user_serializer.data, status=status.HTTP_200_OK)
#                 else:
#                     raise UserNotFoundError(f"User with ID {userId} not found.")
#             except UserNotFoundError as e:
#                 return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
#             except UpdateOperationError as e:
#                 return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#             except ValueError as e:
#                 return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#             except Exception as e:
#                 return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# GET: Get a single user (Admin Only)----------------------------------------------------------------------------------
class GetSingleUserView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    @get_single_user_schema()

    def get(self, request, userId):
        try:
            user = AdminUserManagementService.get_user_by_id(userId)
            if user:
                user_serializer = UserDetailSerializer(user)
                return Response(user_serializer.data, status=status.HTTP_200_OK)
            else:
                raise UserNotFoundError(f"User with ID {userId} not found.")
        except UserNotFoundError as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# GET: Get all users (Admin Only)----------------------------------------------------------------------------------
class GetAllUsersView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    @get_all_users_schema()

    def get(self, request):
        try:
            users = AdminUserManagementService.get_all_users()
            user_serializer = UserDetailSerializer(users, many=True)
            return Response(user_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# 7. Get user account info (Authenticated User)----------------------------------------------------------------------------------
class AccountInfoView(APIView):
    permission_classes = [IsAuthenticated]
    @account_info_schema()

    def get(self, request):
        user_serializer = UserDetailSerializer(request.user)
        return Response(user_serializer.data, status=status.HTTP_200_OK)
    
    
    
    
    
# CSRF-FAILURE ----------------------------------------------------------------------------------
@api_view(['GET', 'POST'])
def csrf_failure(request, reason=""):
    return Response(
        {
            "status": "error", 
            "code": "csrf_failure",
            "message": "CSRF verification failed"
        },
        status=status.HTTP_403_FORBIDDEN
    )
    
    
    
# RENDER HEALTH-CHECK -----------------------------------------------------------------------------------------
@require_GET
def healthcheck(request):
    """Simplified healthcheck without DB dependency"""
    return JsonResponse({"status": "ok"}, status=200)