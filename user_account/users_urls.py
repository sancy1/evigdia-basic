
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from user_account.views import csrf_failure
from .views import (
    GoogleLogin, 
    MicrosoftLogin, 
    ProfileView, 
    SocialLoginRedirectView, 
    LogoutView, 
    GoogleLogoutView, 
    SwitchAccountView, 
    DeleteAccountView,
    RegisterView, 
    VerifyEmailView,
    UserLoginView,
    PasswordResetRequestView,
    PasswordResetTokenValidationView,
    PasswordResetView,
    ResendVerificationEmailView,
    ChangePasswordView,
    DeleteAllUsersExceptAdminView,
    DeleteSingleUserView,
    DeleteUnverifiedUsersView,
    UpdateUserRoleView,
    GetSingleUserView,
    GetAllUsersView,  
    AccountInfoView,
    DevTokenView,
    healthcheck,
)
        
urlpatterns = [
    # Google Auth endpoints
    path('auth/google/', GoogleLogin.as_view(), name='google_login'),    
    path('auth/google/logout/', GoogleLogoutView.as_view(), name='google_logout'),
    path('social-login-redirect/', SocialLoginRedirectView.as_view(), name='social-login-redirect'),
    
    # Profile endpoints
    path('profile/', ProfileView.as_view(), name='profile'),
    
    # Custome User ----------------------------------------------------------------------------------------
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),

    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
   
    path('request-password-reset/', PasswordResetRequestView.as_view(), name='request-password-reset'),
    path('validate-reset-token/', PasswordResetTokenValidationView.as_view(), name='validate-reset-token'),
    path('reset-password/', PasswordResetView.as_view(), name='reset-password'),
    path('resend-verification-email/', ResendVerificationEmailView.as_view(), name='resend-verification-email'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    
    path('delete-all-except-admin/', DeleteAllUsersExceptAdminView.as_view(), name='delete-all-except-admin'),
    path('delete/<uuid:userId>/', DeleteSingleUserView.as_view(), name='delete-user'),
    path('delete-unverified/', DeleteUnverifiedUsersView.as_view(), name='delete-unverified'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),
    
    path('update-role/<uuid:user_id>/', UpdateUserRoleView.as_view(), name='update-user-role'),
    path('users/<uuid:userId>/', GetSingleUserView.as_view(), name='get-single-user'),
    path('users/', GetAllUsersView.as_view(), name='get-all-users'),
    path('account-info/', AccountInfoView.as_view(), name='account-info'),
    
    # Development-only token endpoint (for testing)
    path('auth/dev-token/', DevTokenView.as_view(), name='dev-token'),
    
    # Render Health-Checker
    path('health/', healthcheck),
]




