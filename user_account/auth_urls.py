

from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from user_account.views import csrf_failure
from .views import (
    GoogleLogin, 
    DevTokenView,
    GoogleLogoutView,
    SocialLoginRedirectView, 
    SwitchAccountView,
)
        
urlpatterns = [

    # Development-only token endpoint (for testing)
    path('auth/dev-token/', DevTokenView.as_view(), name='dev-token'),
    
    # Django REST Auth endpoints
    path('auth/', include('dj_rest_auth.urls')),
    path('auth/registration/', include('dj_rest_auth.registration.urls')),
    
    # path('switch-account/', SwitchAccountView.as_view(), name='switch-account'),
    # path('switch-account/', SwitchAccountView.as_view(), name='switch-account'),
    
    # JWT endpoints
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]




