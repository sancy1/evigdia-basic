
# src/urls.py  | main project urls

from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static

from user_account.views import GoogleLogin
from user_account.views import GoogleLogin

from drf_yasg import openapi
from drf_yasg.views import get_schema_view as swagger_get_schema_view

from django.contrib import admin
from django.urls import path, include

schema_view = swagger_get_schema_view(
    openapi.Info(
        title='EvigDia Basic API',
        default_version='1.0.0',
        description='API documentation of FussionPex',
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@evigdiabasic.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Swagger Documentation -----------------------------------------------------------------------------------------
    path('swagger/schema/', schema_view.with_ui('swagger', cache_timeout=0), name="swagger-schema"),
    
    # Account -----------------------------------------------------------------------------------------
    path('api/user/', include('user_account.users_urls')),
    path('api/auth/google/', GoogleLogin.as_view(), name='google-login'),
    path('accounts/', include('allauth.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

