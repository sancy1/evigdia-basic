

# # /user_account/adapters.py

# import logging
# from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
# from allauth.account.adapter import DefaultAccountAdapter
# from allauth.account.utils import user_email, user_field, user_username
# from allauth.utils import valid_email_or_none
# from django.contrib.auth import get_user_model
# from django.contrib.auth.hashers import make_password
# from .models import Profile
# import requests
# from django.conf import settings
# from django.utils import timezone
# from datetime import timedelta
# import uuid

# logger = logging.getLogger(__name__)

# User = get_user_model()

# class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
#     def pre_social_login(self, request, sociallogin):
#         email = user_email(sociallogin.user)
#         if email:
#             try:
#                 user = User.objects.get(email=email)
#                 sociallogin.connect(request, user)
#             except User.DoesNotExist:
#                 pass

#     def populate_user(self, request, sociallogin, data):
#         user = sociallogin.user
        
#         email = data.get('email')
#         user_email(user, valid_email_or_none(email) or '')
        
#         username = data.get('username') or email.split('@')[0]
#         user_username(user, username or '')
        
#         # Mark all social login users as verified by default
#         user.is_verified = True
        
#         if sociallogin.account.provider == 'google':
#             user_field(user, 'first_name', data.get('given_name', ''))
#             user_field(user, 'last_name', data.get('family_name', ''))
#             # Get profile picture from Google data
#             picture = data.get('picture', '')
#             if picture:
#                 user.profile_picture = picture
#             # Google-authenticated users are automatically verified
#             user.set_unusable_password()
#         elif sociallogin.account.provider == 'microsoft':
#             user_field(user, 'first_name', data.get('givenName', ''))
#             user_field(user, 'last_name', data.get('surname', ''))
#             user.profile_picture = self.get_microsoft_profile_picture(sociallogin)
#             user.set_unusable_password()
        
#         logger.debug(f"Populated user data: email={email}, username={username}, "
#                      f"first_name={user.first_name}, last_name={user.last_name}, "
#                      f"profile_picture={user.profile_picture}, is_verified={user.is_verified}")
        
#         return user

#     def save_user(self, request, sociallogin, form=None):
#         user = super().save_user(request, sociallogin, form)
#         self.update_user_profile(user, sociallogin)
#         return user

#     def update_user_profile(self, user, sociallogin):
#         extra_data = sociallogin.account.extra_data
#         profile, created = Profile.objects.get_or_create(user=user)
        
#         # Update profile fields from social login
#         if sociallogin.account.provider == 'google':
#             # Set profile image URL from Google picture
#             picture_url = extra_data.get('picture', '')
#             if picture_url:
#                 profile.profile_image_url = picture_url
#                 user.profile_picture = picture_url
#                 user.save()
            
#             if 'given_name' in extra_data and 'family_name' in extra_data:
#                 profile.headline = f"{extra_data['given_name']} {extra_data['family_name']}'s Profile"
#         elif sociallogin.account.provider == 'microsoft':
#             profile.profile_image_url = self.get_microsoft_profile_picture(sociallogin)
        
#         profile.save()
        
#         logger.debug(f"Updated user profile: id={user.id}, email={user.email}, "
#                      f"is_verified={user.is_verified}, profile_image={profile.profile_image_url}")

#     def get_microsoft_profile_picture(self, sociallogin):
#         access_token = sociallogin.token.token
#         headers = {'Authorization': f'Bearer {access_token}'}
#         photo_url = 'https://graph.microsoft.com/v1.0/me/photo/$value'
        
#         try:
#             response = requests.get(photo_url, headers=headers)
#             if response.status_code == 200:
#                 return photo_url
#         except requests.RequestException as e:
#             logger.error(f"Error fetching Microsoft profile picture: {e}")
        
#         return ''

# class CustomAccountAdapter(DefaultAccountAdapter):
#     def get_login_redirect_url(self, request):
#         return settings.LOGIN_REDIRECT_URL

#     def save_user(self, request, user, form, commit=True):
#         user = super().save_user(request, user, form, commit=False)
        
#         if not user.username:
#             user.username = self.generate_unique_username(user)
        
#         # Only set password for non-OAuth users
#         if not user.is_verified:
#             if 'password' in form.cleaned_data:
#                 user.set_password(form.cleaned_data['password'])
#             else:
#                 raise ValueError("Password is required for non-OAuth users")
        
#         # Generate verification token for email verification
#         user.verification_token = uuid.uuid4().hex
#         user.verification_token_expires = timezone.now() + timedelta(hours=24)
        
#         if commit:
#             user.save()
#             # Create profile with default values
#             Profile.objects.get_or_create(
#                 user=user,
#                 defaults={
#                     'headline': f"{user.first_name}'s Profile" if user.first_name else "New User Profile",
#                     'show_email': False,
#                     'show_phone': False,
#                     'show_location': True
#                 }
#             )
#         return user

#     def generate_unique_username(self, user):
#         email = user.email if hasattr(user, 'email') else ''
#         return self.generate_unique_username_from_email(email)

#     def generate_unique_username_from_email(self, email):
#         base_username = email.split('@')[0] if email else 'user'
#         username = base_username
#         suffix = 1
#         while User.objects.filter(username=username).exists():
#             username = f"{base_username}_{suffix}"
#             suffix += 1
#         return username



















# /user_account/adapters.py

import logging
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.utils import user_email, user_field, user_username
from allauth.utils import valid_email_or_none
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from .models import Profile, UserRole
import requests
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import uuid
from allauth.core.exceptions import ImmediateHttpResponse
from django.http import JsonResponse
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)
User = get_user_model()

# /user_account/adapters.py

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def populate_user(self, request, sociallogin, data):
        """
        Populate user instance with social account data.  Crucially, set the
        default role here, *before* the user is saved for the first time.
        """
        user = super().populate_user(request, sociallogin, data)
        user.is_verified = True
        user.set_unusable_password()

        # Set the default role.  This is the most important change.
        if not user.role:  # Check if role is already set (it shouldn't be, but it's safer)
            user.role = UserRole.USER.value  # Make *ABSOLUTELY* sure this is the correct value.

        # Handle provider-specific data (as before)
        provider = sociallogin.account.provider
        extra_data = sociallogin.account.extra_data

        if provider == 'google':
            user.first_name = extra_data.get('given_name', '')
            user.last_name = extra_data.get('family_name', '')
            if 'picture' in extra_data:
                user.profile_picture = extra_data['picture']
        # No need to save the user here, allauth's save_user will handle it.
        return user

    def save_user(self, request, sociallogin, form=None):
        """
        Override save_user to ensure role is set.  This acts as a double-check,
        but the primary role-setting should happen in populate_user.
        """
        user = super().save_user(request, sociallogin, form)
        if not user.role:
            user.role = UserRole.USER.value
        return user

    def _get_valid_email(self, sociallogin):
        """Extract and validate email from social login data."""
        email = user_email(sociallogin.user) or sociallogin.account.extra_data.get('email')
        return email.lower().strip() if email else None

    def pre_social_login(self, request, sociallogin):
        """
        Handle social login with comprehensive email conflict resolution.
        """
        try:
            email = self._get_valid_email(sociallogin)
            if not email:
                logger.warning("Social login attempt with no email address")
                return

            existing_user = User.objects.filter(email__iexact=email).first()

            if not existing_user:
                logger.info(f"New social account creation for email: {email}")
                return

            self._handle_existing_user(request, sociallogin, existing_user)

        except Exception as e:
            logger.error(f"Error in pre_social_login: {str(e)}", exc_info=True)
            raise ImmediateHttpResponse(
                JsonResponse({
                    'status': 'error',
                    'code': 'social_login_failed | existing_regular_account',
                    'message': 'An error occurred during social login processing. | This email is registered with a password. Please log in directly.'
                }, status=400)
            )

    def _handle_existing_user(self, request, sociallogin, existing_user):
        """Resolve cases where user with same email exists."""
        provider = sociallogin.account.provider
        existing_social = existing_user.socialaccount_set.filter(provider=provider)

        if existing_social.exists():
            logger.info(f"Connecting to existing {provider} account for {existing_user.email}")
            sociallogin.connect(request, existing_user)
            return

        if existing_user.socialaccount_set.exists():
            logger.warning(f"Email {existing_user.email} exists with different social provider")
            raise ImmediateHttpResponse(
                JsonResponse({
                    'status': 'error',
                    'code': 'different_social_provider',
                    'message': 'This email is associated with a different social provider.'
                }, status=400)
            )

        logger.warning(f"Email {existing_user.email} exists as regular account")
        raise ImmediateHttpResponse(
            JsonResponse({
                'status': 'error',
                'code': 'existing_regular_account',
                'message': 'This email is registered with a password. Please log in directly.',
                'existing_account': True
            }, status=400)
        )


class CustomAccountAdapter(DefaultAccountAdapter):
    def get_login_redirect_url(self, request):
        return settings.LOGIN_REDIRECT_URL

    def save_user(self, request, user, form, commit=True):
        """Save regular user account with verification token and profile."""
        user = super().save_user(request, user, form, commit=False)

        if not user.username:
            user.username = self.generate_unique_username(user)

        if not user.is_verified:
            if 'password' in form.cleaned_data:
                user.set_password(form.cleaned_data['password'])
            else:
                raise ValidationError("Password is required for non-OAuth users")

        # Generate verification token
        user.verification_token = uuid.uuid4().hex
        user.verification_token_expires = timezone.now() + timedelta(hours=24)

        if commit:
            user.save()
            # Auto-create profile for regular users too
            Profile.objects.get_or_create(
                user=user,
                defaults={
                    'headline': f"{user.first_name}'s Profile" if user.first_name else "New User Profile",
                    'show_email': False,
                    'show_phone': False,
                    'show_location': True
                }
            )

        return user

    def generate_unique_username(self, user):
        """Generate unique username from email."""
        email = user.email if hasattr(user, 'email') else ''
        return self.generate_unique_username_from_email(email)

    def generate_unique_username_from_email(self, email):
        """Generate unique username from email address."""
        base_username = email.split('@')[0] if email else 'user'
        username = base_username
        suffix = 1

        while User.objects.filter(username__iexact=username).exists():
            username = f"{base_username}_{suffix}"
            suffix += 1

        return username