
# user_account/services/user_services.py

import logging
from django.contrib.auth import get_user_model
from ..services.email_service import EmailService
from ..models import Profile
from datetime import timedelta
from django.utils import timezone
from ..models import CustomUser, UserRole
import uuid
from .reset_password_service import ResetPasswordService
from ..validators.password_reset_validators import PasswordResetValidator
from ..exceptions.custom_exceptions import RegistrationError
from django.db import IntegrityError


logger = logging.getLogger(__name__)
User = get_user_model()


# Register User ----------------------------------------------------------------------------------
class UserService:
    @staticmethod
    def register_user(username, email, password, role=UserRole.USER.value, is_staff=False, is_superuser=False):
        if not username.strip():
            raise RegistrationError("Username cannot be empty.")
        if not email.strip():
            raise RegistrationError("Email cannot be empty.")
        if not password:
            raise RegistrationError("Password cannot be empty.")

        if User.objects.filter(email__iexact=email).exists():
            raise RegistrationError("A user with this email address already exists.")
        if User.objects.filter(username__iexact=username).exists():
            raise RegistrationError("A user with this username already exists.")

        try:
            # Create the user with is_staff and is_superuser flags
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role=role,
                is_staff=is_staff,
                is_superuser=is_superuser,
                is_verified=False,
                verification_token=uuid.uuid4().hex,
                verification_token_expires=timezone.now() + timedelta(hours=24)
            )

            # Create or get profile
            profile, created = Profile.objects.get_or_create(user=user)
            if created:
                logger.info(f"Profile created for new user: {user.email}")
                # Optionally set default profile values here
                profile.headline = f"{user.first_name}'s Profile" if user.first_name else "New User Profile"
                profile.show_email = False
                profile.show_phone = False
                profile.show_location = True
                profile.save()

            # Send verification email
            if not EmailService.send_verification_email(user):
                logger.error("Failed to send verification email")

            return user

        except IntegrityError as e:
            raise RegistrationError(f"Database error during user creation: {e}")
        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            raise RegistrationError(f"An unexpected error occurred during registration: {e}")

    @staticmethod
    def verify_email(token):
        """Verifies the user's email using the verification token."""
        try:
            user = User.objects.get(verification_token=token, verification_token_expires__gt=timezone.now())
            if not user.is_verified:
                user.is_verified = True
                user.verification_token = None
                user.verification_token_expires = None
                user.save()
            return user
        except User.DoesNotExist:
            raise ValueError("Invalid or expired verification token.")
        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            raise ValueError("An error occurred during email verification.")

# class UserService:
#     @staticmethod
#     def register_user(username, email, password, role=None):
#         if role == '':
#             role = None
#         try:
#             # Check if user already exists
#             if User.objects.filter(email=email).exists():
#                 raise ValueError("A user with this email already exists")

#             if User.objects.filter(username=username).exists():
#                 raise ValueError("A user with this username already exists")

#             # Create the user
#             user = User.objects.create_user(
#                 username=username,
#                 email=email,
#                 password=password,
#                 role=role,
#                 is_verified=False,
#                 verification_token=uuid.uuid4().hex,
#                 verification_token_expires=timezone.now() + timedelta(hours=24)
#             )

#             # Create or get profile
#             profile, created = Profile.objects.get_or_create(user=user)
#             if created:
#                 logger.info(f"Profile created for new user: {user.email}")
#                 # Optionally set default profile values here, similar to your adapter
#                 profile.headline = f"{user.first_name}'s Profile" if user.first_name else "New User Profile"
#                 profile.show_email = False
#                 profile.show_phone = False
#                 profile.show_location = True
#                 profile.save()

#             # Send verification email
#             if not EmailService.send_verification_email(user):
#                 logger.error("Failed to send verification email")

#             return user

#         except Exception as e:
#             logger.error(f"Error registering user: {str(e)}")
#             raise


    
    # Verify ZEmail --------------------------------------------------------------------------------
    @staticmethod
    def verify_email(token):
        try:
            user = User.objects.get(
                verification_token=token,
                verification_token_expires__gt=timezone.now()
            )
            
            user.is_verified = True
            user.verification_token = None
            user.verification_token_expires = None
            user.save()
            
            return user
            
        except User.DoesNotExist:
            raise ValueError("Invalid or expired verification token")
        except Exception as e:
            logger.error(f"Error verifying email: {str(e)}")
            raise
        
        
        
    # Reset Password ---------------------------------------------------------------------------------
    @staticmethod
    def request_password_reset(email):
        try:
            user = CustomUser.objects.get(email=email)

            # Generate reset token and set expiry (1 hour from now)
            user.reset_password_token = uuid.uuid4().hex
            user.reset_password_expires = timezone.now() + timedelta(hours=1)
            user.save()

            # Send email
            if not ResetPasswordService.send_password_reset_email(user):
                logger.error("Failed to send password reset email")
                return False

            return True

        except CustomUser.DoesNotExist:
            logger.info(f"Password reset requested for non-existent email: {email}")
            raise
        except Exception as e:
            logger.error(f"Error requesting password reset: {str(e)}")
            raise
        

    @staticmethod
    def validate_reset_token(token, user_id):
        try:
            from ..models import CustomUser
            user = CustomUser.objects.get(
                id=user_id,
                reset_password_token=token,
                reset_password_expires__gt=timezone.now()
            )
            return user
        except CustomUser.DoesNotExist:
            return None

    @staticmethod
    def reset_password(user, new_password):
        try:
            # Validate the new password against user's history
            # PasswordResetValidator.validate_password_not_used_before(user, new_password)
            
            # # Save current password to history before changing it
            # from ..models import PasswordHistory
            # PasswordHistory.objects.create(
            #     user=user,
            #     password=user.password
            # )
            
            # Update password and clear reset token
            user.set_password(new_password)
            user.reset_password_token = None
            user.reset_password_expires = None
            user.save()
            
            return True
            
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            raise
        


    # Resend Verification Email --------------------------------------------------------------------------------
    @staticmethod
    def resend_verification_email(email):
        try:
            user = User.objects.get(email=email, is_verified=False)
            # Optionally regenerate the verification token and expiry
            user.verification_token = uuid.uuid4().hex
            user.verification_token_expires = timezone.now() + timedelta(hours=24)
            user.save()

            if EmailService.send_verification_email(user):
                return user
            else:
                logger.error(f"Failed to resend verification email to {email}")
                return None
        except User.DoesNotExist:
            logger.info(f"Resend verification requested for non-existent or already verified email: {email}")
            return None
        except Exception as e:
            logger.error(f"Error resending verification email: {str(e)}")
            raise