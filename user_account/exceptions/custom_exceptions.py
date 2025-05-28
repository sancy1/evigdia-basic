
from rest_framework.exceptions import APIException
from rest_framework import status


# Profile -----------------------------------------------------------------------------------------

class ProfileAccessError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You don't have permission to access this profile"
    default_code = "profile_access_denied"

    def __init__(self, detail="You do not have the necessary permissions to access this profile. Please ensure you are logged in with the correct account and have the required roles.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)

class ProfileRetrieveError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "Profile data could not be found"
    default_code = "profile_not_found"

    def __init__(self, detail="The requested profile could not be found in our records. Please verify the identifier and try again.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)

class ProfileUpdateError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Invalid profile update request"
    default_code = "invalid_profile_update"

    def __init__(self, detail="The data provided for updating the profile is invalid. Please check the format and values of the fields you are trying to update.", field_errors=None, **kwargs):
        super().__init__(detail=detail)
        self.field_errors = field_errors or {}
        for key, value in kwargs.items():
            setattr(self, key, value)

class ProfileValidationError(APIException):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_detail = "Profile data validation failed"
    default_code = "profile_validation_failed"

    def __init__(self, detail="The profile data you submitted failed one or more validation checks. Please review the specific errors for each field.", errors=None, **kwargs):
        super().__init__(detail=detail)
        self.errors = errors or {}
        for key, value in kwargs.items():
            setattr(self, key, value)

class ProfileDeletionError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Profile cannot be deleted due to existing constraints"
    default_code = "profile_deletion_constraint"

    def __init__(self, detail="This profile cannot be deleted because it has dependencies on other parts of the system. Please resolve these dependencies first.", constraints=None, **kwargs):
        super().__init__(detail=detail)
        self.constraints = constraints or []
        for key, value in kwargs.items():
            setattr(self, key, value)

class ProfileServiceError(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Profile service temporarily unavailable"
    default_code = "profile_service_unavailable"

    def __init__(self, detail="The profile service is currently experiencing technical difficulties. Please try again later.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)

class AuthenticationError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Authentication credentials were invalid or expired"
    default_code = "authentication_failed"

    def __init__(self, detail="The authentication credentials you provided are incorrect or have expired. Please verify your username/email and password and try again.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)

class InvalidTokenError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "The provided token is invalid or expired"
    default_code = "invalid_token"

    def __init__(self, detail="The security token you provided is either invalid, malformed, or has expired. Please request a new token if necessary.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)


# User Signup -----------------------------------------------------------------------------------------

class RegistrationError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "User registration failed"
    default_code = "registration_failed"

    def __init__(self, detail="User registration could not be completed due to invalid input. Please review the error messages for each field.", field_errors=None, **kwargs):
        super().__init__(detail=detail)
        self.field_errors = field_errors or {}
        for key, value in kwargs.items():
            setattr(self, key, value)

class EmailVerificationError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Email verification failed"
    default_code = "email_verification_failed"

    def __init__(self, detail="The email verification process failed. The link may be invalid, expired, or already used. Please request a new verification link if needed.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)


# User Login -----------------------------------------------------------------------------------------

class LoginError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Invalid login credentials'
    default_code = 'authentication_failed'

    def __init__(self, detail="The login attempt failed because the provided username/email or password was incorrect. Please verify your credentials and try again.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)


# User Logout -----------------------------------------------------------------------------------------

class LogoutError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Logout failed'
    default_code = 'logout_failed'

    def __init__(self, detail="The logout process could not be completed. Please try again or contact support if the issue persists.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)


# User Logout -----------------------------------------------------------------------------------------

class PasswordResetError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Password reset failed"
    default_code = "password_reset_failed"

    def __init__(self, detail="The password reset process failed. This could be due to an invalid or expired reset link, or an issue with updating your password. Please ensure you are using a valid link and try again.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)
            

# Change Password --------------------------------------------------------------------------------------

class ChangePasswordError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Password change failed'
    default_code = 'password_change_failed'

    def __init__(self, detail="An error occurred while attempting to change your password. Please review the specific details provided below for more information.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)
            

# Deleteions (Admin-Only) --------------------------------------------------------------------------------------            
class UserNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'User not found'
    default_code = 'user_not_found'

    def __init__(self, detail="The requested user could not be found.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)

class DeleteOperationError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'User deletion operation failed'
    default_code = 'user_deletion_failed'

    def __init__(self, detail="An error occurred during the user deletion process.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)
            
            
 # --------------------------------------------------------------------------------------
class UserNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'User not found'
    default_code = 'user_not_found'

    def __init__(self, detail="The requested user could not be found.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)

class UpdateOperationError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Update operation failed'
    default_code = 'update_operation_failed'

    def __init__(self, detail="An error occurred during the update operation.", **kwargs):
        super().__init__(detail=detail)
        for key, value in kwargs.items():
            setattr(self, key, value)           
            
            
            
            
            
            
            


# from rest_framework.exceptions import APIException
# from rest_framework import status


# # Profile -----------------------------------------------------------------------------------------

# class ProfileAccessError(APIException):
#     status_code = status.HTTP_403_FORBIDDEN
#     default_detail = "You don't have permission to access this profile"
#     default_code = "profile_access_denied"

# class ProfileRetrieveError(APIException):
#     status_code = status.HTTP_404_NOT_FOUND
#     default_detail = "Profile data could not be found"
#     default_code = "profile_not_found"

# class ProfileUpdateError(APIException):
#     status_code = status.HTTP_400_BAD_REQUEST
#     default_detail = "Invalid profile update request"
#     default_code = "invalid_profile_update"
    
#     def __init__(self, detail=None, field_errors=None):
#         super().__init__(detail=detail)
#         self.field_errors = field_errors or {}

# class ProfileValidationError(APIException):
#     status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
#     default_detail = "Profile data validation failed"
#     default_code = "profile_validation_failed"
    
#     def __init__(self, detail=None, errors=None):
#         super().__init__(detail=detail)
#         self.errors = errors or {}

# class ProfileDeletionError(APIException):
#     status_code = status.HTTP_403_FORBIDDEN
#     default_detail = "Profile cannot be deleted due to existing constraints"
#     default_code = "profile_deletion_constraint"
    
#     def __init__(self, detail=None, constraints=None):
#         super().__init__(detail=detail)
#         self.constraints = constraints or []

# class ProfileServiceError(APIException):
#     status_code = status.HTTP_503_SERVICE_UNAVAILABLE
#     default_detail = "Profile service temporarily unavailable"
#     default_code = "profile_service_unavailable"

# class AuthenticationError(APIException):
#     status_code = status.HTTP_401_UNAUTHORIZED
#     default_detail = "Authentication credentials were invalid or expired"
#     default_code = "authentication_failed"

# class InvalidTokenError(APIException):
#     status_code = status.HTTP_401_UNAUTHORIZED
#     default_detail = "The provided token is invalid or expired"
#     default_code = "invalid_token"
    
    
    
# # User Signup -----------------------------------------------------------------------------------------

# class RegistrationError(APIException):
#     status_code = status.HTTP_400_BAD_REQUEST
#     default_detail = "User registration failed"
#     default_code = "registration_failed"
    
#     def __init__(self, detail=None, field_errors=None):
#         super().__init__(detail=detail)
#         self.field_errors = field_errors or {}

# class EmailVerificationError(APIException):
#     status_code = status.HTTP_400_BAD_REQUEST
#     default_detail = "Email verification failed"
#     default_code = "email_verification_failed"
    
#     def __init__(self, detail=None):
#         super().__init__(detail=detail)



# # User Login -----------------------------------------------------------------------------------------

# class LoginError(APIException):
#     status_code = status.HTTP_401_UNAUTHORIZED
#     default_detail = 'Invalid login credentials'
#     default_code = 'authentication_failed'


# # User Logout -----------------------------------------------------------------------------------------

# class LogoutError(APIException):
#     status_code = status.HTTP_400_BAD_REQUEST
#     default_detail = 'Logout failed'
#     default_code = 'logout_failed'


# # User Logout -----------------------------------------------------------------------------------------

# class PasswordResetError(APIException):
#     status_code = status.HTTP_400_BAD_REQUEST
#     default_detail = "Password reset failed"
#     default_code = "password_reset_failed"
    

    
#     def __init__(self, detail=None):
#         super().__init__(detail=detail)