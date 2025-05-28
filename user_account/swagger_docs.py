
# views/swagger.py
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status

from .serializers import (
    ChangePasswordSerializer,
    UpdateUserRoleSerializer,
    UserDetailSerializer,
    ResendVerificationEmailSerializer,
    PasswordResetTokenValidationSerializer,
    PasswordResetSerializer,
    PasswordResetRequestSerializer,
    ChangePasswordSerializer,
    UserLoginSerializer,
    ProfileSerializer,
    UserRegistrationSerializer,
    )



# Resend Verification Email ---------------------------------------------------------------------------
def resend_verification_email_schema():
    """
    Swagger documentation for ResendVerificationEmailView
    """
    return swagger_auto_schema(
        operation_description="Resend verification email to the specified email address",
        request_body=ResendVerificationEmailSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Verification email resent successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Verification email has been resent'
                        ),
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'email': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["Enter a valid email address."]
                        ),
                    }
                )
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Not Found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='No user found with this email address'
                        ),
                    }
                )
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: openapi.Response(
                description="Too Many Requests",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Please wait before requesting another email'
                        ),
                        'retry_after': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            example=60
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Internal Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to send verification email'
                        ),
                        'code': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='email_send_failed'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        examples={
            'application/json': {
                'Valid Request': {
                    'email': 'user@example.com'
                },
                'Invalid Email': {
                    'email': 'invalid-email'
                }
            }
        }
    )
        
    

# Password Reset Toekn Validation ---------------------------------------------------------------------------
@staticmethod
def password_reset_token_validation():
        """Documentation for PasswordResetTokenValidationView"""
        return swagger_auto_schema(
            operation_description="Validate password reset token",
            request_body=PasswordResetTokenValidationSerializer,
            responses={
                status.HTTP_200_OK: openapi.Response(
                    description="Token validation successful",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='successful'
                            ),
                            'message': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Reset verification successful'
                            ),
                            'token': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                            ),
                            'userId': openapi.Schema(
                                type=openapi.TYPE_STRING, 
                                format=openapi.FORMAT_UUID,
                                example='550e8400-e29b-41d4-a716-446655440000'
                            ),
                        }
                    )
                ),
                status.HTTP_400_BAD_REQUEST: openapi.Response(
                    description="Invalid token",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'detail': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Invalid or expired reset token.'
                            ),
                            'code': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='invalid_reset_token'
                            ),
                        }
                    )
                ),
                status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                    description="Server error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'detail': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Failed to process password reset request.'
                            ),
                            'code': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='password_reset_failed'
                            ),
                        }
                    )
                )
            },
            tags=['Authentication'],
            examples={
                'application/json': {
                    'Valid Request': {
                        'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                        'userId': '550e8400-e29b-41d4-a716-446655440000'
                    },
                    'Invalid Token': {
                        'token': 'expired_or_invalid_token',
                        'userId': '550e8400-e29b-41d4-a716-446655440000'
                    }
                }
            }
        )
      
    

# Password Reset View ---------------------------------------------------------------------------
def password_reset_docs():
    """Swagger documentation for PasswordResetView"""
    return swagger_auto_schema(
        operation_description="Reset user password using valid reset token",
        request_body=PasswordResetSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Password reset successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN,
                            example=True
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Password reset successfully. You may login with your new password'
                        ),
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid token or validation error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Invalid or expired token'
                        ),
                        'code': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='invalid_reset_token'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Password reset failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to reset password'
                        ),
                        'code': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='password_reset_failed'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        examples={
            'application/json': {
                'Valid Request': {
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    'userId': '550e8400-e29b-41d4-a716-446655440000',
                    'newPassword': 'NewSecurePassword123!'
                },
                'Invalid Request': {
                    'token': 'expired_token',
                    'userId': '550e8400-e29b-41d4-a716-446655440000',
                    'newPassword': 'weak'
                }
            }
        }
    )
      
    

# Password Reset Request ---------------------------------------------------------------------------
def password_reset_request_docs():
    """Swagger documentation for PasswordResetRequestView"""
    return swagger_auto_schema(
        operation_description="Request password reset email",
        request_body=PasswordResetRequestSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Password reset email sent (always returns 200 for security)",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Password reset link has been sent to your email.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Server error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An unexpected error occurred during the password reset request.'
                        ),
                        'code': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='password_reset_request_failed'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        examples={
            'application/json': {
                'Valid Request': {
                    'email': 'user@example.com'
                },
                'Invalid Format': {
                    'email': 'not-an-email'
                }
            }
        }
    )
      
    

# Change Password ---------------------------------------------------------------------------
def change_password_docs():
    """Swagger documentation for ChangePasswordView"""
    return swagger_auto_schema(
        operation_description="Change authenticated user's password\n\n"
                            "Requires current password and new password with confirmation. "
                            "New password must meet security requirements.",
        request_body=ChangePasswordSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Password changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN,
                            example=True
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Password changed successfully'
                        ),
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid request data",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'currentPassword': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["Current password is incorrect"]
                        ),
                        'newPassword': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["This password is too common", 
                                   "Passwords don't match"]
                        ),
                        'non_field_errors': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["New password cannot be same as current password"]
                        )
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Authentication required",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Internal server error during password change",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to change password'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        security=[{'Bearer': []}],
        examples={
            'Valid Request': {
                'summary': 'Successful password change',
                'value': {
                    'currentPassword': 'OldSecurePassword123!',
                    'newPassword': 'NewSecurePassword456!',
                    'confirmNewPassword': 'NewSecurePassword456!'
                }
            },
            'Mismatched Passwords': {
                'summary': 'New passwords do not match',
                'value': {
                    'currentPassword': 'OldSecurePassword123!',
                    'newPassword': 'NewSecurePassword456!',
                    'confirmNewPassword': 'DifferentPassword789!'
                }
            },
            'Weak Password': {
                'summary': 'Password too simple',
                'value': {
                    'currentPassword': 'OldSecurePassword123!',
                    'newPassword': '12345',
                    'confirmNewPassword': '12345'
                }
            }
        }
    )
      
    

# DELETE USER ACCOUNT ---------------------------------------------------------------------------
def delete_account_docs():
    """Swagger documentation for DeleteAccountView"""
    return swagger_auto_schema(
        operation_description="Permanently delete authenticated user's account and all associated data",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Account deleted successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Account and all associated data deleted successfully'
                        ),
                        'deletion_report': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            description='Detailed report of data deletion',
                            example={
                                'user_data': True,
                                'posts': 15,
                                'comments': 42,
                                'files': 8
                            }
                        ),
                        'metadata': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'timestamp': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    format=openapi.FORMAT_DATETIME,
                                    example='2023-07-20T14:30:45Z'
                                ),
                                'deletion_complete': openapi.Schema(
                                    type=openapi.TYPE_BOOLEAN,
                                    example=True
                                )
                            }
                        )
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Deletion failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to complete account deletion'
                        ),
                    }
                )
            )
        },
        tags=['Account Management'],
        security=[{'Bearer': []}],
        operation_summary="Permanent account deletion",
        operation_notes="""**WARNING:** This action is irreversible and will permanently delete:
        - User profile
        - All associated content
        - Related data across all services

        The system will also clear authentication cookies automatically."""
    )
      
    

# DELETE USER ACCOUNT ---------------------------------------------------------------------------
def delete_all_users_except_admin_docs():
    """Swagger documentation for DeleteAllUsersExceptAdminView (Admin Only)"""
    return swagger_auto_schema(
        operation_description="[ADMIN ONLY] Permanently delete all non-admin user accounts",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Users deleted successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='42 user(s) (excluding admins) deleted successfully.'
                        ),
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden (Admin Only)",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You do not have permission to perform this action.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Deletion failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to delete users: Database constraint violation'
                        ),
                    }
                )
            )
        },
        tags=['Admin Operations'],
        security=[{'Bearer': []}],
        operation_summary="Mass user deletion (Admin Only)",
        operation_notes="""**DANGER - ADMIN ONLY OPERATION**

This will permanently delete ALL non-admin user accounts and their associated data. 

⚠️ **Critical Warnings:**
- This action is **irreversible**
- Will affect **all regular users** in the system
- May cause significant data loss
- Should only be used during system maintenance

Returns count of successfully deleted users."""
    )
      
    

# DELETE SINGLE USER ACCOUNT ---------------------------------------------------------------------------
def delete_single_user_docs():
    """Swagger documentation for DeleteSingleUserView (Admin Only)"""
    return swagger_auto_schema(
        operation_description="[ADMIN ONLY] Permanently delete a specific user account by ID",
        manual_parameters=[
            openapi.Parameter(
                name='userId',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_UUID,
                description="Target user's UUID",
                example="550e8400-e29b-41d4-a716-446655440000"
            )
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="User deleted successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='User with ID 550e8400-e29b-41d4-a716-446655440000 and associated data deleted successfully.'
                        ),
                        'deletion_report': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            description='Detailed breakdown of deleted data',
                            example={
                                'user_data': True,
                                'posts': 15,
                                'comments': 7,
                                'media_files': 3,
                                'related_entities': 2
                            }
                        )
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden (Admin Only)",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You do not have permission to perform this action.'
                        ),
                    }
                )
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="User Not Found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='User with ID 550e8400-e29b-41d4-a716-446655440000 not found.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Deletion failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Database constraint violation during deletion'
                        ),
                    }
                )
            )
        },
        tags=['Admin Operations'],
        security=[{'Bearer': []}],
        operation_summary="Single user deletion (Admin Only)",
        operation_notes="""**ADMIN-ONLY DESTRUCTIVE OPERATION**

Permanently deletes a specific user account and all associated data.

⚠️ **Critical Considerations:**
- **Irreversible** action
- Cascades to all related data (posts, comments, files)
- Cannot be applied to admin accounts
- Returns detailed deletion report

🔒 **Protection Against:**
- Self-deletion (admins cannot delete themselves)
- System account deletion
- Concurrent deletion attempts"""
    )
      
    

# DELETE UNVERIFIED USER ACCOUNT ---------------------------------------------------------------------------
def delete_unverified_users_docs():
    """Swagger documentation for DeleteUnverifiedUsersView (Admin Only)"""
    return swagger_auto_schema(
        operation_description="[ADMIN ONLY] Permanently delete all unverified user accounts",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Unverified users deleted successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='42 unverified user(s) deleted successfully.'
                        ),
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden (Admin Only)",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You do not have permission to perform this action.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Deletion failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to delete unverified users: Database constraint violation'
                        ),
                    }
                )
            )
        },
        tags=['Admin Operations'],
        security=[{'Bearer': []}],
        operation_summary="Bulk deletion of unverified users (Admin Only)",
        operation_notes="""**ADMIN-ONLY OPERATION**

Permanently deletes ALL user accounts that haven't completed email verification.

⚠️ **Important Notes:**
- Targets **only** users with `is_verified=False`
- Does not affect admin accounts
- Returns count of deleted accounts
- Automatic cleanup of related data

⏳ **Typical Use Cases:**
- Regular system maintenance
- GDPR compliance cleanup
- Removing stale registrations"""
    )
      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------
def update_user_role_docs():
    """Swagger documentation for UpdateUserRoleView (Admin Only)"""
    return swagger_auto_schema(
        operation_description="[ADMIN ONLY] Update a user's role",
        manual_parameters=[
            openapi.Parameter(
                name='userId',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_UUID,
                description="Target user's UUID",
                example="550e8400-e29b-41d4-a716-446655440000"
            )
        ],
        # Changed to use serializer directly
        request_body=UpdateUserRoleSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Role updated successfully",
                schema=UserDetailSerializer,
                examples={
                    "application/json": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "email": "user@example.com",
                        "role": "moderator",
                        "is_verified": True,
                        "created_at": "2023-07-20T12:00:00Z"
                    }
                }
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Invalid role specified'
                        ),
                        'role': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["Not a valid role choice"]
                        ),
                    }
                )
            ),
            # ... rest of the responses remain exactly the same ...
        },
        tags=['Admin Operations'],
        security=[{'Bearer': []}],
        operation_summary="Update user role (Admin Only)",
        operation_notes="""**ADMIN-ONLY OPERATION**

Updates a user's system role with validation.

🛡️ **Role Management Rules:**
- Cannot demote other admin accounts
- Some roles may require additional setup
- Changes take effect immediately

📋 **Available Roles:**
- `user`: Basic account privileges
- `moderator`: Content moderation rights
- `content_creator`: Special publishing rights
- `analyst`: Data analytics access"""
    )
     
    

# GET SINGLE USER ---------------------------------------------------------------------------
def get_single_user_schema():
    """
    Swagger documentation for GetSingleUserView (Admin Only)
    """
    return swagger_auto_schema(
        operation_description="[ADMIN ONLY] Retrieve detailed information about a specific user",
        manual_parameters=[
            openapi.Parameter(
                name='userId',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_UUID,
                description="Target user's UUID",
                example="550e8400-e29b-41d4-a716-446655440000"
            )
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="User details retrieved successfully",
                schema=UserDetailSerializer,  # Using serializer directly here
                examples={
                    "application/json": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "email": "user@example.com",
                        "role": "user",
                        "is_verified": True,
                        "created_at": "2023-01-15T09:30:00Z",
                        "last_login": "2023-07-20T14:25:00Z"
                    }
                }
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden (Admin Only)",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You do not have permission to perform this action.'
                        ),
                    }
                )
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="User Not Found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='User with ID 550e8400-e29b-41d4-a716-446655440000 not found.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An unexpected error occurred while fetching user data'
                        ),
                    }
                )
            )
        },
        tags=['Admin Operations'],
        security=[{'Bearer': []}],
        operation_summary="Get user details (Admin Only)",
        operation_notes="""**ADMIN-ONLY OPERATION**

Retrieves complete details for a specific user account.

🔒 **Access Rules:**
- Requires admin privileges
- Returns sensitive user information
- Includes all account metadata"""
    )
    


# GET ALL USERS ---------------------------------------------------------------------------
# In views/swagger.py
def get_all_users_schema():
    """
    Swagger documentation for GetAllUsersView (Admin Only)
    """
    return swagger_auto_schema(
        operation_description="[ADMIN ONLY] Retrieve list of all users with detailed information",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="List of users retrieved successfully",
                schema=UserDetailSerializer(many=True),  # Using serializer with many=True
                examples={
                    "application/json": [
                        {
                            "id": "550e8400-e29b-41d4-a716-446655440000",
                            "email": "admin@example.com",
                            "role": "admin",
                            "is_verified": True,
                            "created_at": "2023-01-10T08:00:00Z"
                        },
                        {
                            "id": "110e8400-e29b-41d4-a716-446655440001",
                            "email": "user@example.com",
                            "role": "user",
                            "is_verified": False,
                            "created_at": "2023-07-15T14:30:00Z"
                        }
                    ]
                }
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden (Admin Only)",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You do not have permission to perform this action.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An unexpected error occurred while fetching users'
                        ),
                    }
                )
            )
        },
        tags=['Admin Operations'],
        security=[{'Bearer': []}],
        operation_summary="Get all users (Admin Only)",
        operation_notes="""**ADMIN-ONLY OPERATION**

Retrieves complete details for all user accounts.

🔒 **Access Rules:**
- Requires admin privileges
- Returns sensitive user information
- Includes pagination details if implemented

📝 **Note:** 
- Returns empty array if no users exist
- System accounts may be filtered out"""
    )
      
    

# GET USER ACCOUNT INFO ---------------------------------------------------------------------------
# In views/swagger.py
def account_info_schema():
    """
    Swagger documentation for AccountInfoView (Authenticated User)
    """
    return swagger_auto_schema(
        operation_description="Retrieve authenticated user's account information",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="User account info retrieved successfully",
                schema=UserDetailSerializer,  # Using serializer directly
                examples={
                    "application/json": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "email": "user@example.com",
                        "role": "user",
                        "is_verified": True,
                        "created_at": "2023-01-15T09:30:00Z",
                        "last_login": "2023-07-20T14:25:00Z",
                        "profile": {
                            "first_name": "John",
                            "last_name": "Doe",
                            "avatar": "https://example.com/avatars/user.jpg"
                        }
                    }
                }
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        ),
                    }
                )
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You do not have permission to perform this action.'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An unexpected error occurred while fetching account info'
                        ),
                    }
                )
            )
        },
        tags=['Account Management'],
        security=[{'Bearer': []}],
        operation_summary="Get authenticated user's account info",
        operation_notes="""**AUTHENTICATED USER OPERATION**

Retrieves complete details for the currently authenticated user.

🔐 **Access Rules:**
- Requires valid authentication token
- Returns only the requesting user's information
- Includes all account metadata and profile details

💡 **Note:** 
- Sensitive fields may be filtered based on user permissions
- Profile information may vary based on account type"""
    )
      
    

# USER LOGIN ---------------------------------------------------------------------------
def user_login_schema():
    """
    Swagger documentation for UserLoginView
    """
    return swagger_auto_schema(
        operation_description="Authenticate user and return access tokens with profile data",
        request_body=UserLoginSerializer,  # Using serializer directly
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'tokens': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'access': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                                ),
                                'refresh': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                                )
                            }
                        ),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
                                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                                'role': openapi.Schema(type=openapi.TYPE_STRING, enum=['user', 'admin', 'moderator']),
                                'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'profile': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                                        'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                                        'avatar': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_URI)
                                    }
                                )
                            }
                        )
                    },
                    example={
                        "tokens": {
                            "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                        },
                        "user": {
                            "id": "550e8400-e29b-41d4-a716-446655440000",
                            "email": "user@example.com",
                            "role": "user",
                            "is_verified": True,
                            "profile": {
                                "first_name": "John",
                                "last_name": "Doe",
                                "avatar": "https://example.com/avatars/user.jpg"
                            }
                        }
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'email': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["Enter a valid email address."]
                        ),
                        'password': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["This field may not be blank."]
                        ),
                        'non_field_errors': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            example=["Unable to log in with provided credentials."]
                        )
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An error occurred during login'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        examples={
            'application/json': {
                'Valid Request': {
                    'email': 'user@example.com',
                    'password': 'SecurePassword123!'
                },
                'Invalid Request': {
                    'email': 'invalid-email',
                    'password': ''
                }
            }
        },
        operation_summary="User login",
        operation_notes="""**PUBLIC ENDPOINT**

Authenticates user credentials and returns access tokens with profile data.

🔐 **Response Includes:**
- Access and refresh tokens
- Complete user profile information
- Account verification status

⚠️ **Security Notes:**
- Rate limited to prevent brute force attacks
- Invalid attempts are logged
- Tokens are HttpOnly and Secure"""
    )
      
    

# PROFILE---------------------------------------------------------------------------
def get_profile_schema():
    """Returns the complete profile schema configuration"""
    return {
        'retrieve': {
            'operation_description': "Retrieve authenticated user's profile",
            'responses': {
                status.HTTP_200_OK: openapi.Response(
                    description="Profile retrieved successfully",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='success'),
                            'data': openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'profile': ProfileSerializer,
                                    'meta': openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'is_complete': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                            'last_updated': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME)
                                        }
                                    )
                                }
                            )
                        }
                    )
                ),
                status.HTTP_401_UNAUTHORIZED: openapi.Response(
                    description="Unauthorized",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'detail': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Authentication credentials were not provided.'
                            )
                        }
                    )
                ),
                status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                    description="Server Error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='error'),
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example='unexpected_profile_access_error'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='An unexpected error occurred while accessing the profile.')
                        }
                    )
                )
            },
            'tags': ['Profile'],
            'security': [{'Bearer': []}]
        },
        'update': {
            'operation_description': "Update authenticated user's profile",
            'request_body': ProfileSerializer,
            'responses': {
                status.HTTP_200_OK: openapi.Response(
                    description="Profile updated successfully",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='success'),
                            'data': ProfileSerializer
                        }
                    )
                ),
                status.HTTP_400_BAD_REQUEST: openapi.Response(
                    description="Validation Error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='error'),
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example='profile_validation_error'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='Invalid data provided.'),
                            'errors': openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                additional_properties=openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_STRING)
                                )
                            )
                        }
                    )
                ),
                status.HTTP_401_UNAUTHORIZED: openapi.Response(
                    description="Unauthorized",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'detail': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Authentication credentials were not provided.'
                            )
                        }
                    )
                ),
                status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                    description="Server Error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='error'),
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example='profile_update_error'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='Failed to update profile data.')
                        }
                    )
                )
            },
            'tags': ['Profile'],
            'security': [{'Bearer': []}]
        },
        'partial_update': {
            'operation_description': "Partially update authenticated user's profile",
            'request_body': ProfileSerializer,
            'responses': {
                status.HTTP_200_OK: openapi.Response(
                    description="Profile partially updated successfully",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='success'),
                            'data': ProfileSerializer
                        }
                    )
                ),
                status.HTTP_400_BAD_REQUEST: openapi.Response(
                    description="Validation Error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='error'),
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example='profile_validation_error'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='Invalid data provided.'),
                            'errors': openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                additional_properties=openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_STRING)
                                )
                            )
                        }
                    )
                ),
                status.HTTP_401_UNAUTHORIZED: openapi.Response(
                    description="Unauthorized",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'detail': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Authentication credentials were not provided.'
                            )
                        }
                    )
                ),
                status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                    description="Server Error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='error'),
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example='profile_update_error'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='Failed to update profile data.')
                        }
                    )
                )
            },
            'tags': ['Profile'],
            'security': [{'Bearer': []}]
        },
        'destroy': {
            'operation_description': "Delete authenticated user's profile",
            'responses': {
                status.HTTP_204_NO_CONTENT: openapi.Response(
                    description="Profile deleted successfully",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='success'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='Profile deleted successfully.')
                        }
                    )
                ),
                status.HTTP_401_UNAUTHORIZED: openapi.Response(
                    description="Unauthorized",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'detail': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example='Authentication credentials were not provided.'
                            )
                        }
                    )
                ),
                status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                    description="Server Error",
                    schema=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'status': openapi.Schema(type=openapi.TYPE_STRING, example='error'),
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example='profile_deletion_error'),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example='Failed to delete profile.')
                        }
                    )
                )
            },
            'tags': ['Profile'],
            'security': [{'Bearer': []}]
        }
    }
      


# VERIFY EMAIL ---------------------------------------------------------------------------
def verify_email_schema():
    """
    Swagger documentation for VerifyEmailView
    """
    return swagger_auto_schema(
        operation_description="Verify user's email address using the verification token",
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                required=True,
                description='Email verification token that was sent to the user',
                example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            )
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Email verified successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Email verified successfully'
                        ),
                        'debug': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'user_id': openapi.Schema(
                                    type=openapi.TYPE_INTEGER,
                                    example=1
                                ),
                                'tokens': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'access': openapi.Schema(
                                            type=openapi.TYPE_STRING,
                                            example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                                        ),
                                        'refresh': openapi.Schema(
                                            type=openapi.TYPE_STRING,
                                            example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                                        )
                                    }
                                )
                            }
                        )
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='error'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Verification token is required'
                        ),
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Invalid or expired verification token'
                        ),
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Internal Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An error occurred during email verification'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        examples={
            'application/json': {
                'Valid Request': {
                    'description': 'Include token as query parameter',
                    'value': {}
                },
                'Missing Token': {
                    'description': 'Request without token parameter',
                    'value': {}
                }
            }
        }
    )

      
    

# USER REGISTRATION ---------------------------------------------------------------------------
def register_schema():
    """
    Swagger documentation for RegisterView
    """
    return swagger_auto_schema(
        operation_description="Register a new user account",
        request_body=UserRegistrationSerializer,
        responses={
            status.HTTP_201_CREATED: openapi.Response(
                description="User registered successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='success'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='User registered successfully. Please check your email for verification.'
                        ),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                'email': openapi.Schema(type=openapi.TYPE_STRING, example='user@example.com'),
                                # Add other UserSerializer fields here
                            }
                        ),
                        'debug': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'user_id': openapi.Schema(
                                    type=openapi.TYPE_INTEGER,
                                    example=1
                                ),
                                'email': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    example='user@example.com'
                                )
                            }
                        )
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='error'
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Validation error'
                        ),
                        'field_errors': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'email': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_STRING),
                                    example=["This field is required."]
                                ),
                                'password': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_STRING),
                                    example=["This password is too common."]
                                )
                            }
                        )
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Internal Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Failed to complete registration'
                        ),
                    }
                )
            )
        },
        tags=['Authentication'],
        examples={
            'application/json': {
                'Valid Request': {
                    'value': {
                        'email': 'user@example.com',
                        'password': 'SecurePassword123!',
                        'password2': 'SecurePassword123!',
                        # Add other required registration fields
                    }
                },
                'Invalid Request': {
                    'value': {
                        'email': 'invalid-email',
                        'password': '123',
                        'password2': '456'
                    }
                }
            }
        }
    )
      
    

# SOCIAL LOGIN REDIRECT ---------------------------------------------------------------------------
def social_login_redirect_schema():
    """
    Swagger documentation for SocialLoginRedirectView
    """
    return swagger_auto_schema(
        operation_description="Handle social authentication redirect and return user profile",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successfully authenticated via social provider",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Successfully authenticated'
                        ),
                        'profile': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                'user': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                # Add other ProfileSerializer fields here
                            }
                        )
                    }
                )
            ),
            status.HTTP_302_FOUND: openapi.Response(
                description="Redirect to login page when not authenticated",
                headers={
                    'Location': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description='Redirect URL',
                        example='/accounts/login/'
                    )
                }
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Internal Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='An error occurred during the social login redirect.'
                        ),
                    }
                )
            )
        },
        security=[],  # No authentication required for redirect endpoint
        tags=['Authentication'],
        manual_parameters=[
            openapi.Parameter(
                'code',
                openapi.IN_QUERY,
                description='OAuth2 authorization code',
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'state',
                openapi.IN_QUERY,
                description='OAuth2 state parameter',
                type=openapi.TYPE_STRING,
                required=False
            )
        ]
    )

      
    
# Google OAuth --------------------------------------------------------------------------------------
def google_login_schema():
    """
    Swagger documentation for GoogleLogin view
    """
    return swagger_auto_schema(
        operation_id='google_oauth_login',
        operation_description="Authenticate using Google OAuth2. Returns JWT tokens in cookies (access_token and refresh_token).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'code': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Authorization code from Google',
                    example='4/0Adeu5BV...'
                ),
                'state': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='State parameter for CSRF protection',
                    example='random_state_string'
                )
            },
            required=['code', 'state']
        ),
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successfully authenticated with Google",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'pk': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                'email': openapi.Schema(type=openapi.TYPE_STRING, example='user@example.com'),
                                'username': openapi.Schema(type=openapi.TYPE_STRING, example='google_user'),
                                'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True)
                            }
                        ),
                        'access_token': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Only returned in DEBUG mode',
                            example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                        ),
                        'refresh_token': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Only returned in DEBUG mode',
                            example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                        ),
                        'is_verified': openapi.Schema(
                            type=openapi.TYPE_BOOLEAN,
                            example=True
                        )
                    }
                ),
                headers={
                    'Set-Cookie': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description='Contains access_token and refresh_token as HttpOnly cookies',
                        example='access_token=eyJhbGciOi...; HttpOnly; Secure; SameSite=Lax; Max-Age=3600'
                    )
                }
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='invalid_grant'
                        ),
                        'error_description': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Malformed auth code'
                        )
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        )
                    }
                )
            )
        },
        tags=['Authentication'],
        security=[],
        examples={
            'application/json': {
                'Request': {
                    'value': {
                        'code': '4/0Adeu5BV...',
                        'state': 'random_state_string'
                    }
                }
            }
        }
    )     
    

# GOOGLE LOGOUT-VIEW ---------------------------------------------------------------------------
def google_logout_schema():
    return swagger_auto_schema(
        operation_description="Logout user and clear authentication cookies",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successfully logged out",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Successfully logged out'
                        )
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Not authenticated",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        )
                    }
                )
            )
        },
        tags=['Authentication'],
        security=[{'Bearer': []}]
    )
      
    

# LOGOUT VIEW ---------------------------------------------------------------------------
def logout_schema():
    """
    Swagger documentation for LogoutView
    """
    return swagger_auto_schema(
        operation_description="Logout user and invalidate authentication tokens",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successfully logged out",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Successfully logged out'
                        ),
                        'status': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            example=200
                        )
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Invalid token'
                        ),
                        'code': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='token_invalid'
                        )
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Authentication credentials were not provided.'
                        )
                    }
                )
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: openapi.Response(
                description="Internal Server Error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Logout failed due to server error'
                        ),
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Exception details...'
                        )
                    }
                )
            )
        },
        tags=['Authentication'],
        security=[{'Bearer': []}],
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Bearer token',
                example='Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            )
        ]
    )
      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------
      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------
      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------
      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------
      
    

# UPDATE USER ROLE ---------------------------------------------------------------------------
