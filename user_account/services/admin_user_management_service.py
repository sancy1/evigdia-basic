
# # user_account/services/admin_usermanagement_service.py

# import logging
# from django.contrib.auth import get_user_model
# from django.db import IntegrityError
# from ..exceptions.custom_exceptions import UserNotFoundError, UpdateOperationError 

# logger = logging.getLogger(__name__)
# User = get_user_model()

# class AdminUserManagementService:
#     @staticmethod
#     def update_user_role(user_id, role):
#         try:
#             user = User.objects.get(id=user_id)
#             if role == 'admin':
#                 user.is_staff = True
#                 user.is_superuser = True
#             elif role == 'staff':
#                 user.is_staff = True
#                 user.is_superuser = False
#             elif role == 'user':
#                 user.is_staff = False
#                 user.is_superuser = False
#             else:
#                 raise ValueError(f"Invalid role: {role}")
#             user.save()
#             return user
#         except User.DoesNotExist:
#             raise UserNotFoundError(f"User with ID {user_id} not found.")
#         except IntegrityError as e:
#             logger.error(f"Error updating role for user {user_id}: {str(e)}")
#             raise UpdateOperationError(f"Could not update role for user {user_id} due to database error.")
#         except Exception as e:
#             logger.error(f"Unexpected error updating role for user {user_id}: {str(e)}")
#             raise UpdateOperationError("Failed to update user role.")

#     @staticmethod
#     def get_user_by_id(user_id):
#         try:
#             return User.objects.get(id=user_id)
#         except User.DoesNotExist:
#             raise UserNotFoundError(f"User with ID {user_id} not found.") # Raised as exception
#         except Exception as e:
#             logger.error(f"Error fetching user with ID {user_id}: {str(e)}")
#             raise

#     @staticmethod
#     def get_all_users():
#         try:
#             return User.objects.all()
#         except Exception as e:
#             logger.error(f"Error fetching all users: {str(e)}")
#             raise






















# user_account/services/admin_user_management_service.py

import logging
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from ..exceptions.custom_exceptions import UserNotFoundError, UpdateOperationError
from ..models import UserRole  # Assuming UserRole is defined in your models
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)
User = get_user_model()

class AdminUserManagementService:
    """
    Service for admin user role and permission management.
    Handles both regular and social auth users.
    """
    
    @staticmethod
    def update_user_role(user_id, role_data):
        """
        Update user role and permissions (admin-only).
        
        Args:
            user_id: ID of user to update
            role_data: Dict containing:
                - role: string role value
                - is_staff: boolean
                - is_superuser: boolean
                
        Returns:
            Updated user instance
            
        Raises:
            UserNotFoundError: If user doesn't exist
            UpdateOperationError: If update fails
            ValueError: If invalid role provided
        """
        try:
            # Get user with existence check
            user = User.objects.get(id=user_id)
            
            # Validate and update role if provided
            if 'role' in role_data:
                if not AdminUserManagementService._is_valid_role(role_data['role']):
                    raise ValueError(f"Invalid role: {role_data['role']}")
                user.role = role_data['role']
            
            # Update staff status if provided
            if 'is_staff' in role_data:
                user.is_staff = bool(role_data['is_staff'])
            
            # Update superuser status if provided
            if 'is_superuser' in role_data:
                user.is_superuser = bool(role_data['is_superuser'])
            
            # Save changes
            user.save(update_fields=['role', 'is_staff', 'is_superuser'])
            logger.info(f"Updated role/permissions for user {user_id}: {role_data}")
            
            return user
            
        except User.DoesNotExist as e:
            logger.error(f"User not found: {user_id}")
            raise UserNotFoundError(f"User with ID {user_id} not found")
        except IntegrityError as e:
            logger.error(f"Database error updating user {user_id}: {str(e)}")
            raise UpdateOperationError("Database error during role update")
        except ValidationError as e:
            logger.error(f"Validation error updating user {user_id}: {str(e)}")
            raise UpdateOperationError(f"Invalid data: {str(e)}")
        except ValueError as e:
            logger.error(f"Invalid role value for user {user_id}: {str(e)}")
            raise UpdateOperationError(str(e))
        except Exception as e:
            logger.error(f"Unexpected error updating user {user_id}: {str(e)}")
            raise UpdateOperationError("Failed to update user role")

    @staticmethod
    def _is_valid_role(role):
        """Check if role is valid without using choices"""
        return role in [role.value for role in UserRole]  # Or your existing role validation

    @staticmethod
    def get_user_by_id(user_id):
        """
        Get user by ID with proper error handling
        
        Args:
            user_id: User ID to retrieve
            
        Returns:
            User instance
            
        Raises:
            UserNotFoundError: If user doesn't exist
            UpdateOperationError: On other errors
        """
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        except Exception as e:
            logger.error(f"Error fetching user {user_id}: {str(e)}")
            raise UpdateOperationError("Failed to retrieve user")

    @staticmethod
    def get_all_users():
        """
        Get all users with proper error handling
        
        Returns:
            QuerySet of all users
            
        Raises:
            UpdateOperationError: On query failure
        """
        try:
            return User.objects.all().order_by('-date_joined')
        except Exception as e:
            logger.error(f"Error fetching all users: {str(e)}")
            raise UpdateOperationError("Failed to retrieve users")