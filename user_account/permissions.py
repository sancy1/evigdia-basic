
# user_account/permissions.py

from rest_framework import permissions
from django.contrib.auth import get_user_model
# from web_apis.blog.models import BlogPost
from .models import UserRole

import logging
logger = logging.getLogger(__name__)

User = get_user_model()

class IsAuthenticated(permissions.BasePermission):
    """
    Allows access only to authenticated users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

class IsAdmin(permissions.BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)

class IsSuperAdmin(permissions.BasePermission):
    """
    Allows access only to superadmin users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)

class IsOwner(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to access it.
    Assumes the model instance has an `owner` attribute.
    """
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class IsAuthor(permissions.BasePermission):
    """
    Object-level permission to only allow authors of an object to access it.
    Assumes the model instance has an `author` attribute.
    """
    def has_object_permission(self, request, view, obj):
        return obj.author == request.user

class IsAuthorOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow authors of an object to edit it.
    Read permissions are allowed to any request.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.author == request.user

class IsStaffOrReadOnly(permissions.BasePermission):
    """
    Allows read-only access to everyone, but write access only to staff users.
    """
    def has_permission(self, request, view):
        return (
            request.method in permissions.SAFE_METHODS or
            request.user and
            request.user.is_staff
        )

class IsAdminOrAuthor(permissions.BasePermission):
    """
    Allows access only to admin users or the author of the object.
    """
    def has_object_permission(self, request, view, obj):
        return bool(
            request.user and 
            (request.user.is_staff or obj.author == request.user)
        )

class IsAdminOrAuthorOrReadOnly(permissions.BasePermission):
    """
    Allows read access to everyone, but write access only to admin or author.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(
            request.user and 
            (request.user.is_staff or obj.author == request.user)
        )

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Allows access only to owners of an object or admin users.
    """
    def has_object_permission(self, request, view, obj):
        return bool(
            request.user and 
            (request.user.is_staff or obj.owner == request.user)
        )

class IsPublicOrOwner(permissions.BasePermission):
    """
    Allows access to public objects or to owners if the object is not public.
    """
    def has_object_permission(self, request, view, obj):
        if obj.is_public:
            return True
        return obj.owner == request.user

class HasAPIKeyOrIsAuthenticated(permissions.BasePermission):
    """
    Allows access either via API key or authenticated session.
    """
    def has_permission(self, request, view):
        api_key = request.META.get('HTTP_X_API_KEY')
        if api_key:
            # Validate API key logic here
            return self.validate_api_key(api_key)
        return request.user and request.user.is_authenticated
    
    def validate_api_key(self, key):
        # Implement your API key validation logic
        try:
            return User.objects.get(api_key=key).exists()
        except User.DoesNotExist:
            return False

class IsPostAuthorOrAdmin(permissions.BasePermission):
    """
    Special permission for blog posts that checks both direct authorship
    and staff status, with different rules for different methods.
    """
    def has_permission(self, request, view):
        # Allow all authenticated users to list/create
        if request.method in ['GET', 'POST']:
            return request.user and request.user.is_authenticated
        return True
    
    # def has_object_permission(self, request, view, obj):
    #     # Allow read access to published posts for everyone
    #     if request.method in permissions.SAFE_METHODS:
    #         if obj.status == BlogPost.PostStatus.PUBLISHED:
    #             return True
    #         # For non-published posts, only author/admin can view
    #         return obj.author == request.user or request.user.is_staff
        
    #     # Write permissions require author or admin
    #     return obj.author == request.user or request.user.is_staff

class IsCommentAuthorOrPostAuthorOrAdmin(permissions.BasePermission):
    """
    Special permission for comments:
    - Comment author can edit/delete their own comments
    - Post author can moderate comments on their posts
    - Admins can do anything
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Comment author can edit/delete their own comments
        if obj.user == request.user:
            return True
        
        # Post author can moderate comments on their posts
        if hasattr(obj, 'post') and obj.post.author == request.user:
            return True
        
        return False

class IsSubscriptionOwnerOrAdmin(permissions.BasePermission):
    """
    Permission for subscriptions:
    - Owners can view/modify their own subscriptions
    - Admins can view/modify all subscriptions
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        
        # For email-based subscriptions
        if hasattr(obj, 'email') and obj.email == request.user.email:
            return True
        
        # For user-based subscriptions
        if hasattr(obj, 'user') and obj.user == request.user:
            return True
        
        return False
    
    
 
 
# class IsAdminOrSuperUser(permissions.BasePermission):
#     def has_permission(self, request, view):
#         user = request.user
#         if not user.is_authenticated:
#             logger.debug("Permission denied: User not authenticated")
#             return False
            
#         logger.info(
#             f"Full permission check for {user.email}:\n"
#             f"DB ID: {user.id}\n"
#             f"Role: {getattr(user, 'role', 'N/A')}\n"
#             f"Is Staff: {user.is_staff}\n"
#             f"Is Superuser: {user.is_superuser}\n"
#             f"Is Active: {user.is_active}"
#         )
        
#         if user.is_superuser:
#             logger.debug("Permission granted: Superuser")
#             return True
            
#         result = (
#             getattr(user, 'role', None) == UserRole.ADMIN.value and 
#             user.is_staff
#         )
        
#         logger.debug(f"Admin check result: {result}")
#         return result
       
    
class IsAdminOrSuperUser(permissions.BasePermission):
    """
    Allows access only to:
    - Users with role='admin' AND is_staff=True
    - Superusers (is_superuser=True)
    """
    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False
            
        # Debug logging
        logger.info(
            f"Permission check for {user.email}: "
            f"role={user.role}, "
            f"is_staff={user.is_staff}, "
            f"is_superuser={user.is_superuser}"
        )
        
        # Superusers always pass
        if user.is_superuser:
            return True
            
        # Regular admin check
        return (
            user.role == UserRole.ADMIN.value and 
            user.is_staff  # Extra safeguard
        )