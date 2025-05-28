# # user_account/backends.py
# from django.contrib.auth import get_user_model
# from django.contrib.auth.backends import ModelBackend

# User = get_user_model()

# class NeonDBCompatibleAuthBackend(ModelBackend):
#     def get_user_permissions(self, user_obj, obj=None):
#         # Ensure superusers have all permissions
#         if user_obj.is_superuser:
#             return set()
#         return super().get_user_permissions(user_obj, obj)
    
#     def has_perm(self, user_obj, perm, obj=None):
#         # Bypass checks for superusers
#         if user_obj.is_active and user_obj.is_superuser:
#             return True
#         return super().has_perm(user_obj, perm, obj)