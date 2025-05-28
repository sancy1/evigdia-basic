
# backend/apps/user_account/admin.py

# backend/apps/user_account/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from .models import CustomUser, Profile

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('id', 'email', 'username', 'first_name', 'last_name', 'is_verified', 'is_staff', 'profile_picture_display')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'profile_picture')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'profile_picture')}),
    )
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)

    def profile_picture_display(self, obj):
        """Display a small image preview in the list view."""
        if obj.profile_picture:
            return format_html('<img src="{}" width="50" height="50" style="border-radius: 50%;">', obj.profile_picture)
        return "No picture"  # Or a default image

    profile_picture_display.short_description = _('Profile Picture')  # Column header
    profile_picture_display.allow_tags = True  # Important for rendering HTML


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio_short', 'location', 'birth_date', 'initials')
    search_fields = ('user__email', 'user__username', 'location')
    readonly_fields = ('user', 'created_at', 'updated_at', 'initials') # Added readonly_fields from the new code
    fieldsets = (
        (None, {'fields': ('user',)}), # Adjusted to be consistent with the new code's structure
        (_('Personal Information'), {'fields': ('bio', 'headline', 'phone_number', 'location', 'birth_date')}), # Added missing fields
        (_('Professional Information'), {'fields': ('company', 'job_title', 'website')}), # Added missing fields
        (_('Social Links'), {'fields': ('twitter_url', 'linkedin_url', 'github_url')}), # Added missing fields
        (_('Profile Media'), {'fields': ('profile_image', 'profile_image_url', 'cover_image')}), # Added missing fields
        (_('Privacy Settings'), {'fields': ('show_email', 'show_phone', 'show_location')}), # Added missing fields
        (_('Metadata'), {'fields': ('created_at', 'updated_at')}), # Added missing fields
    )

    def bio_short(self, obj):
        return f"{str(obj.bio)[:50]}..." if obj.bio else ""
    bio_short.short_description = _('Bio (short)')

    def initials(self, obj):
        return obj.get_initials()
    initials.short_description = _('Initials')
    initials.admin_order_field = 'user__first_name'  # Allows ordering by initials


















# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin
# from django.utils.translation import gettext_lazy as _
# from django.utils.html import format_html
# from .models import CustomUser, Profile

# @admin.register(CustomUser)
# class CustomUserAdmin(UserAdmin):
#     model = CustomUser
#     list_display = ('id', 'email', 'username', 'first_name', 'last_name', 'is_staff', 'profile_picture_display')
#     fieldsets = (
#         (None, {'fields': ('email', 'password')}),
#         (_('Personal info'), {'fields': ('first_name', 'last_name', 'profile_picture')}),
#         (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
#         (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
#     )
#     add_fieldsets = (
#         (None, {'fields': ('email', 'password')}),
#         (_('Personal info'), {'fields': ('first_name', 'last_name', 'profile_picture')}),
#     )
#     search_fields = ('email', 'username', 'first_name', 'last_name')
#     ordering = ('email',)

#     def profile_picture_display(self, obj):
#         """Display a small image preview in the list view."""
#         if obj.profile_picture:
#             return format_html('<img src="{}" width="50" height="50" style="border-radius: 50%;">', obj.profile_picture)
#         return "No picture"  # Or a default image

#     profile_picture_display.short_description = _('Profile Picture')  # Column header
#     profile_picture_display.allow_tags = True  # Important for rendering HTML


# @admin.register(Profile)
# class ProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'bio_short', 'location', 'birth_date', 'initials')
#     search_fields = ('user__email', 'user__username', 'location')
#     readonly_fields = ('user',)
#     fieldsets = (
#         (None, {'fields': ('user', 'bio', 'location', 'birth_date')}),
#     )

#     def bio_short(self, obj):
#         return f"{str(obj.bio)[:50]}..." if obj.bio else ""
#     bio_short.short_description = _('Bio (short)')

#     def initials(self, obj):
#         return obj.get_initials()
#     initials.short_description = _('Initials')
#     initials.admin_order_field = 'user__first_name'  # Allows ordering by initials