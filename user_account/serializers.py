

# user_account/serializers.py

from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import CustomUser, Profile, UserRole
from .validators.user_validators import UserValidator
from .services.user_services import UserService 
from .validators.user_validators import UserValidator
from rest_framework.exceptions import ValidationError
from .validators.password_reset_validators import PasswordResetValidator
from .validators.change_password_validators import ChangePasswordValidator
from django.contrib.auth import get_user_model




# REGISTER USER -------------------------------------------------------------------------------
# REGISTER USER -------------------------------------------------------------------------------
class UserRegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)

    role = serializers.ChoiceField(
        choices=[(role.value, role.name) for role in UserRole],  # Correct choices format
        allow_blank=True,
        required=False,
        write_only=True,
        default=UserRole.USER.value
    )
    is_staff = serializers.BooleanField(default=False)
    is_superuser = serializers.BooleanField(default=False)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'confirm_password', 'role', 'is_staff', 'is_superuser')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, data):
        if 'role' in data and not data['role'].strip():
            data['role'] = None
        UserValidator.validate_registration_data(data)
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        role = validated_data.get('role', UserRole.USER.value)
        is_staff = validated_data.pop('is_staff', False)
        is_superuser = validated_data.pop('is_superuser', False)
        try:
            user = UserService.register_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password'],
                role=role,
                is_staff=is_staff,
                is_superuser=is_superuser
            )
            return user
        except Exception as e:
            raise serializers.ValidationError(str(e))

# class UserRegistrationSerializer(serializers.ModelSerializer):
#     confirm_password = serializers.CharField(write_only=True, required=True)
    
#     role = serializers.ChoiceField(
#         choices=[(role.value, role.name) for role in UserRole],  # Correct choices format
#         allow_blank=True,
#         required=False,
#         write_only=True,
#         default=UserRole.USER.value
#     )

#     class Meta:
#         model = CustomUser
#         fields = ('username', 'email', 'password', 'confirm_password', 'role')
#         extra_kwargs = {
#             'password': {'write_only': True},
#         }

#     def validate(self, data):
#         if 'role' in data and not data['role'].strip():
#             data['role'] = None
#         UserValidator.validate_registration_data(data)
#         return data

#     def create(self, validated_data):
#         validated_data.pop('confirm_password')
#         try:
#             user = UserService.register_user(
#                 username=validated_data['username'],
#                 email=validated_data['email'],
#                 password=validated_data['password'],
#                 role=validated_data.get('role', UserRole.USER.value)
#             )
#             return user
#         except Exception as e:
#             raise serializers.ValidationError(str(e))









class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'}
    )

    role = serializers.CharField(
        read_only=False,  # Allow writing but control in update()
        required=False,
        default=UserRole.USER.value  # This is correct.
    )

    is_verified = serializers.BooleanField(read_only=True)

    class Meta:
        model = CustomUser
        fields = (
            'id', 'email', 'password', 'first_name', 'last_name',
            'profile_picture', 'is_verified', 'role', 'date_joined'
        )
        read_only_fields = ('id', 'is_verified', 'date_joined')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """Handle both regular and social auth user creation"""
        # Check for social auth via SocialAccount instead of direct fields
        social_auth = hasattr(self.context.get('request'), 'socialaccount')

        # Only require password if not social auth
        if not social_auth and not validated_data.get('password'):
            raise serializers.ValidationError(
                {"password": "Password is required for non-OAuth users"}
            )

        # Hash password if provided
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])

        #  Important:  DO NOT set the role here for social auth.  The adapter is responsible.
        return super().create(validated_data)

    def update(self, instance, validated_data):
        """Update user with admin-controlled role changes"""
        request = self.context.get('request')

        # Only allow admin/superuser to update role
        if 'role' in validated_data:
            if not (request and (request.user.is_staff or request.user.is_superuser)):
                validated_data.pop('role')
            elif validated_data['role'] not in [role.value for role in UserRole]:
                raise serializers.ValidationError({"role": "Invalid role specified"})

        # Handle password update if needed
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])

        return super().update(instance, validated_data)


# class UserSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(
#         write_only=True,
#         required=False,
#         style={'input_type': 'password'}
#     )
    
#     role = serializers.CharField(
#         read_only=False,  # Allow writing but control in update()
#         required=False,
#         default=UserRole.USER.value
#     )
    
#     is_verified = serializers.BooleanField(read_only=True)
    
#     class Meta:
#         model = CustomUser
#         fields = (
#             'id', 'email', 'password', 'first_name', 'last_name', 
#             'profile_picture', 'is_verified', 'role', 'date_joined'
#         )
#         read_only_fields = ('id', 'is_verified', 'date_joined')
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self, validated_data):
#         """Handle both regular and social auth user creation"""
#         # Check for social auth via SocialAccount instead of direct fields
#         social_auth = hasattr(self.context.get('request'), 'socialaccount')
        
#         # Only require password if not social auth
#         if not social_auth and not validated_data.get('password'):
#             raise serializers.ValidationError(
#                 {"password": "Password is required for non-OAuth users"}
#             )
        
#         # Hash password if provided
#         if 'password' in validated_data:
#             validated_data['password'] = make_password(validated_data['password'])
        
#         return super().create(validated_data)

#     def update(self, instance, validated_data):
#         """Update user with admin-controlled role changes"""
#         request = self.context.get('request')
        
#         # Only allow admin/superuser to update role
#         if 'role' in validated_data:
#             if not (request and (request.user.is_staff or request.user.is_superuser)):
#                 validated_data.pop('role')
#             elif validated_data['role'] not in [role.value for role in UserRole]:
#                 raise serializers.ValidationError({"role": "Invalid role specified"})
        
#         # Handle password update if needed
#         if 'password' in validated_data:
#             validated_data['password'] = make_password(validated_data['password'])
            
#         return super().update(instance, validated_data)
    
    
    

# class UserSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(
#         write_only=True,
#         required=False,
#         style={'input_type': 'password'}
#     )
    
#     role = serializers.CharField(read_only=True)
#     default=UserRole.USER.value
#     is_verified = serializers.BooleanField(read_only=True)
    
#     class Meta:
#         model = CustomUser
#         fields = (
#             'id', 'email', 'password', 'first_name', 'last_name', 
#             'profile_picture', 'is_verified', 'role', 'date_joined'

#         )
#         read_only_fields = (
#             'id', 'is_verified', 'role', 'date_joined'
#         )
#         extra_kwargs = {
#             'password': {'write_only': True}
#         }

#     def create(self, validated_data):
#         # Only require password if not social auth
#         if not validated_data.get('google_id') and not validated_data.get('microsoft_id'):
#             if not validated_data.get('password'):
#                 raise serializers.ValidationError(
#                     {"password": "Password is required for non-OAuth users"}
#                 )
        
#         # Hash password if provided
#         if 'password' in validated_data:
#             validated_data['password'] = make_password(validated_data['password'])
        
#         return super().create(validated_data)

#     def update(self, instance, validated_data):
#         # Handle password update
#         if 'password' in validated_data:
#             validated_data['password'] = make_password(validated_data['password'])
#         return super().update(instance, validated_data)
    


# PROFILE -------------------------------------------------------------------------------
class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    initials = serializers.SerializerMethodField()
    image_url = serializers.SerializerMethodField()
    profile_image = serializers.ImageField(
        required=False, 
        allow_null=True,
        write_only=True
    )
    profile_image_url = serializers.URLField(
        required=False, 
        allow_blank=True,
        write_only=True
    )

    class Meta:
        model = Profile
        fields = (
            'id', 'user', 'bio', 'headline', 'phone_number', 'location', 'birth_date',
            'company', 'job_title', 'website', 'twitter_url', 'linkedin_url', 'github_url',
            'profile_image', 'profile_image_url', 'cover_image', 'show_email', 'show_phone',
            'show_location', 'created_at', 'updated_at', 'initials', 'image_url'
        )
        read_only_fields = (
            'id', 'initials', 'image_url', 'created_at', 'updated_at'
        )

    def get_initials(self, obj):
        return obj.get_initials()
    
    def get_image_url(self, obj):
        return obj.image_url

    def update(self, instance, validated_data):
        # Handle profile image updates
        profile_image = validated_data.pop('profile_image', None)
        profile_image_url = validated_data.pop('profile_image_url', None)
        
        if profile_image is not None:
            if instance.profile_image:
                instance.profile_image.delete()
            instance.profile_image = profile_image
            instance.profile_image_url = ''
        
        if profile_image_url is not None:
            if instance.profile_image:
                instance.profile_image.delete()
                instance.profile_image = None
            instance.profile_image_url = profile_image_url

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        instance.save()
        return instance



# USER LOGIN -------------------------------------------------------------------------------
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        
        # Validate email format using UserValidator
        try:
            UserValidator.validate_email(email)
        except ValidationError as e:
            raise serializers.ValidationError({'email': str(e)})
        
        # Basic password presence check (we won't validate password complexity here)
        if not password:
            raise serializers.ValidationError({'password': "Password is required"})
            
        return data



# RESET PASSWORD -------------------------------------------------------------------------------
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, data):
        try:
            PasswordResetValidator.validate_email_exists(data['email'])
        except ValidationError as e:
            raise serializers.ValidationError({'email': str(e)})
        return data


class PasswordResetTokenValidationSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)


class PasswordResetSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    newPassword = serializers.CharField(required=True, write_only=True)
    confirmNewPassword = serializers.CharField(required=True, write_only=True)
    userId = serializers.UUIDField(required=True)

    def validate(self, data):
        PasswordResetValidator.validate_password_reset_data(data)
        return data
    


# Rsend Verification Emal--------------------------------------------------------    
class ResendVerificationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        PasswordResetValidator.validate_email_exists(value)
        return value
    
    
    
# Change Password -----------------------------------------------------------------
class ChangePasswordSerializer(serializers.Serializer):
    currentPassword = serializers.CharField(required=True, write_only=True)
    newPassword = serializers.CharField(required=True, write_only=True)
    confirmNewPassword = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        ChangePasswordValidator.validate_change_password_data(user, data)
        return data
    
 
 
# User Details Serializers -----------------------------------------------------------------
User = get_user_model()
class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'is_staff', 'is_superuser', 'is_active', 'is_verified', 'date_joined']
        read_only_fields = ['id', 'username', 'email', 'date_joined'] # Removed 'created_at', 'updated_at' as they are not in the model fields listed

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.role = validated_data.get('role', instance.role)
        instance.is_staff = validated_data.get('is_staff', instance.is_staff)
        instance.is_superuser = validated_data.get('is_superuser', instance.is_superuser)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.is_verified = validated_data.get('is_verified', instance.is_verified)
        instance.save()
        return instance

class UpdateUserRoleSerializer(serializers.Serializer):
    role = serializers.ChoiceField(
        choices=[(role.value, role.name) for role in UserRole],
        required=True
    )
    is_staff = serializers.BooleanField(required=False)  # Make these optional
    is_superuser = serializers.BooleanField(required=False)

# class UserDetailSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'is_staff', 'is_superuser', 'is_active', 'is_verified', 'date_joined'] # Include relevant fields
#         read_only_fields = ['id', 'username', 'email', 'created_at', 'updated_at'] # Fields that should not be updated here

# class UpdateUserRoleSerializer(serializers.Serializer):
#     role = serializers.ChoiceField(
#         choices=[(role.value, role.name) for role in UserRole],  # Proper choices format
#         required=True
#     )

    def validate_role(self, value):
        allowed_roles = ['admin', 'staff', 'user']  # Define your allowed roles
        if value not in allowed_roles:
            raise serializers.ValidationError(f"Role must be one of: {', '.join(allowed_roles)}")
        return value


 
# User Minimal Serializer -----------------------------------------------------------------
class UserMinimalSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 
                 'profile_picture', 'profile_picture_url', 'full_name']
        read_only_fields = fields

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()
        
    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            return obj.profile_picture.url
        return None
    
    def get_initials(self, obj):
        first = obj.first_name[0].upper() if obj.first_name else ''
        last = obj.last_name[0].upper() if obj.last_name else ''
        return f"{first}{last}"