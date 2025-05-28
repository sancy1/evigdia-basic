

# user_account/models.py

import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from enum import Enum



class UserRole(Enum):
    USER = 'user'
    ADMIN = 'admin'
    MODERATOR = 'moderator'

    @classmethod
    def choices(cls):
        return [(key.value, key.name) for key in cls]
    

# Custom User Manager ---------------------------------------------------------------------------------
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        
        # Set default role if not provided
        role = extra_fields.pop('role', None)
        if not role or role not in dict(UserRole.choices()).keys():
            extra_fields['role'] = UserRole.USER.value
        else:
            extra_fields['role'] = role
        
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', UserRole.ADMIN.value)
        extra_fields.setdefault('is_verified', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)



# Custom User ---------------------------------------------------------------------------------
class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    username = models.CharField(_('username'), max_length=150, unique=True, blank=True)
    profile_picture = models.URLField(_('profile picture'), max_length=500, blank=True, null=True)
    
    # Authentication fields
    role = models.CharField(
        max_length=20,
        choices=UserRole.choices(),
        blank=True,
        null=True,
    )
    
    is_verified = models.BooleanField(
        _('verified'),
        default=False,
        help_text=_('Designates whether this user has verified their email address.')
    )
    
    verification_token = models.CharField(max_length=100, blank=True, null=True)
    verification_token_expires = models.DateTimeField(blank=True, null=True)
    reset_password_token = models.CharField(max_length=100, blank=True, null=True)
    reset_password_expires = models.DateTimeField(blank=True, null=True)
    password = models.CharField(_('password'), max_length=128)
    
    # Social auth fields removed as not needed
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def set_password(self, raw_password):
        if raw_password is not None:  # Only hash if password is provided
            self.password = make_password(raw_password)
            self._password = raw_password

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct.
        Handles hashing formats behind the scenes.
        """
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        # For social auth users without password
        if not self.password:
            # Set unusable password for users without password
            self.set_unusable_password()
        super().save(*args, **kwargs)

    @property
    def is_admin(self):
        return self.role == UserRole.ADMIN.value

    @property
    def is_moderator(self):
        return self.role == UserRole.MODERATOR.value

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')



# Profile --------------------------------------------------------------------------------------------------

class Profile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
    
    # Personal Information
    bio = models.TextField(max_length=500, blank=True)
    headline = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=100, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    
    # Professional Information
    company = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    website = models.URLField(max_length=200, blank=True)
    
    # Social Links
    twitter_url = models.URLField(max_length=200, blank=True)
    linkedin_url = models.URLField(max_length=200, blank=True)
    github_url = models.URLField(max_length=200, blank=True)
    
    # Profile Media
    profile_image = models.ImageField(
        upload_to='profile_images/',
        blank=True,
        null=True
    )
    profile_image_url = models.URLField(
        max_length=500,
        blank=True
    )
    cover_image = models.ImageField(
        upload_to='cover_images/',
        blank=True,
        null=True
    )
    
    # Privacy Settings
    show_email = models.BooleanField(default=False)
    show_phone = models.BooleanField(default=False)
    show_location = models.BooleanField(default=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return f'{self.user.email}\'s profile'
    
    def get_initials(self):
        name_parts = (self.user.first_name + ' ' + self.user.last_name).split()
        initials = ''.join([name[0].upper() for name in name_parts if name])
        return initials[:2]
    
    @property
    def image_url(self):
        if self.profile_image:
            return self.profile_image.url
        elif self.profile_image_url:
            return self.profile_image_url
        elif self.user.profile_picture:
            return self.user.profile_picture
        return None
    
    def save(self, *args, **kwargs):
        if self.profile_image_url and self.profile_image:
            self.profile_image.delete(save=False)
            self.profile_image = None
        super().save(*args, **kwargs)


