import logging
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from datetime import timedelta
from rest_framework.response import Response
from rest_framework import status
from ..models import Profile
# from ...payments.models import SubscriptionPlan, Payment

logger = logging.getLogger(__name__)

class ProfileService:
    @staticmethod
    def get_or_create_profile(user):
        """Get or create profile for user with comprehensive error handling"""
        try:
            profile, created = Profile.objects.select_related('user').get_or_create(
                user=user
            )
            if created:
                logger.info(f"Auto-created profile for user {user.id}")
            return profile
        except Exception as e:
            logger.error(f"Profile access error for user {user.id}: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'code': 'profile_access_error',
                    'message': str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    def is_profile_complete(profile):
        """Check if profile has all required fields filled"""
        try:
            required_fields = ['first_name', 'last_name', 'email']
            user = profile.user
            return all(getattr(user, field, None) for field in required_fields)
        except Exception as e:
            logger.error(f"Profile completeness check failed: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'code': 'profile_completeness_error',
                    'message': str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    def validate_deletion_conditions(user):
        """Validate account can be deleted with comprehensive checks"""
        try:
            # if SubscriptionPlan.objects.filter(user=user, is_active=True).exists():
            #     return Response(
            #         {
            #             'status': 'error',
            #             'code': 'active_subscription_exists',
            #             'message': 'Cannot delete account with active subscriptions'
            #         },
            #         status=status.HTTP_403_FORBIDDEN
            #     )
            # if Payment.objects.filter(user=user, status='pending').exists():
            #     return Response(
            #         {
            #             'status': 'error',
            #             'code': 'pending_payments_exist',
            #             'message': 'Pending payments must be resolved first'
            #         },
            #         status=status.HTTP_403_FORBIDDEN
            #     )
            if (timezone.now() - user.date_joined) < timedelta(days=7):
                return Response(
                    {
                        'status': 'error',
                        'code': 'account_too_new',
                        'message': 'Account must be at least 7 days old to delete'
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            return None
        except Exception as e:
            logger.error(f"Deletion validation failed: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'code': 'deletion_validation_error',
                    'message': str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    def get_changed_fields(instance, validated_data, serializer_fields):
        """Identify which fields are being changed with error handling"""
        try:
            return {
                field: {'old': getattr(instance, field), 'new': validated_data[field]}
                for field in validated_data
                if field in serializer_fields and 
                getattr(instance, field) != validated_data[field]
            }
        except Exception as e:
            logger.error(f"Changed fields detection failed: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'code': 'field_comparison_error',
                    'message': str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )