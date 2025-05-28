from django.apps import AppConfig


class UserAccountConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "user_account"
    # from user_account.middleware.ping_render import start_render_ping
    # start_render_ping()  # Starts the ping thread
