from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from .backup import create_secure_backup
from .models import LoginLog


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ip = get_client_ip(request)
    if not ip:
        return

    previous_login = LoginLog.objects.filter(user=user).order_by("-created_at").first()
    LoginLog.objects.create(user=user, ip_address=ip)

    if previous_login and previous_login.ip_address != ip:
        create_secure_backup(skip_duplicate=True)
