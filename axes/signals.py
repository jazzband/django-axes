from django.dispatch import Signal, receiver
from django.contrib.auth.signals import user_logged_out
from django.core.exceptions import ObjectDoesNotExist
from axes.models import AccessLog

# django 1.4 has a new timezone aware now() use if available.
try:
    from django.utils.timezone import now
except ImportError:
    # fall back to none timezone aware now()
    from datetime import datetime
    now = datetime.now

user_locked_out = Signal(providing_args=['request', 'username', 'ip_address'])

@receiver(user_logged_out)
def log_user_lockout(sender, request, user, signal, *args, **kwargs):
    """ When a user logs out, update the access log"""
    if not user:
        return

    access_log = None
    access_logs = AccessLog.objects.filter(username=user.username,
                    logout_time__isnull=True).order_by("-attempt_time")

    if len(access_logs) > 0:
        access_log = access_logs[0]

    if access_log:
        access_log.logout_time = now()
        access_log.save()
