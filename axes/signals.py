from django.dispatch import receiver
from django.dispatch import Signal
from django.utils.timezone import now
from django.contrib.auth.signals import user_logged_out

from axes.models import AccessLog


user_locked_out = Signal(providing_args=['request', 'username', 'ip_address'])


@receiver(user_logged_out)
def log_user_lockout(sender, request, user, signal, *args, **kwargs):
    """ When a user logs out, update the access log
    """
    if not user:
        return

    access_logs = AccessLog.objects.filter(
        username=user.get_username(),
        logout_time__isnull=True,
    ).order_by('-attempt_time')

    if access_logs.exists():
        access_log = access_logs.first()
        access_log.logout_time = now()
        access_log.save()
