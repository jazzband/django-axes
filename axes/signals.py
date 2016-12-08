from django.dispatch import receiver
from django.dispatch import Signal
from django.utils.timezone import now
from django.contrib.auth.signals import user_logged_out
from django.db.models.signals import post_save, post_delete
from django.core.cache import cache

from axes.models import AccessLog, AccessAttempt
from axes.settings import DISABLE_ACCESS_LOG


user_locked_out = Signal(providing_args=['request', 'username', 'ip_address'])

if not DISABLE_ACCESS_LOG:
    @receiver(user_logged_out)
    def log_user_lockout(sender, request, user, signal, *args, **kwargs):
        """ When a user logs out, update the access log
        """
        if not user:
            return

        access_logs = AccessLog.objects.filter(
            username=user.get_username(),
            logout_time__isnull=True,
        ).order_by('-attempt_time')[0:1]

        if access_logs:
            access_log = access_logs[0]
            access_log.logout_time = now()
            access_log.save()


@receiver(post_save, sender=AccessAttempt)
def update_cache_after_save(instance, **kwargs):
    from axes.decorators import get_cache_timeout, get_cache_key
    cache_hash_key = get_cache_key(instance)
    if not cache.get(cache_hash_key):
        cache_timeout = get_cache_timeout()
        cache.set(cache_hash_key, instance.failures_since_start, cache_timeout)


@receiver(post_delete, sender=AccessAttempt)
def delete_cache_after_delete(instance, **kwargs):
    from axes.decorators import get_cache_key
    cache_hash_key = get_cache_key(instance)
    cache.delete(cache_hash_key)
