import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.signals import user_logged_out
from django.contrib.auth.signals import user_login_failed
from django.core.cache import cache
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.dispatch import Signal
from django.utils import timezone

from ipware.ip import get_ip

from axes.conf import settings
from axes.attempts import get_cache_key
from axes.attempts import get_cache_timeout
from axes.attempts import get_user_attempts
from axes.attempts import is_user_lockable
from axes.attempts import ip_in_whitelist
from axes.models import AccessLog, AccessAttempt
from axes.utils import get_client_str
from axes.utils import query2str


log = logging.getLogger(settings.AXES_LOGGER)


user_locked_out = Signal(providing_args=['request', 'username', 'ip_address'])


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    """ Create an AccessAttempt record if the login wasn't successful
    """
    username_field = get_user_model().USERNAME_FIELD
    if request is None or username_field not in credentials:
        log.error('Attempt to authenticate with a custom backend failed.')
        return

    ip_address = get_ip(request)
    username = credentials[username_field]
    user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
    http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]

    if settings.AXES_NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip_address):
        return

    failures = 0
    attempts = get_user_attempts(request)
    cache_hash_key = get_cache_key(request)
    cache_timeout = get_cache_timeout()

    failures_cached = cache.get(cache_hash_key)
    if failures_cached is not None:
        failures = failures_cached
    else:
        for attempt in attempts:
            failures = max(failures, attempt.failures_since_start)

    # add a failed attempt for this user
    failures += 1
    cache.set(cache_hash_key, failures, cache_timeout)

    # has already attempted, update the info
    if len(attempts):
        for attempt in attempts:
            attempt.get_data = '%s\n---------\n%s' % (
                attempt.get_data,
                query2str(request.GET),
            )
            attempt.post_data = '%s\n---------\n%s' % (
                attempt.post_data,
                query2str(request.POST)
            )
            attempt.http_accept = http_accept
            attempt.path_info = path_info
            attempt.failures_since_start = failures
            attempt.attempt_time = timezone.now()
            attempt.save()

            fail_msg = 'AXES: Repeated login failure by {0}.'.format(
                get_client_str(username, ip_address, user_agent, path_info)
            )
            count_msg = 'Count = {0} of {1}'.format(
                failures, settings.AXES_FAILURE_LIMIT
            )
            log.info('{0} {1}'.format(fail_msg, count_msg))
    else:
        # Record failed attempt. Whether or not the IP address or user agent is
        # used in counting failures is handled elsewhere, so we just record
        # everything here.
        AccessAttempt.objects.create(
            user_agent=user_agent,
            ip_address=ip_address,
            username=username,
            get_data=query2str(request.GET),
            post_data=query2str(request.POST),
            http_accept=http_accept,
            path_info=path_info,
            failures_since_start=failures,
        )

        log.info(
            'AXES: New login failure by {0}. Creating access record.'.format(
                get_client_str(username, ip_address, user_agent, path_info)
            )
        )

    # no matter what, we want to lock them out if they're past the number of
    # attempts allowed, unless the user is set to notlockable
    if (
        failures >= settings.AXES_FAILURE_LIMIT and
        settings.AXES_LOCK_OUT_AT_FAILURE and
        is_user_lockable(request)
    ):
        log.warning('AXES: locked out {0} after repeated login attempts.'.format(
            get_client_str(username, ip_address, user_agent, path_info)
        ))

        # send signal when someone is locked out.
        user_locked_out.send(
            'axes', request=request, username=username, ip_address=ip_address
        )


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    """ When a user logs in, update the access log
    """
    username = user.get_username()
    ip_address = get_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
    http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
    log.info('AXES: Successful login by {0}.'.format(
        get_client_str(username, ip_address, user_agent, path_info)
    ))

    if not settings.AXES_DISABLE_SUCCESS_ACCESS_LOG:
        AccessLog.objects.create(
            user_agent=user_agent,
            ip_address=ip_address,
            username=username,
            http_accept=http_accept,
            path_info=path_info,
            trusted=True,
        )


@receiver(user_logged_out)
def log_user_logged_out(sender, request, user, **kwargs):
    """ When a user logs out, update the access log
    """
    log.info('AXES: Successful logout by {0}.'.format(user))

    if user and not settings.AXES_DISABLE_ACCESS_LOG:
        AccessLog.objects.filter(
            username=user.get_username(),
            logout_time__isnull=True,
        ).update(logout_time=timezone.now())


@receiver(post_save, sender=AccessAttempt)
def update_cache_after_save(instance, **kwargs):
    cache_hash_key = get_cache_key(instance)
    if not cache.get(cache_hash_key):
        cache_timeout = get_cache_timeout()
        cache.set(cache_hash_key, instance.failures_since_start, cache_timeout)


@receiver(post_delete, sender=AccessAttempt)
def delete_cache_after_delete(instance, **kwargs):
    cache_hash_key = get_cache_key(instance)
    cache.delete(cache_hash_key)
