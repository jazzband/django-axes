from __future__ import unicode_literals

import logging

from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.signals import user_logged_out
from django.contrib.auth.signals import user_login_failed
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.dispatch import Signal
from django.utils import timezone

from axes.conf import settings
from axes.attempts import get_cache_key
from axes.attempts import get_cache_timeout
from axes.attempts import get_user_attempts
from axes.attempts import is_user_lockable
from axes.attempts import ip_in_whitelist
from axes.attempts import reset_user_attempts
from axes.models import AccessLog, AccessAttempt
from axes.utils import get_client_str
from axes.utils import query2str
from axes.utils import get_axes_cache, get_client_ip, get_client_username, get_credentials


log = logging.getLogger(settings.AXES_LOGGER)


user_locked_out = Signal(providing_args=['request', 'username', 'ip_address'])


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):  # pylint: disable=unused-argument
    """ Create an AccessAttempt record if the login wasn't successful
    """
    if request is None:
        log.warning('Attempt to authenticate with a custom backend failed.')
        return

    ip_address = get_client_ip(request)
    username = get_client_username(request, credentials)
    user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
    http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]

    if settings.AXES_NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip_address):
        return

    failures = 0
    attempts = get_user_attempts(request, credentials)
    cache_hash_key = get_cache_key(request, credentials)
    cache_timeout = get_cache_timeout()

    failures_cached = get_axes_cache().get(cache_hash_key)
    if failures_cached is not None:
        failures = failures_cached
    else:
        for attempt in attempts:
            failures = max(failures, attempt.failures_since_start)

    # add a failed attempt for this user
    failures += 1
    get_axes_cache().set(cache_hash_key, failures, cache_timeout)

    # has already attempted, update the info
    if attempts:
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

            log.info(
                'AXES: Repeated login failure by %s. Count = %d of %d',
                get_client_str(username, ip_address, user_agent, path_info),
                failures,
                settings.AXES_FAILURE_LIMIT
            )
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
            'AXES: New login failure by %s. Creating access record.',
            get_client_str(username, ip_address, user_agent, path_info)
        )

    # no matter what, we want to lock them out if they're past the number of
    # attempts allowed, unless the user is set to notlockable
    if (
        failures >= settings.AXES_FAILURE_LIMIT and
        settings.AXES_LOCK_OUT_AT_FAILURE and
        is_user_lockable(request, credentials)
    ):
        log.warning(
            'AXES: locked out %s after repeated login attempts.',
            get_client_str(username, ip_address, user_agent, path_info)
        )

        # send signal when someone is locked out.
        user_locked_out.send(
            'axes', request=request, username=username, ip_address=ip_address
        )


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):  # pylint: disable=unused-argument
    """ When a user logs in, update the access log
    """
    username = user.get_username()
    credentials = get_credentials(username)
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
    http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
    log.info(
        'AXES: Successful login by %s.',
        get_client_str(username, ip_address, user_agent, path_info)
    )

    if not settings.AXES_DISABLE_SUCCESS_ACCESS_LOG:
        AccessLog.objects.create(
            user_agent=user_agent,
            ip_address=ip_address,
            username=username,
            http_accept=http_accept,
            path_info=path_info,
            trusted=True,
        )

    if settings.AXES_RESET_ON_SUCCESS:
        count = reset_user_attempts(request, credentials)
        log.info(
            'AXES: Deleted %d failed login attempts by %s.',
            count,
            get_client_str(username, ip_address, user_agent, path_info)
        )


@receiver(user_logged_out)
def log_user_logged_out(sender, request, user, **kwargs):  # pylint: disable=unused-argument
    """ When a user logs out, update the access log
    """
    log.info('AXES: Successful logout by %s.', user)

    if user and not settings.AXES_DISABLE_ACCESS_LOG:
        AccessLog.objects.filter(
            username=user.get_username(),
            logout_time__isnull=True,
        ).update(logout_time=timezone.now())


@receiver(post_save, sender=AccessAttempt)
def update_cache_after_save(instance, **kwargs):  # pylint: disable=unused-argument
    cache_hash_key = get_cache_key(instance)
    if not get_axes_cache().get(cache_hash_key):
        cache_timeout = get_cache_timeout()
        get_axes_cache().set(cache_hash_key, instance.failures_since_start, cache_timeout)


@receiver(post_delete, sender=AccessAttempt)
def delete_cache_after_delete(instance, **kwargs):  # pylint: disable=unused-argument
    cache_hash_key = get_cache_key(instance)
    get_axes_cache().delete(cache_hash_key)
