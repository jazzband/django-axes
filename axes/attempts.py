from datetime import timedelta
from hashlib import md5

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

from ipware.ip import get_ip

from axes.conf import settings
from axes.models import AccessAttempt


def _query_user_attempts(request):
    """Returns access attempt record if it exists.
    Otherwise return None.
    """
    ip = get_ip(request)
    username = request.POST.get(settings.AXES_USERNAME_FORM_FIELD, None)

    if settings.AXES_ONLY_USER_FAILURES:
        attempts = AccessAttempt.objects.filter(username=username)
    elif settings.AXES_USE_USER_AGENT:
        ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
        attempts = AccessAttempt.objects.filter(
            user_agent=ua, ip_address=ip, username=username, trusted=True
        )
    else:
        attempts = AccessAttempt.objects.filter(
            ip_address=ip, username=username, trusted=True
        )

    if not attempts:
        params = {'trusted': False}

        if settings.AXES_ONLY_USER_FAILURES:
            params['username'] = username
        elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
            params['username'] = username
            params['ip_address'] = ip
        else:
            params['ip_address'] = ip

        if settings.AXES_USE_USER_AGENT:
            params['user_agent'] = ua

        attempts = AccessAttempt.objects.filter(**params)

    return attempts


def get_cache_key(request_or_obj):
    """
    Build cache key name from request or AccessAttempt object.
    :param  request_or_obj: Request or AccessAttempt object
    :return cache-key: String, key to be used in cache system
    """
    if isinstance(request_or_obj, AccessAttempt):
        ip = request_or_obj.ip_address
        un = request_or_obj.username
        ua = request_or_obj.user_agent
    else:
        ip = get_ip(request_or_obj)
        un = request_or_obj.POST.get(settings.AXES_USERNAME_FORM_FIELD, None)
        ua = request_or_obj.META.get('HTTP_USER_AGENT', '<unknown>')[:255]

    ip = ip.encode('utf-8') if ip else ''.encode('utf-8')
    un = un.encode('utf-8') if un else ''.encode('utf-8')
    ua = ua.encode('utf-8') if ua else ''.encode('utf-8')

    if settings.AXES_ONLY_USER_FAILURES:
        attributes = un
    elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        attributes = ip + un
    else:
        attributes = ip

    if settings.AXES_USE_USER_AGENT:
        attributes += ua

    cache_hash_key = 'axes-{}'.format(md5(attributes).hexdigest())

    return cache_hash_key


def get_cache_timeout():
    """Returns timeout according to COOLOFF_TIME."""
    cache_timeout = None
    cool_off = settings.AXES_COOLOFF_TIME
    if cool_off:
        if (isinstance(cool_off, int) or isinstance(cool_off, float)):
            cache_timeout = timedelta(hours=cool_off).total_seconds()
        else:
            cache_timeout = cool_off.total_seconds()

    return cache_timeout


def get_user_attempts(request):
    force_reload = False
    attempts = _query_user_attempts(request)
    cache_hash_key = get_cache_key(request)
    cache_timeout = get_cache_timeout()

    cool_off = settings.AXES_COOLOFF_TIME
    if cool_off:
        if (isinstance(cool_off, int) or isinstance(cool_off, float)):
            cool_off = timedelta(hours=cool_off)

        for attempt in attempts:
            if attempt.attempt_time + cool_off < timezone.now():
                if attempt.trusted:
                    attempt.failures_since_start = 0
                    attempt.save()
                    cache.set(cache_hash_key, 0, cache_timeout)
                else:
                    attempt.delete()
                    force_reload = True
                    failures_cached = cache.get(cache_hash_key)
                    if failures_cached is not None:
                        cache.set(
                            cache_hash_key, failures_cached - 1, cache_timeout
                        )

    # If objects were deleted, we need to update the queryset to reflect this,
    # so force a reload.
    if force_reload:
        attempts = _query_user_attempts(request)

    return attempts


def ip_in_whitelist(ip):
    if not settings.AXES_IP_WHITELIST:
        return False

    return ip in settings.AXES_IP_WHITELIST


def ip_in_blacklist(ip):
    if not settings.AXES_IP_BLACKLIST:
        return False

    return ip in settings.AXES_IP_BLACKLIST


def is_user_lockable(request):
    """Check if the user has a profile with nolockout
    If so, then return the value to see if this user is special
    and doesn't get their account locked out
    """
    if hasattr(request.user, 'nolockout'):
        return not request.user.nolockout

    if request.method != 'POST':
        return True

    try:
        field = getattr(get_user_model(), 'USERNAME_FIELD', 'username')
        kwargs = {
            field: request.POST.get(settings.AXES_USERNAME_FORM_FIELD)
        }
        user = get_user_model().objects.get(**kwargs)

        if hasattr(user, 'nolockout'):
            # need to invert since we need to return
            # false for users that can't be blocked
            return not user.nolockout

    except get_user_model().DoesNotExist:
        # not a valid user
        return True

    # Default behavior for a user to be lockable
    return True


def is_already_locked(request):
    ip = get_ip(request)

    if (
        settings.AXES_ONLY_USER_FAILURES or
        settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP
    ) and request.method == 'GET':
        return False

    if settings.AXES_NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip):
        return False

    if settings.AXES_ONLY_WHITELIST and not ip_in_whitelist(ip):
        return True

    if ip_in_blacklist(ip):
        return True

    if not is_user_lockable(request):
        return False

    cache_hash_key = get_cache_key(request)
    failures_cached = cache.get(cache_hash_key)
    if failures_cached is not None:
        return (
            failures_cached >= settings.AXES_FAILURE_LIMIT and
            settings.AXES_LOCK_OUT_AT_FAILURE
        )
    else:
        for attempt in get_user_attempts(request):
            if (
                attempt.failures_since_start >= settings.AXES_FAILURE_LIMIT and
                settings.AXES_LOCK_OUT_AT_FAILURE
            ):
                return True

    return False
