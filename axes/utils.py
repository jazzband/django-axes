from importlib import import_module
from six import string_types
from axes.models import AccessAttempt


def reset(ip=None, username=None):
    """Reset records that match ip or username, and
    return the count of removed attempts.
    """
    count = 0

    attempts = AccessAttempt.objects.all()
    if ip:
        attempts = attempts.filter(ip_address=ip)
    if username:
        attempts = attempts.filter(username=username)

    if attempts:
        count = attempts.count()
        attempts.delete()

    return count


def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        assert isinstance(path_or_callable, string_types)
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)
