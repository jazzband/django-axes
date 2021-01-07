from logging import getLogger

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.core.signals import setting_changed
from django.db.models.signals import post_save, post_delete
from django.dispatch import Signal
from django.dispatch import receiver

from axes.handlers.proxy import AxesProxyHandler
from axes.models import AccessAttempt

log = getLogger(__name__)


# This signal provides the following arguments to any listeners:
# request - The current Request object.
# username - The username of the User who has been locked out.
# ip_address - The IP of the user who has been locked out.
user_locked_out = Signal()


@receiver(user_login_failed)
def handle_user_login_failed(*args, **kwargs):
    AxesProxyHandler.user_login_failed(*args, **kwargs)


@receiver(user_logged_in)
def handle_user_logged_in(*args, **kwargs):
    AxesProxyHandler.user_logged_in(*args, **kwargs)


@receiver(user_logged_out)
def handle_user_logged_out(*args, **kwargs):
    AxesProxyHandler.user_logged_out(*args, **kwargs)


@receiver(post_save, sender=AccessAttempt)
def handle_post_save_access_attempt(*args, **kwargs):
    AxesProxyHandler.post_save_access_attempt(*args, **kwargs)


@receiver(post_delete, sender=AccessAttempt)
def handle_post_delete_access_attempt(*args, **kwargs):
    AxesProxyHandler.post_delete_access_attempt(*args, **kwargs)


@receiver(setting_changed)
def handle_setting_changed(
    sender, setting, value, enter, **kwargs
):  # pylint: disable=unused-argument
    """
    Reinitialize handler implementation if a relevant setting changes
    in e.g. application reconfiguration or during testing.
    """

    if setting == "AXES_HANDLER":
        AxesProxyHandler.get_implementation(force=True)
