import logging

from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.signals import user_logged_out
from django.contrib.auth.signals import user_login_failed
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.dispatch import Signal
from django.utils.module_loading import import_string

from axes.conf import settings
from axes.models import AccessAttempt

log = logging.getLogger(settings.AXES_LOGGER)


user_locked_out = Signal(providing_args=['request', 'username', 'ip_address'])


class ProxyHandler:
    """
    Proxy interface for configurable Axes signal handler class.

    If you wish to implement a custom version of this handler,
    you can override the settings.AXES_HANDLER configuration string
    with a class that implements a compatible interface and methods.

    Defaults to using axes.handlers.AxesHandler if not overridden.
    Refer to axes.handlers.AxesHandler for default implementation.
    """

    implementation = None  # concrete handler that is bootstrapped by the Django application loader

    @classmethod
    def initialize(cls):
        """
        Fetch and initialize concrete handler implementation and memoize it to avoid reinitialization.

        This method is re-entrant and can be called multiple times.
        """

        if cls.implementation is None:
            cls.implementation = import_string(settings.AXES_HANDLER)()

    @classmethod
    def user_login_failed(cls, sender, credentials, request, **kwargs):
        """
        Handle user login failure event.

        :param credentials: credentials used for authentication attempt
        :param request: request used for failed authentication attempt
        :return: None
        """

        cls.implementation.user_login_failed(sender, credentials, request, **kwargs)

    @classmethod
    def user_logged_in(cls, sender, request, user, **kwargs):
        """
        Handle user login event.

        :param credentials: credentials used for successful authentication
        :param request: request used for successful authentication
        :return: None
        """

        cls.implementation.user_logged_in(sender, request, user, **kwargs)

    @classmethod
    def user_logged_out(cls, sender, request, user, **kwargs):
        """
        Handle user logout event.

        :param request: request used for logout
        :param user: user used for logout
        :return: None
        """

        cls.implementation.user_logged_out(sender, request, user, **kwargs)

    @classmethod
    def post_save_access_attempt(cls, instance, **kwargs):
        """
        Handle AccessAttempt save event.

        :param instance: axes.models.AccessAttempt instance that will be saved
        :return: None
        """

        cls.implementation.post_save_access_attempt(instance, **kwargs)

    @classmethod
    def post_delete_access_attempt(cls, instance, **kwargs):
        """
        Handle AccessAttempt delete event.

        :param instance: axes.models.AccessAttempt instance that was deleted
        :return: None
        """

        cls.implementation.post_delete_access_attempt(instance, **kwargs)


@receiver(user_login_failed)
def handle_user_login_failed(*args, **kwargs):
    ProxyHandler.user_login_failed(*args, **kwargs)


@receiver(user_logged_in)
def handle_user_logged_in(*args, **kwargs):
    ProxyHandler.user_logged_in(*args, **kwargs)


@receiver(user_logged_out)
def handle_user_logged_out(*args, **kwargs):
    ProxyHandler.user_logged_out(*args, **kwargs)


@receiver(post_save, sender=AccessAttempt)
def handle_post_save_access_attempt(*args, **kwargs):
    ProxyHandler.post_save_access_attempt(*args, **kwargs)


@receiver(post_delete, sender=AccessAttempt)
def handle_post_delete_access_attempt(*args, **kwargs):
    ProxyHandler.post_delete_access_attempt(*args, **kwargs)
