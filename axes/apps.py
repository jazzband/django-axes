# pylint: disable=import-outside-toplevel, unused-import

from logging import getLogger

from django import apps

from axes import __version__

log = getLogger(__name__)


class AppConfig(apps.AppConfig):
    default_auto_field = "django.db.models.AutoField"
    name = "axes"
    initialized = False

    @classmethod
    def initialize(cls):
        """
        Initialize Axes logging and show version information.

        This method is re-entrant and can be called multiple times.
        It displays version information exactly once at application startup.
        """

        if cls.initialized:
            return
        cls.initialized = True

        # Only import settings, checks, and signals one time after Django has been initialized
        from axes.conf import settings
        from axes import checks, signals

        # Skip startup log messages if Axes is not set to verbose
        if settings.AXES_VERBOSE:
            if callable(settings.AXES_LOCKOUT_PARAMETERS) or isinstance(
                settings.AXES_LOCKOUT_PARAMETERS, str
            ):
                mode = "blocking by parameters that are calculated in a custom callable"

            else:
                mode = "blocking by " + " or ".join(
                    [
                        (
                            param
                            if isinstance(param, str)
                            else "combination of " + " and ".join(param)
                        )
                        for param in settings.AXES_LOCKOUT_PARAMETERS
                    ]
                )

            log.info(
                "AXES: BEGIN version %s, %s",
                __version__,
                mode,
            )

    def ready(self):
        self.initialize()
