from logging import getLogger

from django import apps
from pkg_resources import get_distribution

log = getLogger(__name__)


class AppConfig(apps.AppConfig):
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
        from axes.conf import settings  # noqa
        from axes import checks, signals  # noqa

        # Skip startup log messages if Axes is not set to verbose
        if settings.AXES_VERBOSE:
            log.info("AXES: BEGIN LOG")
            log.info(
                "AXES: Using django-axes version %s",
                get_distribution("django-axes").version,
            )

            if settings.AXES_ONLY_USER_FAILURES:
                log.info("AXES: blocking by username only.")
            elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
                log.info("AXES: blocking by combination of username and IP.")
            elif settings.AXES_LOCK_OUT_BY_USER_OR_IP:
                log.info("AXES: blocking by username or IP.")
            else:
                log.info("AXES: blocking by IP only.")

    def ready(self):
        self.initialize()
