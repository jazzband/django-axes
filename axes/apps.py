from logging import getLogger
from pkg_resources import get_distribution

from django import apps

from axes.conf import settings

log = getLogger(settings.AXES_LOGGER)


class AppConfig(apps.AppConfig):
    name = "axes"
    logging_initialized = False

    @classmethod
    def initialize(cls):
        """
        Initialize Axes logging and show version information.

        This method is re-entrant and can be called multiple times.
        It displays version information exactly once at application startup.
        """

        if not settings.AXES_ENABLED:
            return

        if not settings.AXES_VERBOSE:
            return

        if cls.logging_initialized:
            return
        cls.logging_initialized = True

        log.info("AXES: BEGIN LOG")
        log.info(
            "AXES: Using django-axes version %s",
            get_distribution("django-axes").version,
        )

        if settings.AXES_ONLY_USER_FAILURES:
            log.info("AXES: blocking by username only.")
        elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
            log.info("AXES: blocking by combination of username and IP.")
        else:
            log.info("AXES: blocking by IP only.")

    def ready(self):
        self.initialize()

        from axes import checks, signals  # noqa
