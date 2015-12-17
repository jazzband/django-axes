from django.db import models
from django.utils import six

class CommonAccess(models.Model):
    user_agent = models.CharField(
        max_length=255,
        db_index=True,
    )

    ip_address = models.GenericIPAddressField(
        verbose_name='IP Address',
        null=True,
        db_index=True,
    )

    username = models.CharField(
        max_length=255,
        null=True,
        db_index=True,
    )

    # Once a user logs in from an ip, that combination is trusted and not
    # locked out in case of a distributed attack
    trusted = models.BooleanField(
        default=False,
        db_index=True,
    )

    http_accept = models.CharField(
        verbose_name='HTTP Accept',
        max_length=1025,
    )

    path_info = models.CharField(
        verbose_name='Path',
        max_length=255,
    )

    attempt_time = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        abstract = True
        ordering = ['-attempt_time']


class AccessAttempt(CommonAccess):
    get_data = models.TextField(
        verbose_name='GET Data',
    )

    post_data = models.TextField(
        verbose_name='POST Data',
    )

    failures_since_start = models.PositiveIntegerField(
        verbose_name='Failed Logins',
    )

    @property
    def failures(self):
        return self.failures_since_start

    def __unicode__(self):
        return six.u('Attempted Access: %s') % self.attempt_time


class AccessLog(CommonAccess):
    logout_time = models.DateTimeField(
        null=True,
        blank=True,
    )

    def __unicode__(self):
        return six.u('Access Log for %s @ %s') % (self.username, self.attempt_time)
