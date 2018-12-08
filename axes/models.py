from __future__ import unicode_literals

from django.db import models
from django.utils.translation import gettext_lazy as _


class CommonAccess(models.Model):
    user_agent = models.CharField(
        _('User Agent'),
        max_length=255,
        db_index=True,
    )

    ip_address = models.GenericIPAddressField(
        _('IP Address'),
        null=True,
        db_index=True,
    )

    username = models.CharField(
        _('Username'),
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
        _('HTTP Accept'),
        max_length=1025,
    )

    path_info = models.CharField(
        _('Path'),
        max_length=255,
    )

    attempt_time = models.DateTimeField(
        _('Attempt Time'),
        auto_now_add=True,
    )

    class Meta:
        app_label = 'axes'
        abstract = True
        ordering = ['-attempt_time']


class AccessAttempt(CommonAccess):
    get_data = models.TextField(
        _('GET Data'),
    )

    post_data = models.TextField(
        _('POST Data'),
    )

    failures_since_start = models.PositiveIntegerField(
        _('Failed Logins'),
    )

    @property
    def failures(self):
        return self.failures_since_start

    def __str__(self):
        return 'Attempted Access: %s' % self.attempt_time

    class Meta:
        verbose_name = _('access attempt')
        verbose_name_plural = _('access attempts')


class AccessLog(CommonAccess):
    logout_time = models.DateTimeField(
        _('Logout Time'),
        null=True,
        blank=True,
    )

    def __str__(self):
        return 'Access Log for %s @ %s' % (self.username, self.attempt_time)

    class Meta:
        verbose_name = _('access log')
        verbose_name_plural = _('access logs')
