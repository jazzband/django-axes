from django.db import models
from django.utils.translation import gettext_lazy as _


class AccessBase(models.Model):
    user_agent = models.CharField(_("User Agent"), max_length=255, db_index=True)

    ip_address = models.GenericIPAddressField(_("IP Address"), null=True, db_index=True)

    username = models.CharField(_("Username"), max_length=255, null=True, db_index=True)

    http_accept = models.CharField(_("HTTP Accept"), max_length=1025)

    path_info = models.CharField(_("Path"), max_length=255)

    attempt_time = models.DateTimeField(_("Attempt Time"), auto_now_add=True)

    class Meta:
        app_label = "axes"
        abstract = True
        ordering = ["-attempt_time"]


class AccessAttempt(AccessBase):
    get_data = models.TextField(_("GET Data"))

    post_data = models.TextField(_("POST Data"))

    failures_since_start = models.PositiveIntegerField(_("Failed Logins"))

    def __str__(self):
        return f"Attempted Access: {self.attempt_time}"

    class Meta:
        verbose_name = _("access attempt")
        verbose_name_plural = _("access attempts")


class AccessLog(AccessBase):
    logout_time = models.DateTimeField(_("Logout Time"), null=True, blank=True)

    def __str__(self):
        return f"Access Log for {self.username} @ {self.attempt_time}"

    class Meta:
        verbose_name = _("access log")
        verbose_name_plural = _("access logs")
