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


class AccessFailureLog(AccessBase):
    locked_out = models.BooleanField(
        _("Access lock out"), null=False, blank=True, default=False
    )

    def __str__(self):
        locked_out_str = " locked out" if self.locked_out else ""
        return f"Failed access: user {self.username}{locked_out_str} on {self.attempt_time} from {self.ip_address}"

    class Meta:
        verbose_name = _("access failure")
        verbose_name_plural = _("access failures")


class AccessAttempt(AccessBase):
    get_data = models.TextField(_("GET Data"))

    post_data = models.TextField(_("POST Data"))

    failures_since_start = models.PositiveIntegerField(_("Failed Logins"))

    def __str__(self):
        return f"Attempted Access: {self.attempt_time}"

    class Meta:
        verbose_name = _("access attempt")
        verbose_name_plural = _("access attempts")
        unique_together = [["username", "ip_address", "user_agent"]]


class AccessLog(AccessBase):
    logout_time = models.DateTimeField(_("Logout Time"), null=True, blank=True)
    session_hash = models.CharField(_("Session key hash (sha256)"), default="", blank=True, max_length=64)

    def __str__(self):
        return f"Access Log for {self.username} @ {self.attempt_time}"

    class Meta:
        verbose_name = _("access log")
        verbose_name_plural = _("access logs")
