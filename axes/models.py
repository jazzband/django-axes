from django.db import models
from django.conf import settings

if hasattr(settings, 'LOGIN_FAILURE_RESET'):
    FAILURES_DESC = 'Failed Logins Since Server Started'
else:
    FAILURES_DESC = 'Failed Logins'

class AccessAttempt(models.Model):
    user_agent = models.CharField(max_length=255)
    ip_address = models.IPAddressField('IP Address')
    get_data = models.TextField('GET Data')
    post_data = models.TextField('POST Data')
    http_accept = models.CharField('HTTP Accept', max_length=255)
    path_info = models.CharField('Path', max_length=255)
    failures_since_start = models.PositiveIntegerField(FAILURES_DESC)
    attempt_time = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return u'Attempted Access: %s' % self.attempt_time

    def failures(self):
        return self.failures_since_start

    class Meta:
        ordering = ['-attempt_time']