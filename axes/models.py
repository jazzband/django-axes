from django.db import models
#import signals
FAILURES_DESC = 'Failed Logins'

#XXX TODO
# set unique by user_agent, ip
# make user agent, ip indexed fields

class CommonAccess(models.Model):
    user_agent = models.CharField(max_length=255)
    ip_address = models.IPAddressField('IP Address', null=True)
    username = models.CharField(max_length=255, null=True)

    # Once a user logs in from an ip, that combination is trusted and not
    # locked out in case of a distributed attack
    trusted = models.BooleanField(default=False)
    http_accept = models.CharField('HTTP Accept', max_length=255)
    path_info = models.CharField('Path', max_length=255)
    attempt_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True
        ordering = ['-attempt_time']

class AccessAttempt(CommonAccess):
    get_data = models.TextField('GET Data')
    post_data = models.TextField('POST Data')
    failures_since_start = models.PositiveIntegerField(FAILURES_DESC)

    def __unicode__(self):
        return u'Attempted Access: %s' % self.attempt_time

    @property
    def failures(self):
        return self.failures_since_start

class AccessLog(CommonAccess):
    logout_time = models.DateTimeField(null=True, blank=True)

    def __unicode__(self):
        return u'Access Log for %s @ %s' % (self.username, self.attempt_time)
