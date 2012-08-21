from django.db import models
from django.conf import settings
from django.contrib.auth.models import User

FAILURES_DESC = 'Failed Logins'

#XXX TODO
# set unique by user_agent, ip
# make user agent, ip indexed fields

class AccessAttempt(models.Model):
    SUCCESS = 10
    FAILED = 20
    LOCKOUT = 30
    
    STATUS = (
        (SUCCESS, 'Successful'),
        (FAILED, 'Failed, below limit'),
        (LOCKOUT, 'Locked out, above limit'),
    )
    
    user_agent = models.CharField(max_length=255)
    ip_address = models.IPAddressField('IP Address')
    get_data = models.TextField('GET Data')
    post_data = models.TextField('POST Data')
    http_accept = models.CharField('HTTP Accept', max_length=255)
    path_info = models.CharField('Path', max_length=255)
    attempt_time = models.DateTimeField(auto_now_add=True)
    status = models.IntegerField(choices=STATUS, default=SUCCESS)
    user = models.ForeignKey(User,null=True)

    def save(self,*args,**kwargs):
        for line in self.post_data.split('\n'):
            tup = line.split('=')
            if tup[0] == 'username':
                try:
                    self.user = User.objects.get(username=tup[1])
                except User.DoesNotExist:
                    pass
                break
        return super(AccessAttempt,self).save(*args,**kwargs)

    def __unicode__(self):
        return u'Attempted Access: %s' % self.attempt_time

    class Meta:
        ordering = ['-attempt_time']
