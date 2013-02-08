from django.db import models
from django.utils.translation import ugettext as _
#import signals
FAILURES_DESC = 'Failed Logins'

#XXX TODO
# set unique by user_agent, ip
# make user agent, ip indexed fields

class CommonAccess(models.Model):
    user_agent = models.CharField(max_length=255, help_text=_('The user agent as reported by the users browser.'),
                                  verbose_name=_('User Agent'))
    ip_address = models.IPAddressField(verbose_name=_('IP Address'), null=True, 
                                       help_text=_('The IP Address the user accessed the system from.'))
    username = models.CharField(max_length=255, null=True, verbose_name=_('User Name'),
                                help_text='The user name supplied while attempting to access the system.')

    # Once a user logs in from an ip, that combination is trusted and not
    # locked out in case of a distributed attack
    trusted = models.BooleanField(default=False, help_text=_('A user is marked as trusted if they have\
     successfully logged into the system at least once.'), verbose_name=_('Trusted User'))
    http_accept = models.CharField(max_length=255, verbose_name=_('HTTP Accept'),
                                   help_text=_('The HTTP accept header value as sent by the connecting browser/agent.'))
    path_info = models.CharField(_('Path'), max_length=255, 
                                 help_text=_('The path the agent was/is attempting to access.'))
    attempt_time = models.DateTimeField(auto_now_add=True, verbose_name=_('Attempt Time'), 
                                        help_text=_('The time the user attempted to access the system.'))

    class Meta:
        abstract = True
        ordering = ['-attempt_time']

class AccessAttempt(CommonAccess):
    get_data = models.TextField(verbose_name=_('GET Data'), 
                                help_text=_('The GET HTTP data supplied in the URL of the last request.'))
    post_data = models.TextField(verbose_name=_('POST Data'),
                                 help_text=_('Any POST HTTP data supplied in the header.'))
    failures_since_start = models.PositiveIntegerField(_(FAILURES_DESC), help_text=_('The number of consecutive failures.\
      Set back to 0 after successful login by a trusted user.'))

    def __unicode__(self):
        return u'Attempted Access: %s' % self.attempt_time

    @property
    def failures(self):
        return self.failures_since_start
    
    class Meta():
        verbose_name = _('Access Attempt')

class AccessLog(CommonAccess):
    logout_time = models.DateTimeField(null=True, blank=True, verbose_name=_('Logout Time'),
                                       help_text=_('The date and time the user last logged out of the system.'))

    def __unicode__(self):
        return u'Access Log for %s @ %s' % (self.username, self.attempt_time)
    
    class Meta():
        verbose_name = 'Access Log'