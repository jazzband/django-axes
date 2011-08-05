from axes.models import AccessAttempt

def reset(ip=None, username=None, silent=False):
    if not ip:
        # no need to reset trusted records.  If they fail, they go to untrusted
        attempts = AccessAttempt.objects.filter(trusted=False)
        if attempts:
            attempts.delete()
        else:
            if not silent:
                print 'No attempts found.'
    else:
        try:
            # no need to reset trusted records.  If they fail, they go to untrusted
            attempts = AccessAttempt.objects.filter(ip_address=ip, trusted=False)
            if username:
                attempts = attempts | AccessAttempt.objects.filter(username=username, trusted=False)
        except:
            if not silent:
                print 'No matching attempt found.'
        else:
            attempts.delete()

