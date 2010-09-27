from axes.models import AccessAttempt

def reset(ip=None, silent=False):
    if not ip:
        attempts = AccessAttempt.objects.all()
        if attempts:
            for attempt in AccessAttempt.objects.all():
                attempt.delete()
        else:
            if not silent:
                print 'No attempts found.'
    else:
        try:
            attempt = AccessAttempt.objects.get(ip_address=ip)
        except:
            if not silent:
                print 'No matching attempt found.'
        else:
            attempt.delete()
