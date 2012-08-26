from axes.models import AccessAttempt


def reset(ip=None, username=None, silent=False):
    # no need to reset trusted records. If they fail, they go to untrusted
    params = {
        'trusted': False,
    }

    if ip:
        params['ip_address'] = ip

    attempts = AccessAttempt.objects.filter(**params)
    if username:
        if 'ip_address' in params:
            del params['ip_address']

        params['username'] = username
        attempts |= AccessAttempt.objects.filter(**params)

    if attempts:
        attempts.delete()
    else:
        if not silent:
            print 'No attempts found.'
