from axes.models import AccessAttempt


def reset(ip=None, username=None):
    """Reset records that match ip or username, and
    return the count of removed attempts.
    """
    count = 0

    attempts = AccessAttempt.objects.all()
    if ip:
        attempts = attempts.filter(ip_address=ip)
    if username:
        attempts = attempts.filter(username=username)

    if attempts:
        count = attempts.count()
        attempts.delete()

    return count


def iso8601(value):
    """Returns datetime.timedelta translated to ISO 8601 formatted duration.
    """
    seconds = value.total_seconds()
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    date = '{:.0f}D'.format(days) if days else ''

    time_values = hours, minutes, seconds
    time_designators = 'H', 'M', 'S'

    time = ''.join(
        [('{:.0f}'.format(value) + designator)
        for value, designator in zip(time_values, time_designators)
        if value]
    )
    return u'P' + date + (u'T' + time if time else '')
