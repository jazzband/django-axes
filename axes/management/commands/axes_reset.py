from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from axes.utils import reset


class Command(BaseCommand):
    args = ''
    help = ("resets any lockouts or failed login records. If called with an "
            "IP, resets only for that IP")

    def handle(self, *args, **kwargs):
        count = 0
        if args:
            for ip in args:
                count += reset(ip=ip)
        else:
            count = reset()

        if count:
            print '{0} attempts removed.'.format(count)
        else:
            print 'No attempts found.'
