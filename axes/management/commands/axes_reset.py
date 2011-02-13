from django.core.management.base import BaseCommand, CommandError
from axes.utils import reset

class Command(BaseCommand):
    args = ''
    help = ("resets any lockouts or failed login records. If called with an " +
            "IP, resets only for that IP")

    def handle(self, *args, **kwargs):
        if args:
            for ip in args:
                reset(ip)
        else:
            reset()
