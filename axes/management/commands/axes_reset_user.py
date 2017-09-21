from django.core.management.base import BaseCommand

from axes.utils import reset


class Command(BaseCommand):
    help = ("Resets any lockouts or failed login records. If called with an "
            "User name, resets only for that User name")

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **kwargs):
        count = 0
        count += reset(username=kwargs['username'])
        if kwargs['verbosity']:
            if count:
                self.stdout.write('{0} attempts removed.'.format(count))
            else:
                self.stdout.write('No attempts found.')
