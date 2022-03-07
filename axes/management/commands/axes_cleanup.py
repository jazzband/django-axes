import datetime

from django.core.management.base import BaseCommand
from django.utils.timezone import utc

from axes.models import AccessAttempt, AccessLog


class Command(BaseCommand):
    """
    Find all logged entries from `AccessLog` and `AccessAttempt` which were created at least X days in the past
    """
    help = 'Clears all logged data older than "days".'

    def add_arguments(self, parser):
        parser.add_argument('days', type=int, help='Number of days after which all entries will be deleted')
        parser.add_argument('verbose', type=bool, help='Print results', nargs='?', default=False)

    def handle(self, *args, **options):
        # Fetch CLI params
        border_days = options['days']
        verbose = options['verbose']

        # Calculate border date
        border = utc.localize(datetime.datetime.utcnow() - datetime.timedelta(days=border_days))

        # Query records
        logs = AccessLog.objects.filter(attempt_time__lt=border)
        attempts = AccessAttempt.objects.filter(attempt_time__lt=border)

        # Optional output to shell
        if verbose:
            self.stdout.write('AXES: Deleted %s log(s) and %s attempt(s) for border date %s.' %
                              (logs.count(), attempts.count(), border.strftime('%Y-%m-%d')))

        # Delete records
        logs.delete()
        attempts.delete()
