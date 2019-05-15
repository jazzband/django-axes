from django.core.management.base import BaseCommand

from axes.helpers import cleanup_old_logged_data


class Command(BaseCommand):
    help = 'Clears all logged data older than "days".'

    def add_arguments(self, parser):
        parser.add_argument('days', type=int, help='Number of days after which all entries will be deleted')
        parser.add_argument('verbose', type=bool, help='Print results', nargs='?', default=False)

    def handle(self, *args, **options):
        cleanup_old_logged_data(options['days'], options['verbose'])
