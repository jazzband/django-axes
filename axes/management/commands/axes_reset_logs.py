from django.core.management.base import BaseCommand
from django.utils import timezone

from axes.models import AccessLog


class Command(BaseCommand):
    help = 'Reset access log records older than given days.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--age',
            type=int,
            default=30,
            help='Maximum age for records to keep in days',
        )

    def handle(self, *args, **options):
        limit = timezone.now().date() - timezone.timedelta(days=options['age'])
        count, _ = AccessLog.objects.filter(attempt_time__lte=limit).delete()

        if count:
            self.stdout.write(f'{count} logs removed.')
        else:
            self.stdout.write('No logs found.')
