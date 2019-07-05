from django.core.management.base import BaseCommand
from django.utils import timezone

from axes.models import AccessLog

class Command(BaseCommand):
    help = 'Deletes all logs that are older than `age` days old.'

    def add_arguments(self, parser):
        parser.add_argument('age', type=int, help='In days.')

    def handle(self, *args, **options):
        limit_date = timezone.now().date() - timezone.timedelta(days=options['age'])
        to_be_deleted = AccessLog.objects.filter(attempt_time__gt=limit_date)

        self.stdout.write(f'{to_be_deleted.count()} logs will be deleted.')

        to_be_deleted.delete()
