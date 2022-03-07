from django.core.management.base import BaseCommand

from axes.models import AccessAttempt


class Command(BaseCommand):
    help = "List access attempts"

    def handle(self, *args, **options):
        for obj in AccessAttempt.objects.all():
            self.stdout.write(
                f"{obj.ip_address}\t{obj.username}\t{obj.failures_since_start}"
            )
