from django.core.management.base import BaseCommand

from axes.utils import reset


class Command(BaseCommand):
    help = "Reset all access attempts and lockouts"

    def handle(self, *args, **options):
        count = reset()

        if count:
            self.stdout.write(f"{count} attempts removed.")
        else:
            self.stdout.write("No attempts found.")
