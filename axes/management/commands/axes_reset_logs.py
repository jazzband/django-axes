from django.core.management.base import BaseCommand

from axes.handlers.proxy import AxesProxyHandler


class Command(BaseCommand):
    help = "Reset access log records older than given days."

    def add_arguments(self, parser):
        parser.add_argument(
            "--age",
            type=int,
            default=30,
            help="Maximum age for records to keep in days",
        )

    def handle(self, *args, **options):
        count = AxesProxyHandler.reset_logs(age_days=options["age"])
        if count:
            self.stdout.write(f"{count} logs removed.")
        else:
            self.stdout.write("No logs found.")
