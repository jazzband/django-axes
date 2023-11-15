from django.core.management.base import BaseCommand

from axes.utils import reset


class Command(BaseCommand):
    help = "Reset all access attempts and lockouts for a given IP address and username"

    def add_arguments(self, parser):
        parser.add_argument("ip", type=str)
        parser.add_argument("username", type=str)

    def handle(self, *args, **options):
        count = reset(ip=options["ip"], username=options["username"])

        if count:
            self.stdout.write(f"{count} attempts removed.")
        else:
            self.stdout.write("No attempts found.")
