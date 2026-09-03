from django.conf import settings
from django.core.management.base import BaseCommand

from fakeaccountapp.certificates import generate_local_ca_cert


class Command(BaseCommand):
    help = "Generate OpenSSL CA and server certificate files for local HTTPS."

    def add_arguments(self, parser):
        parser.add_argument("--common-name", default="localhost")
        parser.add_argument("--days", type=int, default=365)
        parser.add_argument("--output-dir", default=str(settings.BASE_DIR / "certs"))
        parser.add_argument(
            "--ip",
            action="append",
            dest="ip_addresses",
            help="Additional private IP address to include in the server certificate SAN. Can be used multiple times.",
        )

    def handle(self, *args, **options):
        paths = generate_local_ca_cert(
            output_dir=options["output_dir"],
            common_name=options["common_name"],
            valid_days=options["days"],
            ip_addresses=options["ip_addresses"],
        )
        self.stdout.write(self.style.SUCCESS(f"Certificate generator: {paths['generator']}"))
        self.stdout.write(self.style.SUCCESS(f"Generated server certificate: {paths['server_cert']}"))
        self.stdout.write(self.style.SUCCESS(f"Generated server key: {paths['server_key']}"))
        if paths["ip_addresses"]:
            self.stdout.write(self.style.SUCCESS(f"Included private IP SANs: {', '.join(paths['ip_addresses'])}"))
        else:
            self.stdout.write(self.style.WARNING("No private IP addresses were detected for SAN. Use --ip to add one manually."))
        self.stdout.write(self.style.WARNING(f"Trust this CA in your OS/browser to remove HTTPS warnings: {paths['ca_cert']}"))
