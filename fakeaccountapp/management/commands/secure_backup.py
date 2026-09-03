from django.core.management.base import BaseCommand

from fakeaccountapp.backup import create_secure_backup, decrypt_secure_backup


class Command(BaseCommand):
    help = "Create or decrypt a secure encrypted database backup."

    def add_arguments(self, parser):
        parser.add_argument(
            "--decrypt",
            action="store_true",
            help="Print decrypted backup JSON to stdout.",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Create a backup even when current database dump is unchanged.",
        )

    def handle(self, *args, **options):
        if options["decrypt"]:
            self.stdout.write(decrypt_secure_backup().decode("utf-8"))
            return

        result = create_secure_backup(skip_duplicate=not options["force"])

        if result["created"]:
            self.stdout.write(self.style.SUCCESS(f"Secure backup created: {result['backup_path']}"))
        else:
            self.stdout.write(self.style.WARNING("Secure backup skipped: duplicate database dump."))
