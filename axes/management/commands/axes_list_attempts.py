from django.core.management.base import BaseCommand

from axes.models import AccessAttempt


class Command(BaseCommand):
    args = ''
    help = ('List registered login attempts')

    def handle(self, *args, **kwargs):
        for obj in AccessAttempt.objects.all():
            print('{ip}\t{username}\t{failures}'.format(
                ip=obj.ip_address,
                username=obj.username,
                failures=obj.failures,
            ))
