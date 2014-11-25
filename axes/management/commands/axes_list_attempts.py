from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from axes.models import AccessAttempt

class Command(BaseCommand):
    args = ''
    help = ("List login attempts")

    def handle(self, *args, **kwargs):
        for at in  AccessAttempt.objects.all():
            print ("%s %s %s" % (at.ip_address,  at.username, at.failures))

