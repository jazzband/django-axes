from __future__ import print_function

from django.core.management.base import BaseCommand

from django.contrib.auth.models import User

def create_admin_user(username, password):
    """
    Create a user for testing the admin.

    :param string username:
    :param strring password:
    """
    u = User()
    u.username = username
    u.email = '{0}@dev.mail.example.com'.format(username)
    u.is_superuser = True
    u.is_staff = True
    u.set_password(password)

    try:
        u.save()
        print("Created user {0} with password {1}.".format(username, password))
    except Exception as e:
        #print("Failed to create user {0} with password {1}. Reason: {2}".format(username, password, str(e)))
        pass

class Command(BaseCommand):
    def handle(self, *args, **options):
        """
        Creates test data.
        """
        try:
            create_admin_user('admin', 'test')
        except Exception as e:
            pass

        try:
            create_admin_user('test', 'test')
        except Exception as e:
            pass
