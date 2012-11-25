from django.dispatch import Signal

user_locked_out = Signal(providing_args=['request', 'username'])