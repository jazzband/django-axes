from django.apps import AppConfig


class FakeaccountappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'fakeaccountapp'

    def ready(self):
        import fakeaccountapp.signals
