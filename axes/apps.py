from django import apps


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from axes import signals
        signals.ProxyHandler.initialize()
