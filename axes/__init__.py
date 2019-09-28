from pkg_resources import get_distribution

default_app_config = "axes.apps.AppConfig"

__version__ = get_distribution("django-axes").version
