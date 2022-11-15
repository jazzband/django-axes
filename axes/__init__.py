try:
    from importlib.metadata import version  # New in Python 3.8
except ImportError:
    from pkg_resources import get_distribution  # from setuptools, deprecated

    __version__ = get_distribution("django-axes").version
else:
    __version__ = version("django-axes")
