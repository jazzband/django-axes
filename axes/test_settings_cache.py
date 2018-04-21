from __future__ import unicode_literals

from .test_settings import *  # pylint: disable=unused-wildcard-import

AXES_CACHE = 'axes'

CACHES = {
    'axes': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'
    }
}
