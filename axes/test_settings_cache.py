from __future__ import unicode_literals

from .test_settings import *

AXES_CACHE = 'axes'

CACHES = {
    'axes': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'
    }
}
