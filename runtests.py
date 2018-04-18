#!/usr/bin/env python

from __future__ import unicode_literals

import os
import sys

import django
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test.utils import get_runner


def run_tests():
    os.environ['DJANGO_SETTINGS_MODULE'] = 'axes.test_settings'
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['axes.tests'])
    sys.exit(bool(failures))


def run_tests_cache():
    """Check that using a wrong cache backend (LocMemCache) throws correctly

    This is due to LocMemCache not working with AccessAttempt caching,
    please see issue https://github.com/jazzband/django-axes/issues/288
    """

    try:
        os.environ['DJANGO_SETTINGS_MODULE'] = 'axes.test_settings_cache'
        django.setup()
        print('Using LocMemCache as a cache backend does not throw')
        sys.exit(1)
    except ImproperlyConfigured:
        print('Using LocMemCache as a cache backend throws correctly')
        sys.exit(0)


if __name__ == '__main__':
    if 'cache' in sys.argv:
        run_tests_cache()
    run_tests()
