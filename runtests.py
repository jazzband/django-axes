#!/usr/bin/env python

import os
import sys

import django
from django.conf import settings
from django.test.utils import get_runner


def run_tests(settings_module, *modules):
    os.environ['DJANGO_SETTINGS_MODULE'] = settings_module
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(*modules)
    sys.exit(bool(failures))


if __name__ == '__main__':
    run_tests('axes.test_settings', [
        'axes.tests.AccessAttemptTest',
        'axes.tests.UtilsTest',
    ])
