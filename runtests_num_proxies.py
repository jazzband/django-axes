#!/usr/bin/env python

from runtests import run_tests

if __name__ == '__main__':
    run_tests('axes.test_settings_num_proxies', [
        'axes.tests.GetIPNumProxiesTest',
    ])
