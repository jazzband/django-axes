#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages

VERSION = '1.6.1'

setup(
    name='django-axes',
    version=VERSION,
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description=(
        open("README.rst").read() + '\n' +
        open("CHANGES.txt").read()),
    keywords='authentication, django, pci, security',
    author='Josh VanderLinden, Philip Neustrom, Michael Blume, Camilo Nova',
    author_email='codekoala@gmail.com',
    maintainer='Alex Clark',
    maintainer_email='aclark@aclark.net',
    url='https://github.com/django-pci/django-axes',
    license='MIT',
    package_dir={'axes': 'axes'},
    include_package_data=True,
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: Log Analysis',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        'Topic :: Security',
        'Topic :: System :: Logging',
    ],
    zip_safe=False,
)
