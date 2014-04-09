#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages

try:
    readme = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read() + '\n' + \
             open(os.path.join(os.path.dirname(__file__), 'CHANGES.rst')).read()
except:
    readme = ''

setup(
    name='django-axes',
    version='1.3.6',
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description=readme,
    keywords='django, security, authentication',
    author='Josh VanderLinden, Philip Neustrom, Michael Blume, Camilo Nova',
    author_email='codekoala@gmail.com',
    maintainer='Alex Clark',
    maintainer_email='aclark@aclark.net',
    url='https://github.com/django-security/django-axes',
    license='MIT',
    package_dir={'axes': 'axes'},
    include_package_data=True,
    install_requires=['six>=1.2'],
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
