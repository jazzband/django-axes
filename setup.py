#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name='django-axes',
    version='1.3.6',
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description=(open('README.rst', 'r').read() + '\n' +
        open('CHANGES.txt', 'r').read()),
    keywords='django, security, authentication',
    author='Josh VanderLinden, Philip Neustrom, Michael Blume',
    author_email='codekoala@gmail.com',
    maintainer='Alex Clark',
    maintainer_email='aclark@aclark.net',
    url='https://github.com/django-security/django-axes',
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
        'Topic :: Internet :: Log Analysis',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        'Topic :: Security',
        'Topic :: System :: Logging',
    ],
    zip_safe=False,
)
