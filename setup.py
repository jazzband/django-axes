#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import axes

setup(
    name='django-axes',
    version=axes.get_version(),
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description=open('README.rst', 'r').read(),
    keywords='django, security, authentication',
    author='Josh VanderLinden, Philip Neustrom, Michael Blume',
    author_email='codekoala@gmail.com',
    url='http://bitbucket.org/codekoala/django-axes/',
    license='MIT',
    package_dir={'axes': 'axes'},
    include_package_data=True,
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: Log Analysis',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        'Topic :: Security',
        'Topic :: System :: Logging',
    ],
    zip_safe=False,
)
