#!/usr/bin/env python
# -*- coding: utf-8 -*-
import codecs
from setuptools import setup, find_packages

from axes import get_version

setup(
    name='django-axes',
    version=get_version(),
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description=(
        codecs.open("README.rst", encoding='utf-8').read() + '\n' +
        codecs.open("CHANGES.txt", encoding='utf-8').read()),
    keywords='authentication django pci security'.split(),
    author='Josh VanderLinden, Philip Neustrom, Michael Blume, Camilo Nova',
    author_email='codekoala@gmail.com',
    maintainer='Alex Clark',
    maintainer_email='aclark@aclark.net',
    url='https://github.com/jazzband/django-axes',
    license='MIT',
    package_dir={'axes': 'axes'},
    install_requires=['pytz', 'django-appconf', 'django-ipware'],
    include_package_data=True,
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: Log Analysis',
        'Topic :: Security',
        'Topic :: System :: Logging',
    ],
    zip_safe=False,
)
