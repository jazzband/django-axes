#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup
import axes
import sys, os

def fullsplit(path, result=None):
    """
    Split a pathname into components (the opposite of os.path.join) in a
    platform-neutral way.
    """
    if result is None:
        result = []
    head, tail = os.path.split(path)
    if head == '':
        return [tail] + result
    if head == path:
        return result
    return fullsplit(head, [tail] + result)

packages, data_files = [], []
root_dir = os.path.dirname(__file__)
if root_dir != '':
    os.chdir(root_dir)
axes_dir = 'axes'

for path, dirs, files in os.walk(axes_dir):
    # ignore hidden directories and files
    for i, d in enumerate(dirs):
        if d.startswith('.'): del dirs[i]

    if '__init__.py' in files:
        packages.append('.'.join(fullsplit(path)))
    elif files:
        data_files.append((path, [os.path.join(path, f) for f in files]))

setup(
    name='django-axes',
    version=axes.get_version(),
    url='http://code.google.com/p/django-axes/',
    author='Josh VanderLinden',
    author_email='codekoala@gmail.com',
    license='MIT',
    packages=packages,
    data_files=data_files,
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description="""
django-axes is a very simple way for you to keep track of failed login attempts, both for the Django admin and for the rest of your site.  All you need to do is install the application, a middleware, and syncdb!
""",
    keywords='django, security, authentication',
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
    ]
)
