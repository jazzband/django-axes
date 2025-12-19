#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="django-axes",
    description="Keep track of failed login attempts in Django-powered sites.",
    long_description="\n".join(
        [
            open("README.rst", encoding="utf-8").read(),
            open("CHANGES.rst", encoding="utf-8").read(),
        ]
    ),
    keywords="authentication django pci security",
    author=", ".join(
        [
            "Josh VanderLinden",
            "Philip Neustrom",
            "Michael Blume",
            "Alex Clark",
            "Camilo Nova",
            "Aleksi Hakli",
        ]
    ),
    author_email="security@jazzband.co",
    maintainer="Jazzband",
    maintainer_email="security@jazzband.co",
    url="https://github.com/jazzband/django-axes",
    project_urls={
        "Documentation": "https://django-axes.readthedocs.io/",
        "Source": "https://github.com/jazzband/django-axes",
        "Tracker": "https://github.com/jazzband/django-axes/issues",
    },
    license="MIT",
    package_dir={"axes": "axes"},
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    python_requires=">=3.10",
    install_requires=[
        "django>=4.2",
        "asgiref>=3.6.0",
    ],
    extras_require={
        "ipware": "django-ipware>=3",
    },
    include_package_data=True,
    packages=find_packages(exclude=["tests"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Environment :: Plugins",
        "Framework :: Django",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.2",
        "Framework :: Django :: 6.0",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Internet :: Log Analysis",
        "Topic :: Security",
        "Topic :: System :: Logging",
    ],
    zip_safe=False,
)
