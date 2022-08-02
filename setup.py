#!/usr/bin/env python
"""Navigator-Session.

    Asynchronous library for managing user-specific data into a session object, used by Navigator.
See:
https://github.com/phenobarbital/navigator-session
"""
from os import path
from setuptools import find_packages, setup


def get_path(filename):
    return path.join(path.dirname(path.abspath(__file__)), filename)


def readme():
    with open(get_path('README.md')) as readme:
        return readme.read()


with open(get_path('navigator_session/version.py')) as meta:
    exec(meta.read())

setup(
    name="navigator-session",
    version=__version__,
    python_requires=">=3.9.0",
    url="https://github.com/phenobarbital/navigator-session",
    description=__description__,
    keywords=['asyncio', 'session', 'aioredis', 'aiomcache', 'cassandra'],
    platforms=['POSIX'],
    long_description=readme(),
    long_description_content_type='text/markdown',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Environment :: Web Environment",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Database :: Front-Ends",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Framework :: AsyncIO",
        "Framework :: aiohttp",
    ],
    author=__author__,
    author_email=__author_email__,
    packages=find_packages(exclude=["contrib", "docs", "tests"]),
    license=__license__,
    setup_requires=[
        "wheel==0.37.1",
        "Cython==0.29.32",
        "numpy==1.23.1",
        "asyncio==3.4.3",
        "cchardet==2.1.7",
        "cpython==0.0.6"
    ],
    install_requires=[
        "wheel==0.37.1",
        "cpython==0.0.6",
        "Cython==0.29.32",
        "numpy==1.23.1",
        "cryptography==37.0.4",
        "PyNaCl==1.5.0",
        "aiohttp==3.8.1",
        "uvloop==0.16.0",
        "asyncio==3.4.3",
        "cchardet==2.1.7",
        "rapidjson==1.0.0",
        "jsonpickle==2.2.0",
        'yarl==1.7.2',
        'wrapt==1.14.1',
        "python-rapidjson>=1.8",
        'typing_extensions==4.3.0',
        'urllib3==1.26.11',
        "async-generator==1.10",
        "charset-normalizer>=2.0.7",
        "redis==4.3.4",
        "aioredis==2.0.1",
        "hiredis==2.0.0",
        "aiomcache==0.7.0",
        "navconfig>=0.9.2"
    ],
    tests_require=[
        'pytest>=6.0.0',
        'pytest-asyncio==0.19.0',
        'pytest-xdist==2.5.0',
        'pytest-assume==2.4.3'
    ],
    test_suite='tests',
    project_urls={  # Optional
        "Source": "https://github.com/phenobarbital/navigator-session",
        "Funding": "https://paypal.me/phenobarbital",
        "Say Thanks!": "https://saythanks.io/to/phenobarbital",
    },
)
