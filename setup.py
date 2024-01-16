import os
from setuptools import find_packages, setup
from trade_remedies_client import __author__, __email__
from trade_remedies_client.version import __version__

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='trade-remedies-client',
    version=__version__,
    packages=find_packages(),
    include_package_data=True,
    license='MIT',
    description='An API client for the Trade Remedies API',
    long_description=README,
    url='https://github.com/uktrade/trade-remedies-client',
    author=__author__,
    author_email=__email__,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 4.2',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    install_requires=[
        'Django',
        'requests',
        'django-cache-memoize',
    ]
)
