#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='keyring-vault-backend',
    version='1.3.0',
    description='Hashicorp vault backend for python-keyring',
    author='Philipp Schmitt',
    author_email='philipp.schmitt@post.lu',
    url='https://github.com/pschmitt/keyring-vault-backend',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['hvac', 'keyring', 'requests']
)
