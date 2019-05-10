#!/usr/bin/env python

"""Code for installing the Principal Mapper library and script."""
# TODO: write setup script

from setuptools import setup
import principalmapper

setup(
    name='pmapper',
    version=principalmapper.__version__,
    description='A Python script and library for analyzing an AWS account\'s use of IAM.',
    url='https://github.com/nccgroup/PMapper',
    author='Erik Steringer',
    author_email='erik.steringer@nccgroup.com',
    scripts=['pmapper.py'],
    packages=['principalmapper'],
    package_data={},
    install_requires=['botocore', 'packaging'],
    entry_points={
        'console_scripts': [
            'pmapper = principalmapper.__main__:main'
        ]
    },
    zip_safe=False
)
