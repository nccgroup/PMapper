#!/usr/bin/env python

"""Code for installing the Principal Mapper library and script."""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

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
    install_requires=['botocore', 'packaging', 'python-dateutil', 'pydot'],
    entry_points={
        'console_scripts': [
            'pmapper = principalmapper.__main__:main'
        ]
    },
    zip_safe=False
)
