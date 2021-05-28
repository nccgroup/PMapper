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

from setuptools import setup, find_packages
import principalmapper

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='principalmapper',
    version=principalmapper.__version__,
    description='A Python script and library for analyzing an AWS account\'s use of IAM.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='AGPLv3',
    url='https://github.com/nccgroup/PMapper',
    author='Erik Steringer',
    author_email='erik.steringer@nccgroup.com',
    scripts=[],
    include_package_data=True,
    packages=find_packages(exclude=("tests", )),
    package_data={},
    python_requires='>=3.5, <4',  # assume Python 4 will break
    install_requires=['botocore', 'packaging', 'python-dateutil', 'pydot'],
    entry_points={
        'console_scripts': [
            'pmapper = principalmapper.__main__:main'
        ]
    },
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Security'
    ],
    keywords=[
        'AWS', 'IAM', 'Security', 'PMapper', 'principalmapper', 'Principal Mapper', 'NCC Group'
    ],
    zip_safe=False
)
