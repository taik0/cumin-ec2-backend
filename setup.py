#!/usr/bin/env python
"""Package configuration."""

from setuptools import find_packages, setup

install_requires = [
    'boto3>=1.7.8',
    'pyparsing==2.1.10',
    'cumin>=3.0.1'

]

setup(
    author='Daniel Ortiz',
    author_email='dortiz@devops.faith',
    description='cumin backend for AWS EC2.',
    install_requires=install_requires,
    keywords=['cumin', 'aws', 'ec2'],
    license='GPLv3+',
    name='cumin_backend_ec2',
    packages=find_packages(),
    version='0.1.0',
    platforms=['GNU/Linux', 'BSD', 'MacOSX'],
)
