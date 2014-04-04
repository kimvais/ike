#!/usr/bin/env python3

from distutils.core import setup

def readme():
    with open("README.rst") as f:
        return f.read()

setup(name='ike',
      version='0.0.4',
      description='Minimalistic Internet Key Exchange protocol v2 (RFC 5996) library',
      long_description=readme(),
      author='Kimmo Parviainen-Jalanko',
      author_email='k@77.fi',
      url='http://github.com/kimvais/ike/',
      packages=['ike']
     )
