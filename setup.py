#!/usr/bin/env python3

from distutils.core import setup
from ike import __version__

def readme():
    with open("README.rst") as f:
        return f.read()


setup(name='ike',
      version='.'.join('{}'.format(x) for x in __version__),
      description='Minimalistic Internet Key Exchange protocol v2 (RFC 5996) library',
      long_description=readme(),
      author='Kimmo Parviainen-Jalanko',
      author_email='k@77.fi',
      url='http://github.com/kimvais/ike/',
      download_url='https://github.com/kimvais/ike/releases',
      packages=['ike'],
      classifiers=[
          'Classifier: Development Status :: 2 - Pre-Alpha',
          'Classifier: License :: OSI Approved :: MIT License',
          'Classifier: Operating System :: Unix',
          'Classifier: Programming Language :: Python :: 3.4',
          'Classifier: Topic :: Communications',
          'Classifier: Topic :: Internet',
          'Classifier: Topic :: Security',
          'Classifier: Topic :: Security :: Cryptography',
      ]
)
