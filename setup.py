#!/usr/bin/env python

#from distutils.core import setup
from setuptools import setup, find_packages

setup(name='kaurna',
      version='0.1.0',
      description='Secure secret storage utilities.',
      author='Quinn Raskin',
      author_email='quinn@edofleini.com',
      url='www.edofleini.com',
      packages=find_packages('src'),#['kaurna'],
      package_dir={'kaurna': 'kaurna'},
      scripts=['scripts/kaurna'],
      test_suite='tests',
     )
