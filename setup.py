#!/usr/bin/env python
from setuptools import setup, find_packages
# import os


# data_files = [(d, [os.path.join(d, f) for f in files])
#               for d, folders, files in os.walk(os.path.join('src', 'config'))]

DESC ='syslog etl that converts syslog messages using grok and saves them to mongo'
setup(name='syslog_svc_etl',
      version='1.0',
      description=DESC,
      author='adam pridgen',
      author_email='dso@thecoverofnight.com',
      install_requires=['toml', 'rule_chains', 'pygrok', 'pymongo', 'pytz'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      package_data={
           'syslog_svc_etl': [],
      },
      # data_files=data_files,
)
