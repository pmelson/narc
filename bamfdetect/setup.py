#!/usr/bin/env python2

from distutils.core import setup

setup(name='bamfdetect',
      version='1.6.13',
      description='Identifies and extracts information from bots and other malware',
      author='Brian Wallace',
      author_email='bwall@ballastsecurity.net',
      url='https://github.com/bwall/bamfdetect',
      packages=['BAMF_Detect', 'BAMF_Detect.modules', 'BAMF_Detect.modules.common', 'BAMF_Detect.preprocessors',
                'BAMF_Detect.preprocessors.common', 'BAMF_Detect.postprocessors', 'BAMF_Detect.postprocessors.common'],
      package_data={"BAMF_Detect.modules": ["yara/*.yara"]},
      scripts=['bamfdetect'],
      install_requires=['pefile', 'yara', 'rarfile', 'pycrypto', 'pbkdf2'],
     )