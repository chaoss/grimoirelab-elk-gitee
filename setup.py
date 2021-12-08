# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2019 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#     Haiming Lin <lhming23@outlook.com>
#

import codecs
import os
import re

# Always prefer setuptools over distutils
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
readme_md = os.path.join(here, 'README.md')

# Get the package description from the README.md file
with codecs.open(readme_md, encoding='utf-8') as f:
    long_description = f.read()

setup(name="grimoire-elk-gitee",
      description="GrimoireLab library to produce gitee indexes for ElasticSearch",
      long_description=long_description,
      long_description_content_type='text/markdown',
      url="https://github.com/X-lab2017/grimoirelab-elk-gitee",
      version="0.1.0",
      author="X-lab",
      author_email="lhming23@outlook.com",
      license="GPLv3",
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'Topic :: Software Development',
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5'],
      keywords="development repositories analytics for gitee",
      packages=['grimoire_elk_gitee', 'grimoire_elk_gitee.enriched', 'grimoire_elk_gitee.raw', 'grimoire_elk_gitee.identities'],
      entry_points={"grimoire_elk": "gitee = grimoire_elk_gitee.utils:get_connectors"},
      package_dir={'grimoire_elk_gitee.enriched': 'grimoire_elk_gitee/enriched'},
      package_data={'grimoire_elk_gitee.enriched': ['mappings/*.json']},
      python_requires='>=3.4',
      setup_requires=['wheel'],
      extras_require={'sortinghat': ['sortinghat'],
                      'mysql': ['PyMySQL']},
      tests_require=['httpretty==0.8.6'],
      test_suite='tests',
      install_requires=[
          'grimoire-elk>=0.72.0',
          'perceval>=0.9.6',
          'perceval-gitee>=0.1.0',
          'cereslib>=0.1.0',
          'grimoirelab-toolkit>=0.1.4',
          'sortinghat>=0.6.2',
          'graal>=0.2.2',
          'elasticsearch==6.3.1',
          'elasticsearch-dsl==6.3.1',
          'requests==2.26.0',
          'urllib3==1.26.5',
          'PyMySQL>=0.7.0',
          'pandas>=0.22.0,<=0.25.3',
          'geopy>=1.20.0',
          'statsmodels >= 0.9.0'
      ],
      zip_safe=False
      )
