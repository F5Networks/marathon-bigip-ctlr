#!/usr/bin/env python
#
# Copyright 2017 F5 Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Standard python packaging script.

This module allows us to install the bigip controller system tests via pip.
"""

import os

from setuptools import setup, find_packages


VERSION = "0.1.0a1"


# - This hack is here to avoid having to use "dependency_links" strings that
#   are pinned to a specific version of the target package.
# - It can be removed when our test tool dependencies are moved to pypi
#   because the pin-to-a-specific-version issue is only an issue with
#   non-pypi packages (eg. when installing from private git repos).
os.system("pip install -r requirements.txt")

setup(
    name="systest_f5mlb",
    version=VERSION,
    description="System tests for the bigip controller component.",
    packages=find_packages(exclude=["docs"]),
    install_requires=[
        "systest-common>0,<1",
    ],
    entry_points={},
    package_data={'': [".pytest.rootdir", "*.tmpl"]}
)
