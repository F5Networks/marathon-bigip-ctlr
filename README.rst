.. raw:: html

   <!--
   Copyright 2015-2016 F5 Networks Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   -->


F5 Container Service Connector for Mesos
========================================

|Build Status|

Introduction
------------

The F5® Container Service Connector™ (CSC) for `Mesos <https://mesos.apache.org/>`_ provides an integration for the `Marathon <https://github.com/mesosphere/marathon>`_ orchestration environment that makes L4-L7 services available to users deploying miscroservices-based applications in a containerized infrastructure.

Documentation
-------------

Documentation is published on Read the Docs, at http://<project_name>.readthedocs.io.

Compatibility
-------------

See the `Releases and Support Matrix <#>`_ for more information.

Installation
------------

Please see the `documentation <http://<project_name.readthedocs.io>`_ for installation instructions.

For Developers
--------------

Contributing
````````````
If you are interested in contributing to this project, please see `Contributing <CONTRIBUTING.md>`_.

Filing Issues
`````````````

If you find an issue, we would love to hear about it. Please open a new `issue <#>`_ for each bug you'd like to report or feature you'd like to request. Please be specific, and include as much information about your environment and the issue as possible.

Test
````
Provide relevant testing requirements for this project.

Unit Tests
~~~~~~~~~~

steps for running unit tests

Style Checks
~~~~~~~~~~~~

appropriate style checks

Project Setup
`````````````

Gitlab F5MLB project:
git@bldr-git.int.lineratesystes.com:velcro/f5-marathon-lb.git

Manual environment setup
~~~~~~~~~~~~~~~~~~~~~~~~

Python requirements should be installed into a virtualenv. Follow these links for more in-depth discussion of dependency management via `Virtualenv <https://virtualenv.pypa.io/en/stable/>`_ and this `How-to Guide <http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_.

To test, format, and lint this project; install these packages: flake8, flake8_docstrings, and mock.

To check formatting and lint: ``flake8 --exclude=docs/ ./``.

To run unit tests: ``python -m unittest discover -v``.

.. code-block:: bash

    # First create and activate a virtualenv according to provided links
    sudo apt-get update
    sudo apt-get install gcc git python python-dev python-pip
    git clone [gitlab F5MLB project]
    cd f5-marathon-lb
    pip install -r requirements.txt
    pip install flake8 flake8_docstrings mock

Docker environment setup
~~~~~~~~~~~~~~~~~~~~~~~~

1. Install docker. For example, `Docker for Mac <https://docs.docker.com/engine/installation/mac/>`_
2. Build the docker images used for development (f5mlb-devel):
   ```make devel-image```
3. The ``run-in-docker.sh`` script can be used to run any command in a devel
   container, almost as if you ran it locally. For example, to run tests:
   ``./scripts/run-in-docker.sh make release``


Copyright
---------

Copyright 2015-2016 F5 Networks Inc.

Support
-------

See `Support <SUPPORT.rst>`_.

License
-------

appropriate license

Contributor License Agreement
`````````````````````````````

information about and link to the F5 CLA for the project

