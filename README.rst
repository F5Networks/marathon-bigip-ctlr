F5 Marathon LB (F5MLB)
======================

Introduction
------------

The F5MLB application allows users to manage F5® BIG-IP® devices in a `Mesos <https://mesos.apache.org/>`_ environment with `Marathon <https://github.com/mesosphere/marathon>`_.

Releases and Compatibility
--------------------------

See the F5 Container Integrations `Releases, Versioning, and Support Matrix <#>`_.

Documentation
-------------

Please refer to the `project documentation <docs/README.rst>`_ for installation and configuration instructions.

For Developers
--------------

If you are interested in contributing to this project, please see `Contributing <CONTRIBUTING.rst>`_.

To report an issue or suggest an enhancement, please open an `Issue <>`_.

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

Copyright 2015-2016, F5 Networks Inc.

Support
-------

See `Support <SUPPORT.rst>`_.


License
-------
tbd

Contributor License Agreement
`````````````````````````````

Individuals or business entities who contribute to this project must have completed and submitted the `F5 Contributor License Agreement <#`_ to <TBD>@f5.com prior to their code submission being included in this project.
