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

.. code-block:: bash

    $ sudo apt-get update
    $ sudo apt-get install gcc git python python-dev python-pip
    $ git clone [gitlab F5MLB project]
    $ cd f5-marathon-lb
    # Install python requirements using sudo or create a virtualenv workspace.
    $ sudo pip install -r requirements.txt
    # The gitlab-ci unit-test target will validate source code against 'flake8'
    # and flake8_docstrings. To prevent failures you can install and run:
    #   flake8 --exclude=docs/ ./
    # from the project directory.
    $ sudo pip install flake8 flake8_docstrings
    # The gitlab-ci unit-test target will run pytest unit tests. The unit tests
    # depend on the 'mock' module. To prevent failures you can install and run:
    #   python -m unittest discover -v
    # from the project directory.
    $ sudo pip install mock

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
