F5 Marathon BIG-IP Controller
=============================

.. toctree::
    :hidden:
    :maxdepth: 2

The F5 Marathon BIG-IP Controller is a `Marathon Application`_ that manages F5 BIG-IP `Local Traffic Manager <https://f5.com/products/big-ip/local-traffic-manager-ltm>`_ (LTM) services.

Features
--------

- Dynamically create, manage, and destroy BIG-IP objects.
- Authenticate to `Enterprise DC/OS`_ via the `Identity and Access Management API`_.
- Authenticate to BIG-IP objects with existing BIG-IP SSL profiles.
- Deploy F5 `iApps <https://devcentral.f5.com/iapps>`_ on the BIG-IP.


Guides
------

The F5 Marathon BIG-IP Controller user documentation is available at `add link <#tbd>`_.

Getting Started
```````````````
- links
- to
- guides

Deployment
``````````
- links
- to
- guides

Troubleshooting
```````````````
- links coming soon

Architecture
------------

The F5 Marathon BIG-IP Controller is a Docker container that runs as a `Marathon Application`_. It watches the Marathon API for the creation/destruction of Marathon Apps; when it discovers an App with the F5 labels applied, it automatically updates the BIG-IP as follows:

- matches the Marathon App to the specified BIG-IP partition;
- creates a virtual server and pool for each `port-mapping <https://mesosphere.github.io/marathon/docs/ports.html>`_ ;
- creates a pool member for each App task and adds the member to the default pool;
- creates health monitors on the BIG-IP for pool members if the Marathon App has health checks configured.

Configuration Parameters
------------------------

The F5 Marathon BIG-IP Controller configurations must be valid JSON.

+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| Parameter                         | Type      | Required  | Default       | Description                   | Allowed Values    |
+===================================+===========+===========+===============+===============================+===================+
| MARATHON_URL                      | string    | Required  | n/a           | the Marathon URL              |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_BIGIP_HOSTNAME              | string    | Required  | n/a           | BIG-IP hostname / IP address  |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_BIGIP_USERNAME              | bar       | Required  | n/a           | BIG-IP username               |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_BIGIP_PASSWORD              | bar       | Required  | n/a           | BIG-IP password               |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_PARTITIONS                  | bar       | Required  | n/a           | BIG-IP partition to create    |                   |
|                                   |           |           |               | objects in                    |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_USE_HEALTHCHECK             | boolean   | Optional  | False         | Respect Marathon's health     | True, False       |
|                                   |           |           |               | check status when adding app  |                   |
|                                   |           |           |               | instance to backend pool      |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_SSE_TIMEOUT                 | integer   | Optional  | 30            | Marathon event stream timeout |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_MARATHON_CA_CERT            | integer   | Optional  | n/a           | CA certificate for Marathon   |                   |
|                                   |           |           |               | HTTPS connections             |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_VERIFY_INTERVAL             | integer   | Optional  | 30            | Inteval at which to verify    |                   |
|                                   |           |           |               | BIG-IP configurations         |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_LOG_FORMAT                  | string    | Optional  | %(asctime)s   | log message format            |                   |
|                                   |           |           | %(name)s:     |                               |                   |
|                                   |           |           | %(levelname)  |                               |                   |
|                                   |           |           | -8s:          |                               |                   |
|                                   |           |           | %(message)s   |                               |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_LOG_LEVEL                   | string    | Optional  | INFO          | log level                     | INFO, DEBUG,      |
|                                   |           |           |               |                               | ERROR             |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_MARATHON_AUTH               | string    | Optional  | n/a           | Path to file containing a     |                   |
|                                   |           |           |               | ``'user:pass'`` definition    |                   |
|                                   |           |           |               | for the Marathon HTTP API.    |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_DCOS_AUTH_CREDENTIALS       | string    | Optional  | n/a           | DC/OS service account         |                   |
|                                   |           |           |               | credentials                   |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_DCOS_AUTH_TOKEN             | string    | Optional  | n/a           | DC/OS ACS Token               |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+


Application Labels
------------------

F5 application labels are key-value pairs that correspond to BIG-IP configuration options.

To configure virtual servers on the BIG-IP for specific ports, define a port index in the configuration parameter.
In the table below, ``{n}`` refers to an index into the port mapping array, starting at 0.

+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+
| Parameter             | Type      | Required  | Default       | Description                               | Allowed Values                    |
+=======================+===========+===========+===============+===========================================+===================================+
| F5_PARTITION          | string    | Required  | n/a           | BIG-IP partition in which to create       |                                   |
|                       |           |           |               | objects; cannot be "Common"               |                                   |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+
| \F5_{n}_BIND_ADDR     | string    | Optional  | n/a           | IP address of the App service             |                                   |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | Example:                                  |                                   |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | ``"F5_0_BIND_ADDR": "10.0.0.42"``         |                                   |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+
| \F5_{n}_PORT          | string    | Optional  | n/a           | Service port to use for communications    |                                   |
|                       |           |           |               | with the BIG-IP                           |                                   |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | Overrides the ``servicePort``             |                                   |
|                       |           |           |               | configuration parameter.                  |                                   |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | Example: ``"F5_0_PORT": "80"``            |                                   |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+
| \F5_{n}_MODE          | string    | Optional  | tcp           | Connection mode                           | http, tcp                         |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | Example: ``"F5_0_MODE": "http"``          |                                   |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+
| \F5_{n}_BALANCE       | string    | Optional  | round-robin   | Load-balancing algorithm                  | - dynamic-ratio-member            |
|                       |           |           |               |                                           | - least-connections-member        |
|                       |           |           |               | Example:                                  | - observed-node                   |
|                       |           |           |               |                                           | - ratio-least-connections-node    |
|                       |           |           |               | ``"F5_0_BALANCE":``                       | - round-robin                     |
|                       |           |           |               | ``"least-connections-member"``            | - dynamic-ratio-node              |
|                       |           |           |               |                                           | - least-connections-node          |
|                       |           |           |               |                                           | - predictive-member               |
|                       |           |           |               |                                           | - ratio-member                    |
|                       |           |           |               |                                           | - weighted-least-connections-     |
|                       |           |           |               |                                           |   member                          |
|                       |           |           |               |                                           | - fastest-app-response            |
|                       |           |           |               |                                           | - least-sessions                  |
|                       |           |           |               |                                           | - predictive-node                 |
|                       |           |           |               |                                           | - ratio-node                      |
|                       |           |           |               |                                           | - weighted-least-connections-node |
|                       |           |           |               |                                           | - fastest-node                    |
|                       |           |           |               |                                           | - observed-member                 |
|                       |           |           |               |                                           | - ratio-least-connections-member  |
|                       |           |           |               |                                           | - ratio-session                   |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+
| \F5_{n}_SSL_PROFILE   | string    | Optional  | n/a           | BIG-IP SSL profile to use to access an    |                                   |
|                       |           |           |               | HTTPS virtual server                      |                                   |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | Example:                                  |                                   |
|                       |           |           |               |                                           |                                   |
|                       |           |           |               | ``"F5_0_SSL_PROFILE": "Common/clientssl"``|                                   |
|                       |           |           |               |                                           |                                   |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------+

iApps Application Labels
````````````````````````

Use iApps Application labels to deploy iApp templates on the BIG-IP.

+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| Parameter                             | Type      | Required  | Default       | Description                                                       |
+=======================================+===========+===========+===============+===================================================================+
| \F5_{n}_IAPP_TEMPLATE                 | string    | Optional  | n/a           | The iApp template you want to use to create the Application       |
|                                       |           |           |               | Service; must already exist on the BIG-IP.                        |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_TEMPLATE": "/Common/f5.http"``                       |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_OPTION_*                 | string    | Optional  | n/a           | Define iApp configuration options to apply to the Application     |
|                                       |           |           |               | Service.                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_OPTION_description": "This is a test iApp"``         |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_VARIABLE_*               | string    | Optional  | n/a           | Define the variables the iApp needs to create the Service.        |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Use an existing resource,or tell the service to create a new one  |
|                                       |           |           |               | using ``#create_new#``.                                           |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Examples:                                                         |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_VARIABLE_pool__addr": "10.128.10.240"``              |
|                                       |           |           |               | ``"F5_0_IAPP_VARIABLE_pool__pool_to_use": "#create_new#"``        |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_POOL_MEMBER_TABLE_NAME   | string    | Optional  | n/a           | The iApp table entry containing pool member definitions.          |
|                                       |           |           |               | This entry can vary from iApp to iApp.                            |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_POOL_MEMBER_TABLE_NAME": "pool__members"``           |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+


Example Configuration Files
```````````````````````````
- `sample-marathon-application.json <./_static/config_examples/sample-marathon-application.json>`_
- `sample-iApp-marathon-application.json <./_static/config_examples/sample-iApp-marathon-application.json>`_

Usage Example
-------------

The F5 Marathon BIG-IP Controller configures objects on the BIG-IP in response to Marathon Applications and Tasks. For our example App -- `sample-marathon-application.json <./_static/config_examples/sample-marathon-application.json>`_ -- running the command below on the Mesos master creates objects  in the ``/mesos`` partition on the BIG-IP.

::

   $ ./marathon-bigip-ctlr.py --hostname 1.2.3.4 --username admin --password admin --partition mesos


Run the command below on the BIG-IP to view the newly-created objects.

::

    user@(my-bigip)(Active)(/mesos)(tmos)# show ltm


API Endpoints
-------------

coming soon!

.. _Enterprise DC/OS: https://mesosphere.com/product/
.. _Identity and Access Management API: https://docs.mesosphere.com/1.8/administration/id-and-access-mgt/iam-api/
.. _Marathon: https://mesosphere.github.io/marathon/
.. _Marathon Application: https://mesosphere.github.io/marathon/docs/application-basics.html

