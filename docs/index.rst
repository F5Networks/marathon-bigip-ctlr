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
- Deploy F5 `iApps <https://devcentral.f5.com/iapps>`_ on the BIG-IP.


Guides
------

See the `F5 Marathon Container Connector user documentation </containers/v1/marathon/>`_.


Overview
------------

The F5 Marathon BIG-IP Controller is a Docker container that runs as a `Marathon Application`_. It watches the Marathon API for the creation/destruction of Marathon Apps; when it discovers an App with the F5 labels applied, it automatically updates the BIG-IP as follows:

- matches the Marathon App to the specified BIG-IP partition;
- creates a virtual server and pool for each `port-mapping <https://mesosphere.github.io/marathon/docs/ports.html>`_ ;
- creates a pool member for each App task and adds the member to the default pool;
- creates health monitors on the BIG-IP for pool members if the Marathon App has health checks configured.

Configuration Parameters
------------------------

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

To configure virtual servers on the BIG-IP for specific application service ports, define a port index in the configuration parameter.
In the table below, ``{n}`` refers to an index into the service-port mapping array, starting at 0.

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
| \F5_{n}_SSL_PROFILE   | string    | Optional  | n/a           | BIG-IP SSL profile to apply to an         |                                   |
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
| \F5_{n}_IAPP_TABLE_*                  | JSON      | Optional  | n/a           | Define iApp tables to apply to the Application Service.           |
|                                       | string    |           |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_TABLE_monitor__Monitors":``                          |
|                                       |           |           |               |  ``{"columns": ["Index", "Name", "Type", "Options"],``            |
|                                       |           |           |               |  ``"rows": [[0, "mon1", "tcp", "" ],[1, "mon2", "http", ""]]}"``  |
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
| \F5_{n}_IAPP_POOL_MEMBER_TABLE        | string    | Optional  | n/a           | Defines the name and layout of the pool member table in the iApp  |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | This entry can vary from iApp to iApp.                            |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | See F5_{n}_IAPP_POOL_MEMBER_TABLE section below.                  |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_POOL_MEMBER_TABLE_NAME   | string    | Optional  | n/a           | The iApp table entry containing pool member definitions.          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | This entry can vary from iApp to iApp.                            |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | DEPRECATED: Use F5_{n}_IAPP_POOL_MEMBER_TABLE instead.            |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_POOL_MEMBER_TABLE_NAME": "pool__members"``           |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+

F5_{n}_IAPP_POOL_MEMBER_TABLE
`````````````````````````````
You can use the ``F5_{n}_IAPP_POOL_MEMBER_TABLE`` option to describe the layout of the pool member table that the controller should configure.  It is a JSON object with these properties:

- ``name`` (required): A string that specifies the name of the table that contains the pool members.
- ``columns`` (required): An array that specifies the columns that the controller will configure in the pool member table, in order.

Each entry in ``columns`` is an object that has a ``name`` property and either a ``kind`` or ``value`` property:

- ``name`` (required): A string that specifies the column name.
- ``kind``: A string that tells the controller what property from the node to substitute.  The controller supports ``"IPAddress"`` and ``"Port"``.
- ``value``: A string that specifies a value.  The controller will not perform any substitution, it uses the value as specified.

For instance, if you configure an application with two tasks at 1.2.3.4:20123 and 1.2.3.5:20321, and you specify::

    F5_0_IAPP_POOL_MEMBER_TABLE = {
      "name": "pool__members",
      "columns": [
        {"name": "Port", "kind": "Port"},
        {"name": "IPAddress", "kind": "IPAddress"},
        {"name": "ConnectionLimit", "value": "0"}
      ]
    }

.. note:: This is the F5_0_IAPP_POOL_MEMBER_TABLE value represented as a JSON object.  Since Marathon accepts labels as strings, you must encode it as a string before entering it in the UI.

This would configure the following table on BIG-IP::

    {
      "name": "pool__members",
      "columnNames": [
        "Port",
        "IPAddress",
        "ConnectionLimit",
      ],
      "rows": [
        {
          "row": [
            "20121",
            "1.2.3.4",
            "0",
          ]
        },
        {
          "row": [
            "20321",
            "1.2.3.5",
            "0",
          ]
        },
      ]
    }

You will need to adjust this for the particular iApp template that you are using.  One way to discover the format is to configure an iApp manually from a template, and then check its configuration using ``tmsh list sys app service <appname>``.

Example Configuration Files
```````````````````````````
- `sample-marathon-application.json <./_static/config_examples/sample-marathon-application.json>`_
- `sample-iapp-marathon-application.json <./_static/config_examples/sample-iapp-marathon-application.json>`_

Usage Example
-------------

The F5 Marathon BIG-IP Controller configures objects on the BIG-IP in response to Marathon Applications and Tasks. For our example App -- `sample-marathon-application.json <./_static/config_examples/sample-marathon-application.json>`_ -- starting the F5 Marathon BIG-IP Controller with the following JSON in Marathon creates objects in the ``/mesos`` partition on the BIG-IP.

::

    {
      "id": "marathon-bigip-ctlr",
      "cpus": 0.5,
      "mem": 128.0,
      "instances": 1,
      "container": {
        "type": "DOCKER",
        "forcePullImage": true,
        "docker": {
          "image": "<path to Docker image>",
          "network": "BRIDGE"
        }
      },
      "env": {
        "MARATHON_URL": "<URL for Marathon API Service>",
        "F5_CC_PARTITIONS": "mesos",
        "F5_CC_BIGIP_HOSTNAME": "1.2.3.4",
        "F5_CC_BIGIP_USERNAME": "admin",
        "F5_CC_BIGIP_PASSWORD": "admin"
      }
    }

Run the command below on the BIG-IP to view the newly-created objects.

::

    user@(my-bigip)(Active)(/mesos)(tmos)# show ltm


.. _Enterprise DC/OS: https://mesosphere.com/product/
.. _Identity and Access Management API: https://docs.mesosphere.com/1.8/administration/id-and-access-mgt/iam-api/
.. _Marathon: https://mesosphere.github.io/marathon/
.. _Marathon Application: https://mesosphere.github.io/marathon/docs/application-basics.html

