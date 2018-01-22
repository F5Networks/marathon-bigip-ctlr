F5 BIG-IP Controller for Marathon
=================================

|Slack|

.. toctree::
    :hidden:
    :maxdepth: 2

    RELEASE-NOTES
    /_static/ATTRIBUTIONS

The |mctlr-long| is a `Marathon Application`_ that manages F5 BIG-IP `Local Traffic Manager <https://f5.com/products/big-ip/local-traffic-manager-ltm>`_ (LTM) services.

|release-notes|

|attributions|

:fonticon:`fa fa-download` :download:`Attributions.md </_static/ATTRIBUTIONS.md>`

Features
--------

- Dynamically create, manage, and destroy BIG-IP objects.
- Authenticate to `Enterprise DC/OS`_ via the `Identity and Access Management API`_.
- Deploy F5 `iApps`_ on the BIG-IP.

Guides
------

See the |mctlr-long| `user documentation`_.

Overview
--------

The |mctlr-long| is a Docker container that runs as a `Marathon Application`_. It watches the Marathon API for the creation/destruction of Marathon Apps; when it discovers an App with the F5 labels applied, it automatically updates the BIG-IP as follows:

- matches the Marathon App to the specified BIG-IP partition;
- creates a virtual server and pool for each `port-mapping`_;
- creates a pool member for each App task and adds the member to the default pool;
- creates health monitors on the BIG-IP for pool members if the Marathon App has health checks configured.

.. danger::
 
   The |mctlr-long| monitors the BIG-IP partition it manages for configuration changes. If it discovers changes, the Controller reapplies its own configuration to the BIG-IP system.
   
   F5 does not recommend making configuration changes to objects in any partition managed by the |mctlr-long| via any other means (for example, the configuration utility, TMOS, or by syncing configuration with another device or service group). Doing so may result in disruption of service or unexpected behavior.

.. _config parameters:

Configuration Parameters
------------------------

+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| Parameter                         | Type      | Required  | Default       | Description                   | Allowed Values    |
+===================================+===========+===========+===============+===============================+===================+
| MARATHON_URL                      | string    | Required  | n/a           | the Marathon URL              |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_BIGIP_HOSTNAME              | string    | Required  | n/a           | BIG-IP hostname / IP address  |                   |
+-----------------------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| F5_CC_BIGIP_USERNAME              | bar       | Required  | n/a           | BIG-IP username [#username]_  |                   |
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

.. _app labels:

Application Labels
------------------

F5 application labels are key-value pairs that correspond to BIG-IP configuration options.

To configure virtual servers on the BIG-IP device for specific application service ports, define a port index in the configuration parameter.
In the table below, ``{n}`` refers to an index into the service-port mapping array, starting at 0.

|mctlr-long| supports two BIG-IP configuration modes (normal and iApp), with a different set of application labels for each mode. Normal mode directly configures the virtual servers via the application labels, whereas iApp mode configures virtual servers via an iApp template.

The Controller uses the following naming structure when creating BIG-IP objects:

``<marathon_application_path>_<application-port>``


.. _app labels normal:

Application Labels for Normal Mode
``````````````````````````````````
Use the following application labels to deploy virtual servers on the BIG-IP.

+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+
| Parameter             | Type      | Required  | Default       | Description                               | Allowed Values                          |
+=======================+===========+===========+===============+===========================================+=========================================+
| F5_PARTITION          | string    | Required  | n/a           | BIG-IP partition in which to create       |                                         |
|                       |           |           |               | objects; cannot be "Common"               |                                         |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+
| \F5_{n}_BIND_ADDR     | string    | Optional  | n/a           | IP address of the App service [#ba]_      |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | Example:                                  |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | ``"F5_0_BIND_ADDR": "10.0.0.42"``         |                                         |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+
| \F5_{n}_PORT          | string    | Required  | n/a           | Service port to use for communications    |                                         |
|                       |           |           |               | with the BIG-IP                           |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | Overrides the ``servicePort``             |                                         |
|                       |           |           |               | configuration parameter.                  |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | Example: ``"F5_0_PORT": "80"``            |                                         |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+
| \F5_{n}_MODE          | string    | Optional  | tcp           | Connection mode                           | http, tcp                               |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | Example: ``"F5_0_MODE": "http"``          |                                         |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+
| \F5_{n}_BALANCE       | string    | Optional  | round-robin   | Load-balancing algorithm [#lb]_           | See supported                           |
|                       |           |           |               |                                           | `loadBalancingMode options in f5-cccl`_ |
|                       |           |           |               | Example:                                  |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | ``"F5_0_BALANCE":``                       |                                         |
|                       |           |           |               | ``"least-connections-member"``            |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               |                                           |                                         |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+
| \F5_{n}_SSL_PROFILE   | string    | Optional  | n/a           | BIG-IP SSL profile to apply to an         | Any BIG-IP client SSL profile           |
|                       |           |           |               | HTTPS virtual server                      |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | Example:                                  |                                         |
|                       |           |           |               |                                           |                                         |
|                       |           |           |               | ``"F5_0_SSL_PROFILE": "Common/clientssl"``|                                         |
|                       |           |           |               |                                           |                                         |
+-----------------------+-----------+-----------+---------------+-------------------------------------------+-----------------------------------------+

.. note::

   If you don't define ``F5_{n}_BIND_ADDR``, the Controller will create BIG-IP `pools without virtual servers`_. In such cases, **you should already have a BIG-IP virtual server** that handles client connections configured with an iRule or local traffic policy that can forward the request to the correct pool.

   You can `use an IPAM system`_ to populate the ``F5_{n}_BIND_ADDR`` label. When the Controller discovers a valid ``F5_{n}_BIND_ADDR`` for an Application, it creates a BIG-IP virtual server for the App with the specified the IP address.

.. _app labels iapp:

Application Labels for iApp Mode
````````````````````````````````

Use iApp application labels to deploy iApp templates on the BIG-IP.

+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| Parameter                             | Type      | Required  | Default       | Description                                                       |
+=======================================+===========+===========+===============+===================================================================+
| F5_PARTITION                          | string    | Required  | n/a           | BIG-IP partition in which to create                               |
|                                       |           |           |               | objects; cannot be "Common"                                       |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_TEMPLATE                 | string    | Required  | n/a           | The iApp template you want to use to create the Application       |
|                                       |           |           |               | Service; must already exist on the BIG-IP.                        |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_TEMPLATE": "/Common/f5.http"``                       |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_OPTION_*                 | string    | iApp      | n/a           | Define iApp configuration options to apply to the Application     |
|                                       |           | template- |               | Service.                                                          |
|                                       |           | specific  |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_OPTION_description": "This is a test iApp"``         |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_TABLE_*                  | JSON      | iApp      | n/a           | Define iApp tables to apply to the Application Service.           |
|                                       | string    | template- |               |                                                                   |
|                                       |           | specific  |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_TABLE_monitor__Monitors":``                          |
|                                       |           |           |               |  ``{"columns": ["Index", "Name", "Type", "Options"],``            |
|                                       |           |           |               |  ``"rows": [[0, "mon1", "tcp", "" ],[1, "mon2", "http", ""]]}"``  |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_VARIABLE_*               | string    | iApp      | n/a           | Define the variables the iApp needs to create the Service.        |
|                                       |           | template- |               |                                                                   |
|                                       |           | specific  |               | Use an existing resource,or tell the service to create a new one  |
|                                       |           |           |               | using ``#create_new#``.                                           |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | Examples:                                                         |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_VARIABLE_pool__addr": "10.128.10.240"``              |
|                                       |           |           |               | ``"F5_0_IAPP_VARIABLE_pool__pool_to_use": "#create_new#"``        |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_POOL_MEMBER_TABLE        | string    | Required  | n/a           | Defines the name and layout of the pool member table in the iApp  |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | This entry can vary from iApp to iApp.                            |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | See \F5_{n}_IAPP_POOL_MEMBER_TABLE section below.                 |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+
| \F5_{n}_IAPP_POOL_MEMBER_TABLE_NAME   | string    | Required  | n/a           | The iApp table entry containing pool member definitions.          |
|                                       |           | if \F5_{n}|               |                                                                   |
|                                       |           | _IAPP_POOL|               | This entry can vary from iApp to iApp.                            |
|                                       |           | _MEMBER_  |               |                                                                   |
|                                       |           | TABLE is  |               | DEPRECATED: Use \F5_{n}_IAPP_POOL_MEMBER_TABLE instead.           |
|                                       |           | unset     |               |                                                                   |
|                                       |           |           |               | Example:                                                          |
|                                       |           |           |               |                                                                   |
|                                       |           |           |               | ``"F5_0_IAPP_POOL_MEMBER_TABLE_NAME": "pool__members"``           |
+---------------------------------------+-----------+-----------+---------------+-------------------------------------------------------------------+

.. _iapp pool member table:

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

.. _conf examples:

Example Configuration Files
---------------------------

- :fonticon:`fa fa-download` :download:`sample-marathon-application.json </_static/config_examples/sample-marathon-application.json>`
- :fonticon:`fa fa-download` :download:`sample-iapp-marathon-application.json </_static/config_examples/sample-iapp-marathon-application.json>`

Usage Example
-------------

The |mctlr-long| configures objects on the BIG-IP in response to Marathon Applications and Tasks.
For the example App -- :ref:`sample-marathon-application.json <sample-marathon-app>` -- starting the |mctlr-long| with the following JSON creates objects in the ``/mesos`` partition on the BIG-IP device.

.. code-block:: JSON

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

.. code-block:: console

   user@(my-bigip)(Active)(/mesos)(tmos)# show ltm

.. rubric:: **Footnotes:**
.. [#username] The controller requires the BIG-IP user account to have a defined role of ``Administrator``, ``Resource Administrator``, or ``Manager``. See `BIG-IP Users <https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/tmos-concepts-11-5-0/10.html>`_ for further details.
.. [#ba] The controller supports BIG-IP `route domain`_ specific addresses.
.. [#lb] The |mctlr| supports BIG-IP load balancing algorithms that do not require additional configuration parameters. You can view the full list of supported algorithms in the `f5-cccl schema <https://github.com/f5devcentral/f5-cccl/blob/03e22c4779ceb88f529337ade3ca31ddcd57e4c8/f5_cccl/schemas/cccl-ltm-api-schema.yml#L515>`_. See the `BIG-IP Local Traffic Management Basics user guide <https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-basics-13-0-0/4.html>`_ for information about each load balancing mode.
.. |Slack| image:: https://f5cloudsolutions.herokuapp.com/badge.svg
   :target: https://f5cloudsolutions.herokuapp.com
   :alt: Slack
.. _loadBalancingMode options in f5-cccl: https://github.com/f5devcentral/f5-cccl/blob/master/f5_cccl/schemas/cccl-ltm-api-schema.yml
