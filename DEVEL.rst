Usage
-----

The 'run' script internally calls into script f5-marathon-lb.py which supports
the following command-line arguments:

.. code-block:: console

    usage: f5_marathon_lb.py [-h] [--longhelp]
                             [--marathon MARATHON [MARATHON ...]]
                             [--hostname HOSTNAME] [--username USERNAME]
                             [--password PASSWORD] [--partition PARTITION]
                             [--health-check] [--sse-timeout SSE_TIMEOUT]
                             [--verify-interval VERIFY_INTERVAL]
                             [--syslog-socket SYSLOG_SOCKET]
                             [--log-format LOG_FORMAT]
                             [--marathon-auth-credential-file MARATHON_AUTH_CREDENTIAL_FILE]

    If an arg is specified in more than one place, then commandline values override environment variables, which override defaults.

    optional arguments:
      -h, --help            show this help message and exit
      --longhelp            Print out configuration details (default: False)
      --marathon MARATHON [MARATHON ...], -m MARATHON [MARATHON ...]
                            [required] Marathon endpoint, eg. -m
                            http://marathon1:8080 http://marathon2:8080 [env var:
                            MARATHON_URL] (default: None)
      --hostname HOSTNAME   F5 BIG-IP hostname [env var: F5_CSI_BIGIP_HOSTNAME]
                            (default: None)
      --username USERNAME   F5 BIG-IP username [env var: F5_CSI_BIGIP_USERNAME]
                            (default: None)
      --password PASSWORD   F5 BIG-IP password [env var: F5_CSI_BIGIP_PASSWORD]
                            (default: None)
      --partition PARTITION
                            [required] Only generate config for apps which match
                            the specified partition. Use '*' to match all
                            partitions. Can use this arg multiple times to specify
                            multiple partitions [env var: F5_CSI_PARTITIONS]
                            (default: [])
      --health-check, -H    If set, respect Marathon's health check statuses
                            before adding the app instance into the backend pool.
                            [env var: F5_CSI_USE_HEALTHCHECK] (default: False)
      --sse-timeout SSE_TIMEOUT, -t SSE_TIMEOUT
                            Marathon event stream timeout [env var:
                            F5_CSI_SSE_TIMEOUT] (default: 30)
      --verify-interval VERIFY_INTERVAL, -v VERIFY_INTERVAL
                            Interval at which to verify the BIG-IP configuration.
                            [env var: F5_CSI_VERIFY_INTERVAL] (default: 30)
      --syslog-socket SYSLOG_SOCKET
                            Socket to write syslog messages to. Use '/dev/null' to
                            disable logging to syslog [env var:
                            F5_CSI_SYSLOG_SOCKET] (default: /var/run/syslog)
      --log-format LOG_FORMAT
                            Set log message format [env var: F5_CSI_LOG_FORMAT]
                            (default: %(asctime)s %(name)s: %(levelname) -8s:
                            %(message)s)
      --marathon-auth-credential-file MARATHON_AUTH_CREDENTIAL_FILE
                            Path to file containing a user/pass for the Marathon
                            HTTP API in the format of 'user:pass'. [env var:
                            F5_CSI_MARATHON_AUTH] (default: None)

.. important:: The **marathon**, **hostname**, **username**, **password**, and **partition** arguments are mandatory.

Use the ``--partition`` argument multiple times to specify multiple BIG-IP partitions (e.g. ``--partition tenant_a --partition tenant_b``).

.. topic:: Example

    .. code-block:: console

         f5-marathon-lb.py --marathon http://marathon1:8080 http://marathon2:8080 --hostname https://10.190.4.187 --username admin --password admin --partition tenant_a



Build and Launch via Docker
---------------------------

Follow the steps below to build and launch f5-marathon-lb as a Docker container.

.. topic:: 1. Build a Docker container:

    .. code-block:: shell

        docker build -t docker-registry.pdbld.f5net.com/darzins/f5-marathon-lb:latest .


.. topic:: 2. Push to a Docker registry:

    .. code-block:: shell

        docker push docker-registry.pdbld.f5net.com/darzins/f5-marathon-lb:latest

.. topic:: 3. Launch in Marathon:

    .. code-block:: shell

        curl -X POST -H "Content-Type: application/json" http://10.141.141.10:8080/v2/apps -d @f5-marathon-lb.json


In step 3, above, we use the command ``curl -X POST -H "Content-Type: application/json" http://10.141.141.10:8080/v2/apps -d @f5-marathon-lb.json``. In this command, "f5-marathon-lb.json" is the file that contains the details needed to deploy the container in Marathon. You can use either **args** or **env** variables in your json file to define the Marathon application labels.

.. topic:: Example "f5-marathon-lb.json" using **args**

    .. code-block:: javascript

        {
          "id": "f5-marathon-lb",
          "cpus": 0.5,
          "mem": 128.0,
          "instances": 1,
          "container": {
            "type": "DOCKER",
            "forcePullImage": true,
            "docker": {
              "image": "docker-registry.pdbld.f5net.com/darzins/f5-marathon-lb:latest",
              "network": "BRIDGE"
            }
          },
          "args": [
            "--marathon", "http://10.141.141.10:8080",
            "--partition", "mesos_1",
            "--hostname", "10.128.1.145",
            "--username", "admin",
            "--password", "default"
          ]
        }

\

.. topic:: Example "f5-marathon-lb.json" using **env** variables

    .. code-block:: javascript

        {
          "id": "f5-mlb",
          "cpus": 0.5,
          "mem": 128.0,
          "instances": 1,
          "container": {
            "type": "DOCKER",
            "forcePullImage": true,
            "docker": {
              "image": "docker-registry.pdbld.f5net.com/velcro/f5-marathon-lb:latest",
              "network": "BRIDGE"
            }
          },
          "env": {
            "F5_CSI_USE_SSE": "True",
            "MARATHON_URL": "http://10.141.141.10:8080",
            "F5_CSI_PARTITIONS": "[mesos_1, mesos_test]",
            "F5_CSI_BIGIP_HOSTNAME": "10.128.1.145",
            "F5_CSI_BIGIP_USERNAME": "admin",
            "F5_CSI_BIGIP_PASSWORD": "default"
          }
        }


