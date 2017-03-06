Release Notes for Marathon BIG-IP Controller
============================================

v1.0.0
------

* Capabilities

  * Can manage multiple BIG-IP partitions in the following environments
    
    * Apache Mesos/Marathon
    * Mesosphere DC/OS Enterprise

  * Manages the following LTM resources for the BIG-IP partition(s)

    * Virtual Servers
    * Virtual Addresses
    * Pools
    * Pool Members
    * Nodes
    * Health Monitors
    * Application Services

  * Auth0-based authentication for DC/OS Enterprise

* Limitations

  * Command line parameter alternatives to the environment variables are not documented in the user guide.
  * Cannot share endpoints managed in the partition controlled by the Marathon BIG-IP Controller with endpoints managed in another partition.
  * iApp and virtual server parameters are not treated as being mutually exclusive. You should not specify both, otherwise the BIG-IP may be improperly configured.
  * The deployment of the controller will fail if the BIG-IP is not available when the controller starts.
  * Parameters other than IPAddress and Port (e.g. Connection Limit) specified in the iApp Pool Member Table apply to all members of the pool.
  * Health monitor timeout is not described in documentation
        ``timeout = (( maxConsecutiveFailures - 1) * intervalSeconds ) + timeoutSeconds + 1``

