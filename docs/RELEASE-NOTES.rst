Release Notes for F5 BIG-IP Controller for Marathon
===================================================

|release|
----------

Added Functionality
```````````````````
* Support for BIG-IP partitions with non-zero default route domains.
* Added build and version information to the User-Agent header of iControl REST requests to BIG-IP.
* Build and version information logged upon container startup.

Bug Fixes
`````````
* Adds correct Marathon healthCheck path to BIG-IP Health Monitor Send String :issues:`256`

Limitations
```````````
* If you are using F5-supported iapps, you must first install the
  latest release candidate of the iapp available at downloads.f5.com and
  manually switch to using the new version of the iapp.  For instance,
  the minimum version you need to use for the f5.http iapp is f5.http.v1.3.0rc3.
  This version is available in the package iapps-1.0.0.492.0.  Note that
  installing a new version of an iapp does not replace the existing version.

v1.1.1
------

Bug Fixes
`````````
* Supports API changes introduced with Marathon v1.5.2 :issues:`244`
* Gracefully handle the case when an app has no service ports (applies to DC/OS Virtual Networks)
* Removed immutable parameters from update operations, as BIG-IP v11.6.1 does not allow immutable parameters to be present in update operations.
* Added enhanced exception handling to catch invalid input configurations in CCCL.

v1.1.0
------

Added Functionality
```````````````````
* iApp and virtual server parameters are now mutually exclusive. This addresses a previous limitation in v1.0.0.
* Creates detached pools if virtual server bind addresses not specified.
* Container image size reduced from 321MB to 82MB.
* Can use local and non-local BIG-IP users.
* Supports multiple BIG-IP health monitors for each Marathon application Service Port.
* Wildcard (*) for F5_CC_PARTITIONS Configuration Parameter is no longer supported.

v1.0.0
------

Added Functionality
```````````````````
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

Limitations
```````````
* Command line parameter alternatives to the environment variables are not documented in the user guide.
* Cannot share endpoints managed in the partition controlled by the |mctlr-long| with endpoints managed in another partition.
* iApp and virtual server parameters are not treated as being mutually exclusive. You should not specify both, otherwise the BIG-IP may be improperly configured.
* The deployment of the controller will fail if the BIG-IP is not available when the controller starts.
* Parameters other than IPAddress and Port (e.g. Connection Limit) specified in the iApp Pool Member Table apply to all members of the pool.
* Health monitor timeout is not described in documentation
