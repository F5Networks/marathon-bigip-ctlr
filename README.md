[![Build Status](https://travis-ci.org/F5Networks/marathon-bigip-ctlr.svg?branch=master)](https://travis-ci.org/F5Networks/marathon-bigip-ctlr) [![Slack](https://f5cloudsolutions.herokuapp.com/badge.svg)](https://f5cloudsolutions.herokuapp.com) [![Coverage Status](https://coveralls.io/repos/github/F5Networks/marathon-bigip-ctlr/badge.svg?branch=HEAD)](https://coveralls.io/github/F5Networks/marathon-bigip-ctlr?branch=HEAD)

F5 BIG-IP Controller for Marathon
=================================
**This GitHub repository has been archived and is read-only. This project is no longer actively maintained.**

The F5 BIG-IP Controller for Marathon makes F5 BIG-IP
[Local Traffic Manager](https://f5.com/products/big-ip/local-traffic-manager-ltm)
services available for applications defined in a
[Marathon](https://mesosphere.github.io/marathon/) environment.

Documentation
-------------

For instruction on how to use this component, see the
[docs](http://clouddocs.f5.com/products/connectors/marathon-bigip-ctlr/latest/) for
F5 BIG-IP Controller for Marathon.

For guides on this and other solutions for Marathon, see the
[F5 Marathon Solution Guides](http://clouddocs.f5.com/containers/latest/marathon).

Getting Help
------------

We encourage you to use the cc-marathon channel in our [f5CloudSolutions Slack workspace](https://f5cloudsolutions.herokuapp.com/) for discussion and assistance on this
controller. This channel is typically monitored Monday-Friday 9am-5pm MST by F5
employees who will offer best-effort support.

Contact F5 Technical support via your typical method for more time sensitive
changes and other issues requiring immediate support.

Running
-------

The official docker image is `f5networks/marathon-bigip-ctlr`.

Usually the controller is deployed in Marathon. However, the controller can be run locally for development testing.

```shell
docker run f5networks/marathon-bigip-ctlr <args>`
```

Building
--------

Note that these instructions will only work for internal users.

To checkout and build:

```shell
git clone https://github.com/f5networks/marathon-bigip-ctlr.git
cd marathon-bigip-ctlr
```

To build the docker image:

```shell
docker build -t IMG_TAG .
```

To build a docker image with those artifacts:

```shell
./build-tools/build-runtime-image.sh
```
