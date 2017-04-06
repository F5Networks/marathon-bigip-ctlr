#!/bin/bash

#
# This is the common environment for building the runtime image, and the
# reusable developer image
#
# The build uses two docker containers:
#  - Builder container: We build this container by copying in all the
#      source, installing any necessary tools, installing any dependencies,
#      compiling any native modules.
#      We'll run it and tell it to copy only the runtime artifacts to a data
#      volume container.
#  - Runtime container: This container is just the minimum base runtime
#      environment plus any artifacts from the builder that we need to actually
#      run the controller.  We leave all the tooling behind.

set -e

# CI Should set these variables
: ${CLEAN_BUILD:=false}
: ${IMG_TAG:=marathon-bigip-ctlr:latest}
: ${BUILD_IMG_TAG:=marathon-bigip-ctlr-devel:latest}

NO_CACHE_ARGS=""
if $CLEAN_BUILD; then
  NO_CACHE_ARGS="--no-cache"
fi
