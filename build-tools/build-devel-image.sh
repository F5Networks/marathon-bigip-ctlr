#!/bin/bash

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/build-env.sh

# Build the builder image.
#
# This may download many build tools,
# build dependencies and so on.
#
# Adding editing tools is discouraged, since the pattern is to edit files
# outside a container.
#
# Runtime Dockerfile will add only the runtime dependencies

WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.builder $WKDIR
cp $CURDIR/entrypoint.builder.sh $WKDIR
cp $CURDIR/../marathon-*-requirements.txt $WKDIR

docker build --force-rm ${NO_CACHE_ARGS} \
  -t $BUILD_IMG_TAG \
  -f $WKDIR/Dockerfile.builder \
  $WKDIR

rm -rf docker-build.????

docker history $BUILD_IMG_TAG
echo "Built docker image $BUILD_IMG_TAG"
