#!/bin/bash

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"
. $CURDIR/build-env.sh

# Setup a temp docker build context dir
WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.runtime $WKDIR
cp $CURDIR/../marathon-runtime-requirements.txt $WKDIR
cp $CURDIR/../marathon-bigip-ctlr.py $WKDIR
cp $CURDIR/../run $WKDIR

echo "Docker build context:"
ls -la $WKDIR

docker build --force-rm ${NO_CACHE_ARGS} \
  -t $IMG_TAG \
  -f $WKDIR/Dockerfile.runtime \
  $WKDIR

docker history $IMG_TAG
echo "Built docker image $IMG_TAG"

rm -rf docker-build.????
