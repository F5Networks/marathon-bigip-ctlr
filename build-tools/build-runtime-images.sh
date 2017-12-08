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
cp $CURDIR/../common.py $WKDIR
cp $CURDIR/../run $WKDIR

NEXT_VERSION=$(./build-tools/version-tool version)
export BUILD_VERSION=${BUILD_VERSION:-$NEXT_VERSION}
export BUILD_INFO=$(./build-tools/version-tool build-info)
echo "{\"version\": \"${BUILD_VERSION}\", \"build\": \"${BUILD_INFO}\"}" \
  > $WKDIR/VERSION_BUILD.json 

echo "Docker build context:"
ls -la $WKDIR

VERSION_BUILD_ARGS=$(${CURDIR}/version-tool docker-build-args)
docker build --force-rm ${NO_CACHE_ARGS} \
  -t $IMG_TAG \
  --label BUILD_STAMP=$BUILD_STAMP \
  ${VERSION_BUILD_ARGS} \
  -f $WKDIR/Dockerfile.runtime \
  $WKDIR

docker history $IMG_TAG
docker inspect -f '{{ range $k, $v := .ContainerConfig.Labels -}}
{{ $k }}={{ $v }}
{{ end -}}' "$IMG_TAG"

echo "Built docker image $IMG_TAG"

rm -rf docker-build.????
