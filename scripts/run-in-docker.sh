#!/bin/bash

IMGNAME=f5mlb-devel

set -x

exec docker run --rm -it -v $PWD:$PWD --workdir $PWD ${IMGNAME} "$@"
