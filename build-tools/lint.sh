#!/bin/bash

# FIXME (mday): Working to remove `disable`s below as outlined in #131
# use `lint.sh -rn` to see all standard warnings
# use `lint.sh -rn --disable=all --enable=<checker>` to focus on specific
#     comma delimited checker(s). Checker documentation at:
# https://pylint.readthedocs.io/en/latest/reference_guide/features.html

DEFAULTS="-rn --notes=TODO,Todo,ToDo,todo
--max-nested-blocks=6
--disable=invalid-name,\
redefined-outer-name,\
global-statement,\
logging-format-interpolation,\
design,too-many-locals,\
no-self-use,\
too-many-lines,\
unused-argument,\
len-as-condition,\
broad-except"

[ -z $1 ] ||  DEFAULTS=$@

LIST="$(find . -name '*py' ! -path '*test*' ! -path '*docs*' ! -path '*f5_cccl*' )"
for i in $LIST; do
    pylint $i $DEFAULTS
done
