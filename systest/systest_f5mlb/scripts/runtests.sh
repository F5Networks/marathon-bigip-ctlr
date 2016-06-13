#!/usr/bin/env bash
set -ex

if [ "$1" == "" ]; then
    namespace="velcro"
else
    namespace="$1"
fi

fl=~/.ssh/config
opt="StrictHostKeyChecking no"
if [[ ! -e $fl ]] || [[ $(grep "^$opt" $fl | wc -l) == 0 ]]; then
    echo "$opt" >> $fl
fi

virtualenv systest
source systest/bin/activate

repo="git+ssh://git@bldr-git.int.lineratesystems.com/$namespace/f5-marathon-lb.git"
branch="master"
pkg="systest_f5mlb"
subdir="systest"
pip install "$repo@$branch#egg=$pkg&subdirectory=$subdir"

systestdir=$(python -c "import $pkg; print $pkg.__path__[0]")
cd $systestdir/testsuites
py.test \
    -svvra \
    --symbols ~/testenv_symbols/testenv_symbols.json \
    -- marathon
