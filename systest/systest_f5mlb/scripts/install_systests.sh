#!/usr/bin/env bash
set -ex

if [ "$1" == "" ]; then
    echo "ERROR: no repo value provided!"
    exit 1
else
    repo="$1"
fi

if [ "$2" == "" ]; then
    echo "ERROR: no systest_pkg value provided!"
    exit 1
else
    systest_pkg="$2"
fi

# - work around the "unknown host" prompt
fl=~/.ssh/config
opt="StrictHostKeyChecking no"
if [[ ! -e $fl ]] || [[ $(grep "^$opt" $fl | wc -l) == 0 ]]; then
    echo "$opt" >> $fl
fi

# - create the systest virtualenv
virtualenv systest
source systest/bin/activate

# - install system tests
branch="master"
subdir="systest"
pip install ~/$systest_pkg

# - wait for the pytest rootdir file to exist
pkg_dir=$(python -c "import $systest_pkg as m; print m.__path__[0]")
rootfile=$pkg_dir/testsuites/.pytest.rootdir
i=0
while [ ! -e $rootfile ] && [ $i -lt 10 ]; do
    i=$((i+1))
    echo $i
    sleep 1
done

if [ ! -e $rootfile ]; then
    echo "ERROR: pytest rootdir file not found!"
    exit 1
fi
