#!/usr/bin/env bash
set -ex

if [ "$1" == "" ]; then
    namespace="velcro"
else
    namespace="$1"
fi

curdir=$(cd $(dirname $0) && pwd)
registry="docker-registry.pdbld.f5net.com"

testenv create \
    --config mesos.testenv.yaml \
    --requires bigip \
    --params num_masters:1 num_workers:1 \
    --vars f5mlb_img:"$registry/$namespace/f5-marathon-lb"

sshconf="testenv_symbols/testenv_ssh_config"
scp -F $sshconf $curdir/runtests.sh bastion:~/
ssh -F $sshconf bastion "~/runtests.sh"
