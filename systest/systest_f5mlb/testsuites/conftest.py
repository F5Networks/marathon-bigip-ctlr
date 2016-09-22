"""Local pytest plugin."""


import pytest
from pytest import symbols

import systest_common.src as common

from . import utils


DELETE_TIMEOUT = 2 * 60


@pytest.fixture(scope='session', autouse=True)
def orchestration(request):
    """Provide an orchestration connection."""
    return common.orchestration.connect(**vars(symbols))


@pytest.fixture(scope='session', autouse=True)
def ssh(request):
    """Provide an ssh connection - via the bastion host."""
    return common.ssh.connect(gateway=symbols.bastion)


@pytest.fixture(scope='session', autouse=True)
def bigip(request):
    """Provide a bigip connection."""
    return common.bigip.connect(
        symbols.bigip_mgmt_ip,
        utils.DEFAULT_BIGIP_USERNAME,
        utils.DEFAULT_BIGIP_PASSWORD
    )


@pytest.fixture(scope='function', autouse=True)
def default_test_fx(request, orchestration, bigip):
    """Default test fixture.

    Create a test partition on test setup.
    Delete all orchestration apps on test teardown.
    Delete test partition on test teardown.
    """
    partition = utils.DEFAULT_F5MLB_PARTITION
    bigip.partition.create(partition, subPath="/")
    # FIXME (kevin): remove these partition hacks when issue #32 is fixed
    p = bigip.partition.get(name=partition)
    p.inheritedTrafficGroup = False
    p.trafficGroup = "/Common/traffic-group-local-only"
    p.update()

    def teardown():
        if request.config._meta.vars.get('skip_teardown', None):
            return
        orchestration.apps.delete(timeout=DELETE_TIMEOUT)
        orchestration.deployments.delete(timeout=DELETE_TIMEOUT)
        bigip.iapps.delete(partition=partition)
        bigip.virtual_servers.delete(partition=partition)
        bigip.virtual_addresses.delete(partition=partition)
        bigip.pools.delete(partition=partition)
        bigip.nodes.delete(partition=partition)
        bigip.health_monitors.delete(partition=partition)
        bigip.partition.delete(name=partition)

    request.addfinalizer(teardown)


@pytest.fixture(scope='function')
def f5mlb(request, orchestration):
    """Provide a default f5mlb app."""
    f5mlb = utils.create_f5mlb(orchestration)

    def teardown():
        if request.config._meta.vars.get('skip_teardown', None):
            return
        f5mlb.delete()

    request.addfinalizer(teardown)
    return f5mlb
