"""Local pytest plugin."""


import pytest
from pytest import symbols

import systest_common.src as common

from . import utils


@pytest.fixture(scope='module', autouse=True)
def marathon(request):
    """Provide a marathon connection."""
    return common.marathon.connect(symbols.marathon_url)


@pytest.fixture(scope='module', autouse=True)
def bigip(request):
    """Provide a bigip connection."""
    return common.bigip.connect(
        symbols.bigip_default_ip,
        utils.DEFAULT_BIGIP_USERNAME,
        utils.DEFAULT_BIGIP_PASSWORD
    )


@pytest.fixture(scope='function', autouse=True)
def default_test_fx(request, marathon, bigip):
    """Default test fixture.

    Create a test partition on test setup.
    Delete all marathon apps on test teardown.
    Delete test partition on test teardown.
    """
    partition = utils.DEFAULT_F5MLB_PARTITION
    bigip.partition.create(partition, subPath="/")

    def teardown():
        marathon.apps.delete()
        bigip.virtual_servers.delete(partition=partition)
        bigip.pools.delete(partition=partition)
        bigip.nodes.delete(partition=partition)
        bigip.health_monitors.delete(partition=partition)
        bigip.partition.delete(name=partition)

    request.addfinalizer(teardown)


@pytest.fixture(scope='function')
def f5mlb(request, marathon):
    """Provide a default f5mlb app."""
    f5mlb = utils.create_f5mlb(marathon)

    def teardown():
        f5mlb.delete()

    request.addfinalizer(teardown)
    return f5mlb
