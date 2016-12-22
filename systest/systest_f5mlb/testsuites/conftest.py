"""Local pytest plugin."""


import functools

import pytest
from pytest import symbols

import systest_common.src as common

from . import utils


DELETE_TIMEOUT = 2 * 60


def pytest_namespace():
    """Configure objects to go in the pytest namespace."""
    bastion = common.ssh.connect(pytest.symbols.bastion)

    def _run(hosts, *args, **kwargs):
        return [str(bastion.run(host, *args, **kwargs)) for host in hosts]

    return {
        'masters_cmd': functools.partial(_run, pytest.symbols.masters),
        'workers_cmd': functools.partial(_run, pytest.symbols.workers)
    }


@pytest.fixture(scope='session', autouse=True)
def orchestration(request):
    """Provide an orchestration connection."""
    return common.orchestration.connect(**vars(symbols))


@pytest.fixture(scope='session', autouse=True)
def ssh(request):
    """Provide an ssh connection - via the bastion host."""
    return common.ssh.connect(gateway=symbols.bastion)


# Always create an initial bigip
@pytest.fixture(scope='session', autouse=True)
def bigip(request):
    """Provide a bigip connection."""
    return common.bigip.connect(
        utils.DEFAULT_BIGIP_MGMT_IP,
        utils.DEFAULT_BIGIP_USERNAME,
        utils.DEFAULT_BIGIP_PASSWORD
    )


# Only create a second bigip if it is required
@pytest.fixture(scope='session', autouse=False)
def bigip2(request):
    """Provide a bigipX connection."""
    return common.bigip.connect(
        utils.DEFAULT_BIGIP2_MGMT_IP,
        utils.DEFAULT_BIGIP_USERNAME,
        utils.DEFAULT_BIGIP_PASSWORD
    )


def _setup_bigip(instance, partition):
    instance.partition.create(partition, subPath="/")

    # FIXME (kevin): remove these partition hacks when issue #32 is fixed
    p = instance.partition.get(name=partition)
    p.inheritedTrafficGroup = False
    p.trafficGroup = "/Common/traffic-group-local-only"
    p.update()


def _teardown_bigip(instance, partition):
    instance.iapps.delete(partition=partition)
    instance.virtual_servers.delete(partition=partition)
    instance.virtual_addresses.delete(partition=partition)
    instance.pools.delete(partition=partition)
    instance.nodes.delete(partition=partition)
    instance.health_monitors.delete(partition=partition)
    instance.partition.delete(name=partition)


@pytest.fixture(scope='function', autouse=True)
def default_test_fx(request, orchestration, bigip):
    """Default test fixture.

    Create a test partition on test setup.
    Delete all orchestration apps on test teardown.
    Delete test partition on test teardown.
    """
    partition = utils.DEFAULT_F5MLB_PARTITION

    def teardown():
        if request.config._meta.vars.get('skip_teardown', None):
            return
        orchestration.namespace = "default"
        orchestration.apps.delete(timeout=DELETE_TIMEOUT)
        orchestration.deployments.delete(timeout=DELETE_TIMEOUT)
        _teardown_bigip(bigip, partition)

    teardown()
    _setup_bigip(bigip, partition)
    request.addfinalizer(teardown)


@pytest.fixture(scope='function')
def bigip2_addto_test_fx(request, orchestration, bigip2):
    """Bigip2 test fixture.

    Create a test partition on second bigip.
    Delete all orchestration apps on test teardown.
    Delete test partition on test teardown.
    """
    partition = utils.DEFAULT_F5MLB_PARTITION

    def teardown():
        if request.config._meta.vars.get('skip_teardown', None):
            return
        _teardown_bigip(bigip2, partition)

    teardown()
    _setup_bigip(bigip2, partition)
    request.addfinalizer(teardown)


@pytest.fixture(scope='function')
def bigip_controller(request, orchestration):
    """Provide a default bigip-controller service."""
    controller = utils.create_bigip_controller(orchestration)

    def teardown():
        if request.config._meta.vars.get('skip_teardown', None):
            return
        orchestration.namespace = "kube-system"
        controller.delete()

    request.addfinalizer(teardown)
    return controller


@pytest.fixture(scope='function')
def bigip2_controller(request, orchestration, bigip2_addto_test_fx):
    """Provide a second bigip-controller service."""
    controller = \
        utils.create_bigip_controller(orchestration,
                                      id=utils.BIGIP2_F5MLB_NAME,
                                      config=utils.BIGIP2_F5MLB_CONFIG)

    def teardown():
        if request.config._meta.vars.get('skip_teardown', None):
            return
        orchestration.namespace = "kube-system"
        controller.delete()

    request.addfinalizer(teardown)
    return controller
