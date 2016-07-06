"""Helper functions for marathon tests."""


import time

from pytest import symbols


REGISTRY = "docker-registry.pdbld.f5net.com"

DEFAULT_BIGIP_PASSWORD = "admin"
DEFAULT_BIGIP_USERNAME = "admin"

DEFAULT_F5MLB_CPUS = 0.1
DEFAULT_F5MLB_MEM = 32
DEFAULT_F5MLB_TIMEOUT = 30
DEFAULT_F5MLB_BIND_ADDR = "192.168.1.100"
DEFAULT_F5MLB_MODE = "http"
DEFAULT_F5MLB_NAME = "test-f5mlb"
DEFAULT_F5MLB_PARTITION = "test"
DEFAULT_F5MLB_PORT = 8080
DEFAULT_F5MLB_WAIT = 5

DEFAULT_SVC_CPUS = 0.1
DEFAULT_SVC_MEM = 32
DEFAULT_SVC_TIMEOUT = 30
DEFAULT_SVC_LABELS = {
    'F5_PARTITION': DEFAULT_F5MLB_PARTITION,
    'F5_0_BIND_ADDR': DEFAULT_F5MLB_BIND_ADDR,
    'F5_0_PORT': DEFAULT_F5MLB_PORT,
    'F5_0_MODE': DEFAULT_F5MLB_MODE,
}


def create_managed_service(
        marathon, id="test-svc", cpus=DEFAULT_SVC_CPUS, mem=DEFAULT_SVC_MEM,
        labels=DEFAULT_SVC_LABELS, timeout=DEFAULT_SVC_TIMEOUT):
    """Create a marathon app with f5mlb decorations."""
    # FIXME (kevin): merge user-provided labels w/ default labels
    return marathon.app.create(
        id=id,
        cpus=cpus,
        mem=mem,
        timeout=timeout,
        container_img="%s/systest-common/test-nginx" % REGISTRY,
        labels=labels,
        container_port_mappings=[
            {
                'container_port': 80,
                'host_port': 0,
                'service_port': 0,
                'protocol': "tcp"
            }
        ],
        container_force_pull_image=True,
        health_checks=[
            {
                'path': "/",
                'protocol': "HTTP",
                'max_consecutive_failures': 3,
                'port_index': 0,
                'interval_seconds': 5,
                'grace_period_seconds': 10,
                'timeout_seconds': 5
            }
        ]
    )


def create_f5mlb(
        marathon, id=DEFAULT_F5MLB_NAME, cpus=DEFAULT_F5MLB_CPUS,
        mem=DEFAULT_F5MLB_MEM, timeout=DEFAULT_F5MLB_TIMEOUT):
    """Create an f5mlb app."""
    return marathon.app.create(
        id=id,
        cpus=cpus,
        mem=mem,
        timeout=timeout,
        container_img=symbols.f5mlb_img,
        container_force_pull_image=True,
        args=[
            "sse",
            "--marathon", symbols.marathon_url,
            "--partition", DEFAULT_F5MLB_PARTITION,
            "--hostname", symbols.bigip_default_ip,
            "--username", DEFAULT_BIGIP_USERNAME,
            "--password", DEFAULT_BIGIP_PASSWORD
          ]
    )


def create_unmanaged_service(marathon, id, labels={}):
    """Create a marathon app with no f5mlb decorations."""
    return marathon.app.create(
        id=id,
        cpus=DEFAULT_SVC_CPUS,
        mem=DEFAULT_SVC_MEM,
        timeout=DEFAULT_SVC_TIMEOUT,
        container_img="%s/systest-common/test-nginx" % REGISTRY,
        labels=labels,
        container_port_mappings=[
            {
                'container_port': 80,
                'host_port': 0,
                'protocol': "tcp"
            }
        ],
        container_force_pull_image=True
    )


def get_backend_object_name(svc, port_idx=0):
    """Generate expected backend object name."""
    return (
        "%s_%s_%s"
        % (
            svc.id.replace("/", ""),
            svc.labels['F5_%d_BIND_ADDR' % port_idx],
            str(svc.labels['F5_%d_PORT' % port_idx])
        )
    )


def wait_for_f5mlb(num_seconds=DEFAULT_F5MLB_WAIT):
    """Wait for f5mlb to restore expected state (or not!)."""
    time.sleep(num_seconds)


def get_backend_objects(bigip, partition=DEFAULT_F5MLB_PARTITION):
    ret = {}

    if not bigip.partition.exists(name=partition):
        return {}

    # - get list of virtual servers
    virtual_servers = bigip.virtual_servers.list(partition=partition)
    if virtual_servers:
        ret['virtual_servers'] = virtual_servers

    # - get list of virtual addresses
    virtual_addresses = bigip.virtual_addresses.list(partition=partition)
    if virtual_addresses:
        ret['virtual_addresses'] = virtual_addresses

    # - get list of pools
    pools = bigip.pools.list(partition=partition)
    if pools:
        ret['pools'] = pools

    # - get list of pool members
    pool_members = bigip.pool_members.list(partition=partition)
    if pool_members:
        ret['pool_members'] = pool_members

    # - get list of health monitors
    health_monitors = bigip.health_monitors.list(partition=partition)
    if health_monitors:
        ret['health_monitors'] = health_monitors

    # - get list of nodes
    nodes = bigip.nodes.list(partition=partition)
    if nodes:
        ret['nodes'] = nodes

    return ret


def get_backend_objects_exp(svc):
    instances = svc.instances.get()
    obj_name = get_backend_object_name(svc)
    return {
        'virtual_servers': [obj_name],
        'virtual_addresses': [svc.labels['F5_0_BIND_ADDR']],
        'pools': [obj_name],
        'pool_members': [
            "%s:%d" % (instances[0].host, instances[0].ports[0])
        ],
        'nodes': [instances[0].host],
        'health_monitors': [obj_name]
    }


def wait_for_backend_objects(
        bigip, objs_exp, partition=DEFAULT_F5MLB_PARTITION, timeout=60):
    interval = 2
    duration = 0
    while get_backend_objects(bigip) != objs_exp and duration <= timeout:
        time.sleep(interval)
        duration += interval
    assert get_backend_objects(bigip) == objs_exp
