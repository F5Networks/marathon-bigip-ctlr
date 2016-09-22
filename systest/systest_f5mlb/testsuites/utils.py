"""Helper functions for orchestration tests."""


import time

from pytest import symbols


REGISTRY = "docker-registry.pdbld.f5net.com"

DEFAULT_BIGIP_PASSWORD = "admin"
DEFAULT_BIGIP_USERNAME = "admin"

DEFAULT_F5MLB_CPUS = 0.1
DEFAULT_F5MLB_MEM = 32
DEFAULT_F5MLB_TIMEOUT = 60
DEFAULT_F5MLB_BIND_ADDR = symbols.bigip_ext_ip
DEFAULT_F5MLB_MODE = "http"
DEFAULT_F5MLB_NAME = "test-f5mlb"
DEFAULT_F5MLB_PARTITION = "test"
DEFAULT_F5MLB_PORT = 8080
DEFAULT_F5MLB_WAIT = 5

DEFAULT_SVC_CPUS = 0.1
DEFAULT_SVC_HEALTH_CHECKS_HTTP = [
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
DEFAULT_SVC_HEALTH_CHECKS_TCP = [
    {
        'protocol': "TCP",
        'max_consecutive_failures': 3,
        'port_index': 0,
        'interval_seconds': 5,
        'grace_period_seconds': 10,
        'timeout_seconds': 5
    }
]
DEFAULT_SVC_INSTANCES = 1
DEFAULT_SVC_MEM = 32
DEFAULT_SVC_TIMEOUT = 60
DEFAULT_SVC_LABELS = {
    'F5_PARTITION': DEFAULT_F5MLB_PARTITION,
    'F5_0_BIND_ADDR': DEFAULT_F5MLB_BIND_ADDR,
    'F5_0_PORT': DEFAULT_F5MLB_PORT,
    'F5_0_MODE': DEFAULT_F5MLB_MODE,
}
DEFAULT_SVC_SSL_PROFILE = "Common/clientssl"


def create_managed_service(
        orchestration, id="test-svc",
        cpus=DEFAULT_SVC_CPUS,
        mem=DEFAULT_SVC_MEM,
        labels=DEFAULT_SVC_LABELS,
        timeout=DEFAULT_SVC_TIMEOUT,
        health_checks=DEFAULT_SVC_HEALTH_CHECKS_HTTP,
        num_instances=DEFAULT_SVC_INSTANCES):
    """Create an app with f5mlb decorations."""
    # FIXME (kevin): merge user-provided labels w/ default labels
    return orchestration.app.create(
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
        health_checks=health_checks,
        num_instances=num_instances
    )


def create_f5mlb(
        orchestration, id=DEFAULT_F5MLB_NAME, cpus=DEFAULT_F5MLB_CPUS,
        mem=DEFAULT_F5MLB_MEM, timeout=DEFAULT_F5MLB_TIMEOUT):
    """Create an f5mlb app."""
    return orchestration.app.create(
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
            "--hostname", symbols.bigip_mgmt_ip,
            "--username", DEFAULT_BIGIP_USERNAME,
            "--password", DEFAULT_BIGIP_PASSWORD
          ]
    )


def create_unmanaged_service(orchestration, id, labels={}):
    """Create an app with no f5mlb decorations."""
    return orchestration.app.create(
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
    """Get the resources managed by BIG-IP."""
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
    """A dict of the expected backend resources."""
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
    """Verify that the actual backend resources match what's expected."""
    interval = 2
    duration = 0
    while get_backend_objects(bigip) != objs_exp and duration <= timeout:
        time.sleep(interval)
        duration += interval
    assert get_backend_objects(bigip) == objs_exp


def verify_bigip_round_robin(ssh, svc, protocol=None, ipaddr=None, port=None):
    """Verify round-robin load balancing behavior."""
    # - bigip round robin is not as predictable as we would like (ie. you
    #   can't be sure that two consecutive requests will be sent to two
    #   separate pool members - but if you send enough requests, the responses
    #   will average out to something like what you expected).
    svc_url = _get_svc_url(svc, protocol, ipaddr, port)
    pool_members = []
    exp_responses = []
    for instance in svc.instances.get():
        member = "%s:%d" % (instance.host, instance.ports[0])
        pool_members.append(member)
        exp_responses.append("Hello from %s :0)" % member)

    num_members = len(pool_members)
    num_requests = num_members * 10
    min_res_per_member = 2

    # - send the target number of requests and collect the responses
    act_responses = {}
    curl_cmd = "curl -s -k %s" % svc_url
    for i in range(num_requests):
        res = ssh.run(symbols.bastion, curl_cmd)
        if res not in act_responses:
            act_responses[res] = 1
        else:
            act_responses[res] += 1

    # - verify all responses came from recognized pool members
    assert sorted(act_responses.keys()) == sorted(exp_responses)

    # - verify we got at least 2 responses from each member
    for k, v in act_responses.iteritems():
        assert v >= min_res_per_member


def _get_svc_url(svc, protocol=None, ipaddr=None, port=None):
    if protocol is None:
        if 'F5_0_SSL_PROFILE' in svc.labels:
            protocol = "https"
        else:
            protocol = "http"
    if ipaddr is None:
        if 'F5_0_BIND_ADDR' in svc.labels:
            ipaddr = svc.labels['F5_0_BIND_ADDR']
        else:
            ipaddr = DEFAULT_F5MLB_BIND_ADDR
    if port is None:
        if 'F5_0_PORT' in svc.labels:
            port = svc.labels['F5_0_PORT']
        else:
            port = DEFAULT_F5MLB_PORT
    return "%s://%s:%s" % (protocol, ipaddr, port)
