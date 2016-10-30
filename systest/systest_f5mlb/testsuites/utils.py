"""Helper functions for orchestration tests."""


import re
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
DEFAULT_F5MLB_NAME = "test-bigip-controller"
DEFAULT_F5MLB_PARTITION = "test"
DEFAULT_F5MLB_PORT = 8080
DEFAULT_F5MLB_WAIT = 5
DEFAULT_F5MLB_VERIFY_INTERVAL = 2

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
DEFAULT_SVC_SSL_PROFILE = "Common/clientssl"
DEFAULT_SVC_PORT = 80

if symbols.orchestration == "marathon":
    DEFAULT_SVC_CONFIG = {
        'F5_PARTITION': DEFAULT_F5MLB_PARTITION,
        'F5_0_BIND_ADDR': DEFAULT_F5MLB_BIND_ADDR,
        'F5_0_PORT': DEFAULT_F5MLB_PORT,
        'F5_0_MODE': DEFAULT_F5MLB_MODE,
    }
elif symbols.orchestration == "k8s":
    DEFAULT_SVC_CONFIG = {
        'name': "x",
        'labels': {'f5type': "virtual-server"},
        'data': {
            'data': {
                'virtualServer': {
                    'backend': {
                        'serviceName': "x",
                        'servicePort': DEFAULT_SVC_PORT
                    },
                    'frontend': {
                        'partition': DEFAULT_F5MLB_PARTITION,
                        'mode': DEFAULT_F5MLB_MODE,
                        'balance': "round-robin",
                        'virtualAddress': {
                            'bindAddr': DEFAULT_F5MLB_BIND_ADDR,
                            'port': DEFAULT_F5MLB_PORT
                        }
                    }
                }
            },
            'schema': "foo"
        }
    }


def create_managed_northsouth_service(
        orchestration, id="test-svc",
        cpus=DEFAULT_SVC_CPUS,
        mem=DEFAULT_SVC_MEM,
        labels={},
        timeout=DEFAULT_SVC_TIMEOUT,
        health_checks=DEFAULT_SVC_HEALTH_CHECKS_HTTP,
        num_instances=DEFAULT_SVC_INSTANCES,
        config=DEFAULT_SVC_CONFIG):
    """Create a microservice with bigip-controller decorations."""
    # FIXME (kevin): merge user-provided labels w/ default labels
    if symbols.orchestration == "marathon":
        labels.update(config)
    if symbols.orchestration == "k8s":
        orchestration.namespace = "default"
    svc = orchestration.app.create(
        id=id,
        cpus=cpus,
        mem=mem,
        timeout=timeout,
        container_img="%s/systest-common/test-nginx" % REGISTRY,
        labels=labels,
        container_port_mappings=[
            {
                'container_port': DEFAULT_SVC_PORT,
                'host_port': 0,
                'service_port': 0,
                'protocol': "tcp"
            }
        ],
        container_force_pull_image=True,
        health_checks=health_checks,
        num_instances=num_instances
    )
    if symbols.orchestration == "k8s":
        config['name'] = "%s-map" % id
        config['data']['data']['virtualServer']['backend']['serviceName'] = id
        orchestration.app.create_configmap(config)
    return svc


def unmanage_northsouth_service(orchestration, svc):
    """Remove bigip-controller decorations from a managed microservice."""
    if symbols.orchestration == "marathon":
        svc.labels = {}
        svc.update()
    if symbols.orchestration == "k8s":
        orchestration.namespace = "default"
        orchestration.app.delete_configmap("%s-map" % svc.id)


def create_bigip_controller(
        orchestration, id=DEFAULT_F5MLB_NAME, cpus=DEFAULT_F5MLB_CPUS,
        mem=DEFAULT_F5MLB_MEM, timeout=DEFAULT_F5MLB_TIMEOUT):
    """Create a bigip-controller microservice."""
    if symbols.orchestration == "marathon":
        return orchestration.app.create(
            id=id,
            cpus=cpus,
            mem=mem,
            timeout=timeout,
            container_img=symbols.bigip_controller_img,
            container_force_pull_image=True,
            env={
                "F5_CSI_USE_SSE": str(True),
                "F5_CSI_SYSLOG_SOCKET": "/dev/null",
                "MARATHON_URL": symbols.marathon_url,
                "F5_CSI_PARTITIONS": DEFAULT_F5MLB_PARTITION,
                "F5_CSI_BIGIP_HOSTNAME": symbols.bigip_mgmt_ip,
                "F5_CSI_BIGIP_USERNAME": DEFAULT_BIGIP_USERNAME,
                "F5_CSI_BIGIP_PASSWORD": DEFAULT_BIGIP_PASSWORD,
                "F5_CSI_VERIFY_INTERVAL": str(DEFAULT_F5MLB_VERIFY_INTERVAL)
            }
        )
    if symbols.orchestration == "k8s":
        orchestration.namespace = "kube-system"
        return orchestration.app.create(
            id=id,
            cpus=cpus,
            mem=mem,
            timeout=timeout,
            container_img=symbols.bigip_controller_img,
            container_force_pull_image=True,
            cmd="/app/bin/f5-k8s-controller",
            args=[
                "--bigip-partition", DEFAULT_F5MLB_PARTITION,
                "--bigip-url", symbols.bigip_mgmt_ip,
                "--bigip-username", DEFAULT_BIGIP_USERNAME,
                "--bigip-password", DEFAULT_BIGIP_PASSWORD,
                "--verify-interval", str(DEFAULT_F5MLB_VERIFY_INTERVAL)
              ]
        )


def create_unmanaged_service(orchestration, id, labels={}):
    """Create a microservice with no bigip-controller decorations."""
    if symbols.orchestration == "k8s":
        orchestration.namespace = "default"
    return orchestration.app.create(
        id=id,
        cpus=DEFAULT_SVC_CPUS,
        mem=DEFAULT_SVC_MEM,
        timeout=DEFAULT_SVC_TIMEOUT,
        labels=labels,
        container_port_mappings=[
            {
                'container_port': DEFAULT_SVC_PORT,
                'host_port': 0,
                'protocol': "tcp"
            }
        ],
        container_force_pull_image=True
    )


def get_backend_object_name(svc, port_idx=0):
    """Generate expected backend object name."""
    if symbols.orchestration == "marathon":
        return (
            "%s_%s_%s"
            % (
                svc.id.replace("/", ""),
                svc.labels['F5_%d_BIND_ADDR' % port_idx],
                str(svc.labels['F5_%d_PORT' % port_idx])
            )
        )
    if symbols.orchestration == "k8s":
        # FIXME (kevin): need to reach into the associated configmap and pull
        # out the bind_addr and port values
        return (
            "%s_%s_%s"
            % (
                svc.id.replace("/", ""),
                DEFAULT_F5MLB_BIND_ADDR,
                DEFAULT_F5MLB_PORT
            )
        )


def wait_for_bigip_controller(num_seconds=DEFAULT_F5MLB_WAIT):
    """Wait for bigip-controller to restore expected state (or not!)."""
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
    if symbols.orchestration == "marathon":
        virtual_addr = svc.labels['F5_0_BIND_ADDR']
    elif symbols.orchestration == "k8s":
        virtual_addr = DEFAULT_F5MLB_BIND_ADDR
    ret = {
        'virtual_servers': [obj_name],
        'virtual_addresses': [virtual_addr],
        'pools': [obj_name],
        'pool_members': [
            "%s:%d" % (instances[0].host, instances[0].ports[0])
        ],
        'nodes': [instances[0].host],
    }
    # FIXME (kevin): remove when f5-k8s-controller supports health monitors
    if symbols.orchestration == "marathon":
        ret['health_monitors'] = [obj_name]
    return ret


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
    num_members = svc.instances.count()
    num_requests = num_members * 10
    min_res_per_member = 2

    # - send the target number of requests and collect the responses
    act_responses = {}
    curl_cmd = "curl --connect-time 1 -s -k %s" % svc_url
    ptn = re.compile("^Hello from .+ :0\)$")
    for i in range(num_requests):
        res = ssh.run(symbols.bastion, curl_cmd)
        # - verify response looks good
        assert re.match(ptn, res)
        if res not in act_responses:
            act_responses[res] = 1
        else:
            act_responses[res] += 1

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
