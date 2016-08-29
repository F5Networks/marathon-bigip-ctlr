"""Test suite to verify scale test scenarios in a marathon environment."""


import multiprocessing
import random
import time

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["scale", "marathon"])

F5MLB_CPUS = 0.5
F5MLB_MEM = 128
SVC_CPUS = 0.01
SVC_MEM = 32
SVC_TIMEOUT = 5 * 60
SVC_START_PORT = 7000
VS_INTERVAL = 10
VS_TIMEOUT = 5 * 60


@meta_test(id="f5mlb-59", tags=[])
def test_f5mlb1_svc10_srv100(ssh, marathon):
    """Scale test: 1 f5mlb, 10 managed services (w/ 100 backend servers each).

    Each managed service has 100 backend servers.
    So this test creates 1,011 marathon objects.
    """
    _run_scale_test(ssh, marathon, num_svcs=10, num_srvs=100)


@meta_test(id="f5mlb-60", tags=["no_regression"])
def test_f5mlb1_svc100_srv10(ssh, marathon):
    """Scale test: 1 f5mlb, 100 managed services (w/ 10 backend servers each).

    Each managed service has 10 backend servers.
    So this test creates 1,101 marathon objects.
    """
    _run_scale_test(ssh, marathon, num_svcs=100, num_srvs=10)


@meta_test(id="f5mlb-61", tags=["no_regression"])
def test_f5mlb1_svc100_srv100(ssh, marathon):
    """Scale test: 1 f5mlb, 100 managed services (w/ 100 backend servers each).

    Each managed service has and 100 backend servers.
    So this test creates 10,101 marathon objects.
    """
    _run_scale_test(ssh, marathon, num_svcs=100, num_srvs=100)


def _run_scale_test(
        ssh, marathon, num_svcs, num_srvs,
        svc_cpus=SVC_CPUS, svc_mem=SVC_MEM, timeout=SVC_TIMEOUT):
    svc_inputs = []
    svcs = []

    utils.create_f5mlb(marathon, cpus=F5MLB_CPUS, mem=F5MLB_MEM)

    # - first, scale-up the appropriate services and instances
    for i in range(1, num_svcs + 1):
        svc_inputs.append({
            'idx': i,
            'ssh': ssh,
            'marathon': marathon,
            'num_srvs': num_srvs,
            'svc_cpus': svc_cpus,
            'svc_mem': svc_mem,
            'timeout': timeout
        })
    pool_size = 10
    slices = [
        svc_inputs[i:i+pool_size] for i in range(0, len(svc_inputs), pool_size)
    ]
    for slice in slices:
        p = multiprocessing.Pool(processes=len(slice))
        svcs += p.map(_create_svc, slice)
        p.close()
        p.join()

    # - then, verify round-robin load balancing for each service
    pool_size = 10
    for slice in [svcs[i:i+pool_size] for i in range(0, len(svcs), pool_size)]:
        p = multiprocessing.Pool(processes=len(slice))
        p.map(_verify_f5mlb, slice)
        p.close()
        p.join()


def _create_svc(kwargs):
    # - wait a pseudo-random number of seconds (to prevent the marathon server
    #   from being inundated with simultaneous app creation/scaling requests)
    time.sleep(random.randint(1, 20) + ((kwargs['idx'] * 5) % 30))

    # - create a managed service
    svc_name = "svc-%d" % kwargs['idx']
    svc_labels = {
        'F5_PARTITION': utils.DEFAULT_F5MLB_PARTITION,
        'F5_0_BIND_ADDR': utils.DEFAULT_F5MLB_BIND_ADDR,
        'F5_0_PORT': SVC_START_PORT + kwargs['idx'],
        'F5_0_MODE': utils.DEFAULT_F5MLB_MODE,
    }
    svc = utils.create_managed_service(
        kwargs['marathon'],
        svc_name,
        labels=svc_labels,
        cpus=kwargs['svc_cpus'],
        mem=kwargs['svc_mem'],
        timeout=kwargs['timeout'],
        num_instances=kwargs['num_srvs']
    )
    _wait_for_virtual_server(svc, kwargs['ssh'])
    return {
        'svc_name': svc_name,
        'ssh': kwargs['ssh'],
        'marathon': kwargs['marathon']
    }


def _wait_for_virtual_server(svc, ssh, timeout=VS_TIMEOUT):
    duration = 0
    interval = VS_INTERVAL

    vs_name = utils.get_backend_object_name(svc)
    vs_url = (
        "https://%s/mgmt/tm/ltm/virtual/~%s~%s/stats"
        % (
            symbols.bigip_mgmt_ip,
            utils.DEFAULT_F5MLB_PARTITION,
            vs_name
        )
    )
    curl_cmd = (
        "curl -sk -u \"%s:%s\" -H \"Content-Type: application/json\" %s"
        % (
            utils.DEFAULT_BIGIP_USERNAME,
            utils.DEFAULT_BIGIP_PASSWORD,
            vs_url,
        )
    )
    availability_msg = "The virtual server is available"

    def is_available():
        res = ssh.run(symbols.bastion, curl_cmd)
        return availability_msg in res

    while not is_available() and duration < timeout:
        time.sleep(interval)
        duration += interval
    time.sleep(interval)
    assert is_available()


def _verify_f5mlb(kwargs):
    marathon = kwargs['marathon']
    ssh = kwargs['ssh']
    svc = marathon.app.get(kwargs['svc_name'])
    svc_url = (
        "http://%s:%s"
        % (svc.labels['F5_0_BIND_ADDR'], svc.labels['F5_0_PORT'])
    )
    potential_responses = []
    actual_responses = []
    for instance in svc.instances.get():
        member = "%s:%d" % (instance.host, instance.ports[0])
        potential_responses.append("Hello from %s :0)" % member)
    num_requests = 20
    curl_cmd = "curl -s %s" % svc_url
    for i in range(num_requests):
        res = ssh.run(symbols.bastion, curl_cmd)
        assert res in potential_responses
        if res not in actual_responses:
            actual_responses.append(res)
    # - verify we got responses from at least two different pool members
    assert len(actual_responses) >= 2
