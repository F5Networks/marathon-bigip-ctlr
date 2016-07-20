"""Test suite to verify scale test scenarios in a marathon environment."""


import multiprocessing

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["scale", "marathon"])

DEFAULT_SVC_CPUS = 0.01
DEFAULT_SVC_MEM = 32
DEFAULT_SVC_TIMEOUT = 60


@meta_test(id="f5mlb-59", tags=[])
def test_f5mlb1_svc10_srv100(marathon, bigip, f5mlb):
    """Scale test: 1 f5mlb, 10 managed services (w/ 100 backend servers each).

    Each managed service has 100 backend servers.
    So this test creates 1,011 marathon objects.
    """
    _run_scale_test(marathon, bigip, f5mlb, num_svcs=10, num_srvs=10)


@meta_test(id="f5mlb-60", tags=["no_regression"])
def test_f5mlb1_svc100_srv10(marathon, bigip, f5mlb):
    """Scale test: 1 f5mlb, 100 managed services (w/ 10 backend servers each).

    Each managed service has 10 backend servers.
    So this test creates 1,101 marathon objects.
    """
    _run_scale_test(marathon, bigip, f5mlb, num_svcs=100, num_srvs=10)


@meta_test(id="f5mlb-61", tags=["no_regression"])
def test_f5mlb1_svc100_srv100(marathon, bigip, f5mlb):
    """Scale test: 1 f5mlb, 100 managed services (w/ 100 backend servers each).

    Each managed service has and 100 backend servers.
    So this test creates 10,101 marathon objects.
    """
    _run_scale_test(marathon, bigip, f5mlb, num_svcs=100, num_srvs=100)


def _run_scale_test(
        ssh, marathon, num_svcs, num_srvs,
        svc_cpus=DEFAULT_SVC_CPUS, svc_mem=DEFAULT_SVC_MEM,
        timeout=DEFAULT_SVC_TIMEOUT):
    svc_inputs = []
    svcs = []
    results = []
    mismatches = []

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
    # FIXME (kevin): need to figure out why we get intermittent failures when
    # the pool size for the "create managed service" phase is more than 1
    pool_size = 1
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
        results += p.map(_verify_f5mlb, slice)
        p.close()
        p.join()
    for row in results:
        mismatches += [r for r in row if r['is_match'] is not True]
    assert mismatches == []


def _create_svc(kwargs):
    # - create a managed service
    svc_name = "svc-%d" % kwargs['idx']
    svc_labels = {
        'F5_PARTITION': utils.DEFAULT_F5MLB_PARTITION,
        'F5_0_BIND_ADDR': "192.168.100.%d" % kwargs['idx'],
        'F5_0_PORT': utils.DEFAULT_F5MLB_PORT,
        'F5_0_MODE': utils.DEFAULT_F5MLB_MODE,
    }
    svc = utils.create_managed_service(
        kwargs['marathon'],
        svc_name,
        labels=svc_labels,
        cpus=kwargs['svc_cpus'],
        mem=kwargs['svc_mem'],
        timeout=kwargs['timeout']
    )
    svc_url = (
        "http://%s:%s"
        % (svc.labels['F5_0_BIND_ADDR'], svc.labels['F5_0_PORT'])
    )

    # - create backend servers
    svc.scale(kwargs['num_srvs'], timeout=kwargs['timeout'])
    svc_instances = svc.instances.get()
    pool_members = []
    for instance in svc_instances:
        pool_members.append("%s:%d" % (instance.host, instance.ports[0]))

    return {
        'name': svc_name,
        'svc_url': svc_url,
        'members': pool_members,
        'num_srvs': kwargs['num_srvs'],
        'ssh': kwargs['ssh'],
        'timeout': kwargs['timeout']
    }


def _verify_f5mlb(kwargs):
    ret = []
    curl_cmd = "curl -s %s" % kwargs['svc_url']
    msg = "Hello from %s :0)"
    for member in kwargs['members']:
        exp = msg % member
        act = kwargs['ssh'].run(symbols.bastion, curl_cmd)
        ret.append({
            'name': kwargs['name'],
            'exp': exp,
            'act': act,
            'is_match': exp == act
        })
    return ret
