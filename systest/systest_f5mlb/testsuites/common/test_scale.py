# Copyright 2017 F5 Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test suite to verify scale test scenarios."""


import multiprocessing
import re
import time

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["scale", "marathon", "k8s"])

F5MLB_CPUS = 0.5
F5MLB_MEM = 128
SVC_CPUS = 0.01
SVC_MEM = 32
SVC_TIMEOUT = 5 * 60
SVC_START_PORT = 7000
VS_INTERVAL = 10
VS_TIMEOUT = 5 * 60


@meta_test(id="f5mlb-59", tags=[])
def test_bigip_controller1_svc10_srv100(ssh, orchestration):
    """Scale: 1 bigip-controller, 10 managed svcs (w/ 100 backends each).

    Each managed service has 100 backend servers.
    So this test creates 1,011 application instances.
    """
    _run_scale_test(ssh, orchestration, num_svcs=10, num_srvs=100)


@meta_test(id="f5mlb-60", tags=["no_regression"])
def test_bigip_controller1_svc100_srv10(ssh, orchestration):
    """Scale: 1 bigip-controller, 100 managed svcs (w/ 10 backends each).

    Each managed service has 10 backend servers.
    So this test creates 1,101 application instances.
    """
    _run_scale_test(ssh, orchestration, num_svcs=100, num_srvs=10)


@meta_test(id="f5mlb-61", tags=["no_regression"])
def test_bigip_controller1_svc100_srv100(ssh, orchestration):
    """Scale: 1 bigip-controller, 100 managed svcs (w/ 100 backends each).

    Each managed service has and 100 backend servers.
    So this test creates 10,101 application instances.
    """
    _run_scale_test(ssh, orchestration, num_svcs=100, num_srvs=100)


def _run_scale_test(
        ssh, orchestration, num_svcs, num_srvs,
        svc_cpus=SVC_CPUS, svc_mem=SVC_MEM, timeout=SVC_TIMEOUT):
    svc_inputs = []
    svcs = []

    utils.BigipController(
        orchestration, cpus=F5MLB_CPUS, mem=F5MLB_MEM
    ).create()

    # - first, scale-up the appropriate services and instances
    for i in range(1, num_svcs + 1):
        svc_inputs.append({
            'idx': i,
            'ssh': ssh,
            'orchestration': orchestration,
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

    # - set pool_size to number of cores on the bastion
    pool_size = 4
    # - then, verify round-robin load balancing for each service
    for slice in [svcs[i:i+pool_size] for i in range(0, len(svcs), pool_size)]:
        p = multiprocessing.Pool(processes=len(slice))
        p.map(_verify_bigip_controller, slice)
        p.close()
        p.join()


def _create_svc(kwargs):
    # - create a managed service
    svc_name = "svc-%d" % kwargs['idx']
    config = _get_scale_config(kwargs)
    svc = utils.create_managed_northsouth_service(
        kwargs['orchestration'],
        svc_name,
        cpus=kwargs['svc_cpus'],
        mem=kwargs['svc_mem'],
        timeout=kwargs['timeout'],
        num_instances=kwargs['num_srvs'],
        config=config
    )
    _wait_for_virtual_server(svc, kwargs['ssh'])
    return {
        'svc_name': svc_name,
        'ssh': kwargs['ssh'],
        'orchestration': kwargs['orchestration']
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


def _verify_bigip_controller(kwargs):
    orchestration = kwargs['orchestration']
    ssh = kwargs['ssh']
    svc = orchestration.app.get(kwargs['svc_name'])
    svc_url = _get_svc_url(svc)
    actual_responses = []
    num_requests = 20
    curl_cmd = "curl -sk %s" % svc_url
    ptn = re.compile("^Hello from .+ :0\)$")
    for _ in range(num_requests):
        res = ssh.run(symbols.bastion, curl_cmd)
        # - verify response looks good
        assert re.match(ptn, res)
        if res not in actual_responses:
            actual_responses.append(res)
    # - verify we got responses from at least two different pool members
    assert len(actual_responses) >= 2


def _get_scale_config(kwargs):
    if symbols.orchestration == "marathon":
        cfg = {
            'F5_PARTITION': utils.DEFAULT_F5MLB_PARTITION,
            'F5_0_BIND_ADDR': utils.DEFAULT_F5MLB_BIND_ADDR,
            'F5_0_PORT': SVC_START_PORT + kwargs['idx'],
            'F5_0_MODE': utils.DEFAULT_F5MLB_MODE,
        }
    elif symbols.orchestration == "k8s":
        cfg = {}
    return cfg


def _get_svc_url(svc):
    if symbols.orchestration == "marathon":
        return (
            "http://%s:%s"
            % (svc.labels['F5_0_BIND_ADDR'], svc.labels['F5_0_PORT'])
        )
    if symbols.orchestration == "k8s":
        pass
