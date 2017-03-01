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

"""Test suite to verify https scenarios in an orchestration environment."""


import copy

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "openshift", "https"])


@meta_test(id="f5mlb-62", tags=[])
def test_https(ssh, orchestration, bigip, bigip_controller):
    """Verify system behavior with basic https config."""
    # - start managed service
    port = 443
    config = _get_https_config('tcp', port)
    svc = utils.create_managed_northsouth_service(
        orchestration,
        health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_TCP,
        config=config
    )
    utils.wait_for_bigip_controller()
    svc.scale(2)
    assert svc.instances.count() == 2
    utils.wait_for_bigip_controller()
    svc_url = "%s:%s" % (
        utils.DEFAULT_F5MLB_BIND_ADDR, port
    )

    # - verify tcp and SSL profiles are attached to virtual server on the
    # backend
    obj_name = utils.get_backend_object_name(svc)
    vs = bigip.virtual_server.get(
        name=obj_name, partition=utils.DEFAULT_F5MLB_PARTITION
    )
    profiles = vs.profiles_s.get_collection()

    expected_set = set(['/Common/tcp', '/' + utils.DEFAULT_SVC_SSL_PROFILE])
    assert len(profiles) == 2
    assert profiles[0].fullPath in expected_set
    assert profiles[1].fullPath in expected_set

    # - verify http request fails
    http_url = "http://" + svc_url
    curl_cmd = "curl -s -k %s" % http_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res == ""

    # - verify https request succeeds
    https_url = "https://" + svc_url
    curl_cmd = "curl -s -k %s" % https_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res.startswith("Hello from")

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(ssh, svc)


def _get_https_config(mode, port):
    if symbols.orchestration == "marathon":
        cfg = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
        cfg['F5_0_SSL_PROFILE'] = utils.DEFAULT_SVC_SSL_PROFILE
        if mode is not None:
            cfg['F5_0_MODE'] = mode
        if port is not None:
            cfg['F5_0_PORT'] = port
    if utils.is_kubernetes():
        cfg = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
        frontend = cfg['data']['data']['virtualServer']['frontend']
        frontend['sslProfile'] = {
            'f5ProfileName': utils.DEFAULT_SVC_SSL_PROFILE
        }
        if mode is not None:
            frontend['mode'] = mode
        if port is not None:
            frontend['virtualAddress']['port'] = port
    return cfg
