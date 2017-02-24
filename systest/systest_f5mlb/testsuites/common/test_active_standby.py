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

"""Verify poor-man version of BigIP failover in openstack environments."""


import copy
import os
import time

from pytest import meta_suite, meta_test
from pytest import symbols
from .. import utils


pytestmark = meta_suite(tags=["ha", "marathon", "k8s"])


@meta_test(id="f5mlb-66", tags=[])
def test_ha_failover(ssh, orchestration, bigip, bigip_controller,
                     bigip2_controller):
    """Verify system behavior when failing over from one F5 to another."""
    # - start managed service with three http servers
    endpoints_count = 3
    port = 443
    config = _get_https_config('tcp', port)
    svc = utils.create_managed_northsouth_service(
        orchestration,
        health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_HTTP,
        config=config
    )
    utils.wait_for_bigip_controller()
    svc.scale(endpoints_count)
    assert svc.instances.count() == endpoints_count
    utils.wait_for_bigip_controller()

    # - verify https request succeeds and record the endpoint IDs
    #   (send enough requests to guarantee all endpoints are hit.)
    endpoints = {}
    https_url = "https://" + symbols.ha_floating_ip
    curl_cmd = "curl -s -k -m 5 %s" % https_url
    for idx in range(0, 20):
        res = ssh.run(symbols.bastion, curl_cmd)
        assert res.startswith("Hello from ")
        endpoints[res.split(" ")[2]] = False
    assert len(endpoints) == endpoints_count

    # - remove floating ip and verify failure
    nova_cmd = "%s nova floating-ip-disassociate %s %s" % \
               (_get_openstack_credentials(), symbols.bigip_name,
                symbols.ha_floating_ip)
    res = ssh.run(symbols.bastion, nova_cmd)
    # FIXME(kenr): nova returns a warning about an obsolete param we don't use.
    #              We should check for a return value instead of a string
    # assert res == ""

    time.sleep(2)
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res == ""

    # - move floating ip to second bigip and verify request succeeds
    #  using the same endpoints
    nova_cmd = "%s nova floating-ip-associate --fixed-address %s %s %s" % \
               (_get_openstack_credentials(), symbols.bigip2_ext_ip,
                symbols.bigip2_name, symbols.ha_floating_ip)
    res = ssh.run(symbols.bastion, nova_cmd)
    # assert res == ""

    time.sleep(2)
    for idx in range(0, 20):
        res = ssh.run(symbols.bastion, curl_cmd)
        assert res.startswith("Hello from ")
        endpoints[res.split(" ")[2]] = True
    assert len(endpoints) == endpoints_count

    # - verify that the second bigip used all the endpoints the first one used
    for endpoint in endpoints:
        assert endpoints[endpoint] is True

    # - remove floating ip and verify failure
    nova_cmd = "%s nova floating-ip-disassociate %s %s" % \
               (_get_openstack_credentials(), symbols.bigip2_name,
                symbols.ha_floating_ip)
    res = ssh.run(symbols.bastion, nova_cmd)
    # assert res == ""

    time.sleep(2)
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res == ""

    # - move floating ip back to first bigip and verify a request succeeds
    nova_cmd = "%s nova floating-ip-associate --fixed-address %s %s %s" % \
               (_get_openstack_credentials(), symbols.bigip_ext_ip,
                symbols.bigip_name, symbols.ha_floating_ip)
    res = ssh.run(symbols.bastion, nova_cmd)
    # assert res == ""

    time.sleep(2)
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res.startswith("Hello from ")


def _get_openstack_credentials():
    return "export OS_PROJECT_NAME=%s && " \
           "export OS_USERNAME=%s && " \
           "export OS_PASSWORD=%s && " \
           "export OS_AUTH_URL=%s && " % \
           (os.environ['OS_PROJECT_NAME'], os.environ['OS_USERNAME'],
            os.environ['OS_PASSWORD'], os.environ['OS_AUTH_URL'])


def _get_https_config(mode, port, svc=utils.DEFAULT_SVC_CONFIG):
    if symbols.orchestration == "marathon":
        cfg = copy.deepcopy(svc)
        cfg['F5_0_SSL_PROFILE'] = utils.DEFAULT_SVC_SSL_PROFILE
        if mode is not None:
            cfg['F5_0_MODE'] = mode
        if port is not None:
            cfg['F5_0_PORT'] = port
    if utils.is_kubernetes():
        cfg = copy.deepcopy(svc)
        frontend = cfg['data']['data']['virtualServer']['frontend']
        frontend['sslProfile'] = {
            'f5ProfileName': utils.DEFAULT_SVC_SSL_PROFILE
        }
        if mode is not None:
            frontend['mode'] = mode
        if port is not None:
            frontend['virtualAddress']['port'] = port
    return cfg
