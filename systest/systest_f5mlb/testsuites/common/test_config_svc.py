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

"""Test suite to verify managed north-south service config parameters."""

import subprocess
import copy

from pytest import meta_suite, meta_test, symbols

from . import config_utils, utils


pytestmark = meta_suite(tags=["func", "config", "marathon", "k8s",
                              "openshift"])


@meta_test(id="f5mlb-48", tags=[""])
def test_svc_config_invalid_partition(
        ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'partition' value is invalid."""
    invalid_vals = ["", "does-not-exist"]
    for invalid_val in invalid_vals:
        config_utils.verify_config_produces_unmanaged_svc(
            orchestration, bigip, param="partition", input_val=invalid_val
        )


@meta_test(id="f5mlb-49", tags=[""])
def test_svc_config_invalid_bind_addr(
        ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'bind_addr' value is invalid."""
    invalid_vals = ["", "abc", "300.300.300.300"]
    for invalid_val in invalid_vals:
        config_utils.verify_config_produces_unmanaged_svc(
            orchestration, bigip, param="bind_addr", input_val=invalid_val
        )


@meta_test(id="f5mlb-50", tags=[""])
def test_svc_config_invalid_port(ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'port' value is invalid."""
    invalid_vals = ["", 0, -80, 65536]
    for invalid_val in invalid_vals:
        config_utils.verify_config_produces_unmanaged_svc(
            orchestration, bigip, param="port", input_val=invalid_val
        )


@meta_test(id="f5mlb-51", tags=[""])
def test_svc_config_valid_mode(ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'mode' value is valid."""
    valid_vals = ["tcp", "http"]
    for valid_val in valid_vals:
        config_utils.verify_config_produces_managed_svc(
            orchestration, bigip, bigip_controller, param="mode",
            input_val=valid_val
        )


@meta_test(id="f5mlb-52", tags=[""])
def test_svc_config_invalid_mode(ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'mode' value is invalid."""
    invalid_vals = ["", "does-not-exist"]
    for invalid_val in invalid_vals:
        config_utils.verify_config_produces_unmanaged_svc(
            orchestration, bigip, param="mode", input_val=invalid_val
        )


@meta_test(id="f5mlb-53", tags=[""])
def test_svc_config_valid_balance(ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'lb_algorithm' value is valid."""
    valid_vals = ["least-sessions"]
    for valid_val in valid_vals:
        config_utils.verify_config_produces_managed_svc(
            orchestration, bigip, bigip_controller, param="lb_algorithm",
            input_val=valid_val
        )


@meta_test(id="f5mlb-54", tags=[""])
def test_svc_config_invalid_balance(
        ssh, orchestration, bigip, bigip_controller):
    """Verify response when the 'lb_algorithm' value is invalid."""
    invalid_vals = ["", "does-not-exist"]
    for invalid_val in invalid_vals:
        config_utils.verify_config_produces_unmanaged_svc(
            orchestration, bigip, param="lb_algorithm", input_val=invalid_val
        )


@meta_test(id="f5mlb-55", tags=[""])
def test_svc_config_bind_addr_added(ssh, orchestration,
                                    bigip, bigip_controller):
    """Verify response when the 'bind_addr' value is not initially configured.

    and then is added.
    """
    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    if symbols.orchestration == "marathon":
        del config['F5_0_BIND_ADDR']
    elif utils.is_kubernetes():
        frontend = config['data']['data']['virtualServer']['frontend']
        del frontend['virtualAddress']['bindAddr']
    svc = utils.create_managed_northsouth_service(orchestration, config=config)
    # - verify service is deployed
    assert svc.instances.count() > 0
    # - verify no bigip objects created for unmanaged service
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}

    if symbols.orchestration == "marathon":
        config = config_utils.get_managed_northsouth_service_config(
            "bind_addr", utils.DEFAULT_F5MLB_BIND_ADDR)
        orchestration.app.update(
            id=svc.id, labels=config,
            health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_HTTP)
    elif utils.is_kubernetes():
        annotate = ['kubectl', 'annotate', 'configmap',
                    '{}-map'.format(svc.id),
                    'virtual-server.f5.com/ip={}'
                    .format(utils.DEFAULT_F5MLB_BIND_ADDR)]
        subprocess.call(annotate, stdout=subprocess.PIPE)

    # - verify service is deployed
    assert svc.instances.count() > 0
    # - verify bigip objects created for managed service
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
