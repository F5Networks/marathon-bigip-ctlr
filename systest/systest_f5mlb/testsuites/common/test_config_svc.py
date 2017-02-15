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


from pytest import meta_suite, meta_test

from . import config_utils


pytestmark = meta_suite(tags=["func", "config", "marathon", "k8s"])


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
