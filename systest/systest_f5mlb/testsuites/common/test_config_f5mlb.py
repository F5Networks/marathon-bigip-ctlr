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

"""Test suite to verify bigip-controller configuration parameters."""


from pytest import meta_suite, meta_test


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "config"])


@meta_test(id="f5mlb-28", tags=["incomplete"])
def test_f5mlb_config_invalid_partition(orchestration):
    """Verify response when the bigip 'partition' value is invalid."""
    pass


@meta_test(id="f5mlb-29", tags=["incomplete"])
def test_f5mlb_config_invalid_hostname(orchestration):
    """Verify response when the bigip 'hostname' value is invalid."""
    pass


@meta_test(id="f5mlb-30", tags=["incomplete"])
def test_f5mlb_config_invalid_creds(orchestration):
    """Verify response when the bigip user credentials are invalid."""
    pass


@meta_test(id="f5mlb-33", tags=["incomplete"])
def test_f5mlb_config_valid_health_check(orchestration):
    """Verify response when the 'health-check' value is valid."""
    pass


@meta_test(id="f5mlb-34", tags=["incomplete", "no_k8s"])
def test_f5mlb_config_invalid_health_check(orchestration):
    """Verify response when the 'health-check' value is invalid."""
    pass


@meta_test(id="f5mlb-37", tags=["incomplete"])
def test_f5mlb_config_valid_log_format(orchestration):
    """Verify response when the 'log-format' value is valid."""
    pass


@meta_test(id="f5mlb-38", tags=["incomplete"])
def test_f5mlb_config_invalid_log_format(orchestration):
    """Verify response when the 'log-format' value is invalid."""
    pass


@meta_test(id="f5mlb-46", tags=["incomplete"])
def test_f5mlb_config_valid_orchestration_timeout(orchestration):
    """Verify response when the orchestration 'timeout' value is valid."""
    pass


@meta_test(id="f5mlb-47", tags=["incomplete"])
def test_f5mlb_config_invalid_orchestration_timeout(orchestration):
    """Verify response when the orchestration 'timeout' value is invalid."""
    pass
