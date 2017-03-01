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

import pytest
from pytest import symbols, meta_suite, meta_test

import systest_common.src as common


pytestmark = meta_suite(
    tags=["func", "marathon", "no_k8s", "no_openshift", "config"]
)


@pytest.fixture(scope='module', autouse=True)
def marathon(request):
    """Provide a marathon connection."""
    return common.marathon.connect(**vars(symbols))


@meta_test(id="f5mlb-27", tags=["incomplete"])
def test_bigip_controller_config_invalid_marathon_url(marathon):
    """Verify response when the 'marathon_url' value is invalid."""
    # - marathon url not provided
    # - marathon url not a valid url
    # - marathon url not a working marathon instance
    # - marathon url with no port number
    pass
