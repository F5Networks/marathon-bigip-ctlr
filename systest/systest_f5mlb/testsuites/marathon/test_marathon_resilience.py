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

"""Tests for the behavior of the bigip-controller when Marathon goes down."""

import time

import pytest
import requests

from .. import utils

pytestmark = pytest.meta_suite(
    tags=["func", "marathon", "no_k8s", "no_openshift"]
)


@pytest.meta_test(id='f5mlb-65', tags=[])
def test_no_disruptions_without_marathon(orchestration, bigip,
                                         bigip_controller):
    """Assert Big-IP configuration doesn't change when Marathon is disabled."""
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    try:
        backend_before_config = utils.get_backend_objects(
            bigip, default_partition)
        utils.create_managed_northsouth_service(orchestration)
        utils.wait_for_bigip_controller()
        backend_before_stop = utils.get_backend_objects(
            bigip, default_partition)
        assert backend_before_stop != backend_before_config, \
            'Big-IP configuration not applied.'
        _stop_marathon()
        backend_after_stop = utils.get_backend_objects(
            bigip, default_partition)
        assert backend_after_stop == backend_before_stop, \
            'Big-IP configuration changed when Marathon stopped.'
    finally:
        _start_marathon()
        backend_after_start = utils.get_backend_objects(
            bigip, default_partition)
        assert backend_after_start == backend_after_stop, \
            'Big-IP configuration changed when Marathon restarted.'


def _stop_marathon():
    """Stop Marathon and verify that the process is gone."""
    pytest.masters_cmd('sudo service marathon stop')
    for _ in range(60):
        if not any(pytest.masters_cmd(r"ps -ef | grep '\/[m]arathon'")):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('Marathon still up after 30 seconds.')


def _start_marathon():
    """Start Marathon and verify it is serving connections."""
    pytest.masters_cmd('sudo service marathon start')
    for _ in range(120):
        try:
            if requests.get(pytest.symbols.marathon_url).ok:
                break
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError('Marathon not up after 60 seconds.')
