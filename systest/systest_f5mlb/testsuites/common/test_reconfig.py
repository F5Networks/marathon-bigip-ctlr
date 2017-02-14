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

"""Test suite to verify scenarios with reconfigs from the orchestration env."""

import pykube
import json
from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils

pytestmark = meta_suite(tags=["func", "marathon", "k8s", "reconfig"])


@meta_test(id="f5mlb-67", tags=[])
def test_reconfig_health_monitor_protocol(orchestration, bigip,
                                          bigip_controller):
    """Reconfigure health monitor protocol in the orchestration environment.

    When it realizes that the HM protocol has changed, bigip-controller
    will delete the old one and create a new one.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # Verify that the Health Monitor exists and the pool
    # members are healthy
    health_monitor = bigip.health_monitor.http.get(
        name=obj_name, partition=utils.DEFAULT_F5MLB_PARTITION)
    assert health_monitor is not None

    backend_objs = utils.get_backend_objects(bigip)
    for pool in backend_objs['pools']:
        members = bigip.pool_members.get(
            pool=pool, partition=utils.DEFAULT_F5MLB_PARTITION)
        for member in members:
            assert member.state == 'up'

    if symbols.orchestration == "marathon":
        # Change the protocol in Marathon
        svc.health_checks[0].protocol = 'TCP'
        svc.update()
    elif symbols.orchestration == "k8s":
        # Change the protocol in Kubernetes
        configmap = pykube.ConfigMap.objects(svc._api).get_by_name(
            "%s-map" % svc.id)
        data = json.loads(configmap.obj['data']['data'])
        data['virtualServer']['backend']['healthMonitors'][0]['protocol'] \
            = 'tcp'
        configmap.obj['data']['data'] = json.dumps(data)
        configmap.update()

    utils.wait_for_bigip_controller()

    # Verify the Health Monitor change
    health_monitor = bigip.health_monitor.http.get(
        name=obj_name, partition=utils.DEFAULT_F5MLB_PARTITION)
    new_health_monitor = bigip.health_monitor.tcp.get(
        name=obj_name, partition=utils.DEFAULT_F5MLB_PARTITION)
    assert health_monitor is None
    assert new_health_monitor is not None

    # Verify that the pool members are still healthy
    backend_objs = utils.get_backend_objects(bigip)
    for pool in backend_objs['pools']:
        members = bigip.pool_members.get(
            pool=pool, partition=utils.DEFAULT_F5MLB_PARTITION)
        for member in members:
            assert member.state == 'up'
