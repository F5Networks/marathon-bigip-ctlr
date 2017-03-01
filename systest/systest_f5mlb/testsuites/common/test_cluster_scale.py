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

"""Test suite to verify cluster node scaling scenarios."""

import collections
from subprocess import CalledProcessError
import time

from pytest import meta_suite, meta_test, symbols

from . import utils


pytestmark = meta_suite(
    tags=["func", "openshift", "clusterscale"]
)


def _verify_endpoints(actual, expected):
    act = collections.Counter(actual)

    for i in act.values():
        assert i == 1

    exp = collections.Counter(expected)
    return act == exp


def _poll_fdb_endpoints(bigip, expected):
    max_wait = 30
    waited = 0
    passed = False

    while not passed:
        actual = utils.get_backend_fdb_endpoints(bigip)
        if _verify_endpoints(actual, expected):
            passed = True
        else:
            if waited == max_wait:
                break
            time.sleep(1)
            waited += 1

    return passed


def _set_schedulable(args):
    assert 'node_controller' in args
    assert 'node' in args

    node_ctl = args['node_controller']
    node = args['node']

    node_ctl.mark_schedulability(True, node)


def _reset_node(args):
    assert 'node_controller' in args
    assert 'node' in args
    assert 'config' in args

    node_ctl = args['node_controller']
    node = args['node']
    config = args['config']

    try:
        node_ctl.get_node(node)
    except CalledProcessError:
        node_ctl.add_node(config)


@meta_test(id="f5mlb-69", tags=["no_marathon", "no_k8s"])
def test_clusterscale(ssh, orchestration, bigip, bigip_controller,
                      node_controller):
    """Cluster scaling north-south test.

    Verify correct updates when cluster nodes are added and removed.
    """
    msg = "Cluster scale tests must have more than 1 worker"
    assert len(symbols.worker_default_ips) > 1, msg
    expected = symbols.master_default_ips + symbols.worker_default_ips
    verified = _poll_fdb_endpoints(bigip, expected)
    assert verified is True

    svc = utils.create_managed_northsouth_service(orchestration, "svc-1")
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    svc.scale(2)
    assert svc.instances.count() == 2
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    utils.verify_bigip_round_robin(ssh, svc)

    # mark unschedulable and evacuate so we can still run traffic
    remove = symbols.worker_default_ips[1:]
    for node in remove:
        node_controller.mark_schedulability(False, node)
        node_controller.push_teardown(_set_schedulable,
                                      {"node": node,
                                       "node_controller": node_controller})
        verified = _poll_fdb_endpoints(bigip, expected)
        assert verified is True

        node_controller.evacuate(False, node)
        verified = _poll_fdb_endpoints(bigip, expected)
        assert verified is True

    # remove some nodes
    node_configs = []
    for idx, node in enumerate(remove):
        config = node_controller.get_node(node)
        node_controller.delete_node(node)
        node_controller.push_teardown(_reset_node,
                                      {"config": config,
                                       "node": node,
                                       "node_controller": node_controller})
        node_configs.append(config)

        expected = (symbols.master_default_ips +
                    [symbols.worker_default_ips[0]] +
                    remove[idx+1:])
        verified = _poll_fdb_endpoints(bigip, expected)
        assert verified is True

    for idx, _ in enumerate(remove):
        config = node_configs[idx]
        node_controller.add_node(config)

        expected = (symbols.master_default_ips +
                    [symbols.worker_default_ips[0]] +
                    remove[:idx+1])
        verified = _poll_fdb_endpoints(bigip, expected)
        assert verified is True

    node_controller.clear_teardowns()
