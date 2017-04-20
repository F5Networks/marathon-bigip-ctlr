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

"""Test suite to verify pool only scenarios."""

import copy

from pytest import meta_suite, meta_test, symbols
from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "pool"])


@meta_test(id="f5mlb-78", tags=[])
def test_create_update_delete_pool_only(orchestration, bigip,
                                        bigip_controller):
    """Pool only mode north-south test.

    Verify the creation, updation, and deletion of a pool.
    """
    # - verify bigip is in a clean state
    assert utils.get_backend_objects(bigip) == {}, 'BIG-IP not clean at start'

    # - create managed pool only service (no virtual server)
    name = "pool-only-svc"
    config = _create_pool_only_config()
    svc = utils.create_managed_northsouth_service(orchestration, id=name,
                                                  config=config)
    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc, bigip_controller, pool_only=True)
    orig_backend_objs = utils.get_backend_objects(bigip)

    # - update managed pool only load balancing (no change to other backends)
    if symbols.orchestration == 'marathon':
        config['F5_0_BALANCE'] = "ratio-session"
    elif utils.is_kubernetes():
        config['data']['data']['virtualServer']['frontend']['balance'] = \
            "ratio-session"
    utils.update_svc_config(config, orchestration, name)

    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc, bigip_controller, pool_only=True)
    new_backend_objs = utils.get_backend_objects(bigip)

    # - verify the pool update
    for key in ['pools', 'health_monitors']:
        assert new_backend_objs[key] == orig_backend_objs[key], \
            '%s should not have been updated' % key
    if utils.is_kubernetes():
        _verify_kubernetes_nodes_pool_members(new_backend_objs,
                                              orig_backend_objs)

    # - delete the managed service
    svc.delete()
    # - verify bigip is cleaned up
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}, 'Objects not deleted'


@meta_test(id="f5mlb-79", tags=[])
def test_pool_only_add_virtual_server(orchestration, bigip, bigip_controller):
    """Add virtual server to pool.

    Verify that a virtual server can be added to a pool.
    """
    # - verify bigip is in a clean state
    assert utils.get_backend_objects(bigip) == {}, 'BIG-IP not clean at start'

    # - create managed pool only service (no virtual server)
    name = "pool-vs-svc"
    config = _create_pool_only_config()
    svc = utils.create_managed_northsouth_service(orchestration, id=name,
                                                  config=config)
    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc, bigip_controller, pool_only=True)
    orig_backend_objs = utils.get_backend_objects(bigip)

    # - add virtual server to managed pool only service
    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    utils.update_svc_config(config, orchestration, name)
    utils.wait_for_bigip_controller()
    new_backend_objs = utils.get_backend_objects(bigip)

    # - verify the virtual server was added
    _verify_pool_vs_transition(orig_backend_objs, new_backend_objs)


@meta_test(id="f5mlb-80", tags=[])
def test_pool_only_remove_virtual_server(orchestration, bigip,
                                         bigip_controller):
    """Remove virtual server from pool.

    Verify that a virtual server can be removed from a pool.
    """
    # - verify bigip is in a clean state
    assert utils.get_backend_objects(bigip) == {}, 'BIG-IP not clean at start'

    # - create managed service (with virtual server)
    name = "vs-pool-svc"
    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    svc = utils.create_managed_northsouth_service(orchestration, id=name,
                                                  config=config)
    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc, bigip_controller)
    orig_backend_objs = utils.get_backend_objects(bigip)

    # - remove virtual server from managed service
    config = _create_pool_only_config()
    utils.update_svc_config(config, orchestration, name)
    utils.wait_for_bigip_controller()
    new_backend_objs = utils.get_backend_objects(bigip)

    # - verify the virtual server was removed
    _verify_pool_vs_transition(new_backend_objs, orig_backend_objs)


@meta_test(id="f5mlb-81", tags=[])
def test_pool_only_to_iapp_transition(orchestration, bigip, bigip_controller):
    """Transition from pool only to iapp test.

    Verify that transition from pool only to iapp is correct.
    """
    # - verify bigip is in a clean state
    assert utils.get_backend_objects(bigip) == {}, 'BIG-IP not clean at start'

    # create managed pool only service
    name = "pool-iapp-svc"
    config = _create_pool_only_config()
    svc = utils.create_managed_northsouth_service(orchestration, id=name,
                                                  config=config)
    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc, bigip_controller, pool_only=True)
    orig_backend_objs = utils.get_backend_objects(bigip)

    # - create and add the iapp
    iapp = utils.SampleHttpIApp()
    config = copy.deepcopy(utils.get_iapp_config(iapp))
    utils.update_svc_config(config, orchestration, name)
    utils.wait_for_bigip_controller()
    new_backend_objs = utils.get_backend_objects(bigip)

    # verify pool has been removed
    _verify_pool_iapp_transition(orig_backend_objs, new_backend_objs)


@meta_test(id="f5mlb-82", tags=[])
def test_iapp_to_pool_only_transition(orchestration, bigip, bigip_controller):
    """Transition from iapp to pool only test.

    Verify that transition from iapp to pool only is correct.
    """
    # - verify bigip is in a clean state
    assert utils.get_backend_objects(bigip) == {}, 'BIG-IP not clean at start'

    # - create the managed iapp service
    name = "iapp-pool-svc"
    iapp = utils.SampleHttpIApp()
    config = copy.deepcopy(utils.get_iapp_config(iapp))
    utils.create_managed_northsouth_service(orchestration, id=name,
                                            config=config)
    utils.wait_for_bigip_controller()
    orig_backend_objs = utils.get_backend_objects(bigip)

    # - create and add the pool
    config = _create_pool_only_config()
    utils.update_svc_config(config, orchestration, name)
    utils.wait_for_bigip_controller()
    new_backend_objs = utils.get_backend_objects(bigip)

    # - verify iapp has been removed
    _verify_pool_iapp_transition(new_backend_objs, orig_backend_objs)


@meta_test(id="f5mlb-83", tags=[])
def test_delete_pool_before_virtual_server(orchestration, bigip,
                                           bigip_controller):
    """Test deleting a pool before deleting a virtual.

    Verify that deleting a pool before the virtual server fails.
    """
    # - verify bigip is in a clean state
    assert utils.get_backend_objects(bigip) == {}, 'BIG-IP not clean at start'

    # - create managed pool only service (no virtual server)
    name = "delete-svc"
    config = _create_pool_only_config()
    utils.create_managed_northsouth_service(orchestration, id=name,
                                            config=config)
    utils.wait_for_bigip_controller()

    # - add virtual server to managed pool only service
    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    utils.update_svc_config(config, orchestration, name)
    utils.wait_for_bigip_controller()

    # - verify that the pool can not be deleted
    if symbols.orchestration == 'marathon':
        pool_name = name + "_" + str(utils.DEFAULT_F5MLB_PORT)
    elif utils.is_kubernetes():
        pool_name = utils.DEFAULT_F5MLB_NAMESPACE + "_" + name + "-map"

    e_msg = ("The Pool (/test/%s) cannot be deleted because it is in use by a"
             " Virtual Server" % pool_name)
    try:
        bigip.pools.delete(partition=utils.DEFAULT_F5MLB_PARTITION)
    except Exception, e:
        assert e_msg in str(e)


def _create_pool_only_config():
    """Create a pool only config from DEFAULT_SVC_CONFIG."""
    pool_only_config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)

    if symbols.orchestration == "marathon":
        pool_only_config.pop('F5_0_BIND_ADDR')
    elif utils.is_kubernetes():
        pool_only_config['data']['data']['virtualServer']['frontend'].pop(
            'virtualAddress')
    else:
        raise ValueError('Unknown orchestration environment')

    return pool_only_config


def _verify_virtual_servers(pool, vs):
    """Verify virtual server or lack there of."""
    for key in ['virtual_addresses', 'virtual_servers']:
        assert key in vs, '%s should be on BIG-IP' % key
        assert key not in pool, '%s should be not be on BIG-IP' % key


def _verify_kubernetes_nodes_pool_members(updated, original):
    """Verify nodes and pool_members do not get updated."""
    # Note: in marathon updating the apps labels cause the app to be redeployed
    # so the pool_members and the nodes get updated as well. This is not the
    # case in kubernetes.
    for key in ['nodes', 'pool_members']:
        assert updated[key] == original[key], \
            '%s should not have been updated in k8s' % key


def _verify_pool_vs_transition(pool_results, vs_results):
    """Verify pool only to virtual server transition and vice versa."""
    _verify_virtual_servers(pool_results, vs_results)

    for key in ['pools', 'health_monitors']:
        assert pool_results[key] == vs_results[key], \
            '%s should not have been updated' % key

    if utils.is_kubernetes():
        _verify_kubernetes_nodes_pool_members(pool_results, vs_results)


def _verify_pool_iapp_transition(pool_results, iapp_results):
    """Verify pool only to iapp transition and vice versa."""
    _verify_virtual_servers(pool_results, iapp_results)

    for key in ['pools', 'health_monitors']:
        assert pool_results[key] != iapp_results[key], \
            '%s should have been updated' % key

    if utils.is_kubernetes():
        _verify_kubernetes_nodes_pool_members(pool_results, iapp_results)
