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

"""Verify the bigip-controller's ability to restore target configs."""


from pytest import meta_suite, meta_test

from . import utils


pytestmark = meta_suite(
    tags=["func", "marathon", "k8s", "openshift", "restore"]
)


@meta_test(id="f5mlb-2", tags=[])
def test_restore_after_backend_create(orchestration, bigip, bigip_controller):
    """Unmanaged bigip objects are added.

    When it realizes that unmanaged bigip objects have been added,
    bigip-controller will remove them.
    """
    # - add unmanaged backend objects
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    bigip.virtual_server.create(
        name="tst-virtual-server",
        partition=default_partition,
        destination="192.168.100.1:80"
    )
    bigip.pool.create(name="tst-pool", partition=default_partition)
    bigip.pool_member.create(
        name="192.168.200.1:80", pool="tst-pool", partition=default_partition)

    bigip.health_monitor.tcp.create(
        name="tst-health-monitor", partition=default_partition)

    # - verify unmanaged backend objects are deleted
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-3", tags=[])
def test_restore_after_virtual_server_update(
        orchestration, bigip, bigip_controller):
    """Managed virtual server is modified.

    When it realizes that a managed virtual server was modified,
    bigip-controller will reset the properties that it cares about and ignore
    the properties that it doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed virtual server and verify reset
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    vs_dest_orig = virtual_server.destination
    virtual_server.destination = "192.168.100.1:8080"
    virtual_server.description = "test-description"
    virtual_server.update()
    utils.wait_for_bigip_controller()
    virtual_server.refresh()
    assert virtual_server.destination == vs_dest_orig
    assert virtual_server.description == "test-description"


@meta_test(id="f5mlb-4", tags=[])
def test_restore_after_virtual_address_update(
        orchestration, bigip, bigip_controller):
    """Managed virtual address is modified.

    When it realizes that a managed virtual address was modified,
    bigip-controller will reset the properties that it cares about and ignore
    the properties that it doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()

    # - modify managed virtual address and verify reset
    virtual_address = bigip.virtual_address.get(
        name=utils.DEFAULT_F5MLB_BIND_ADDR, partition=default_partition
    )
    va_enabled_orig = virtual_address.enabled
    virtual_address.enabled = "no"
    virtual_address.description = "test-description"
    virtual_address.update()
    utils.wait_for_bigip_controller()
    virtual_address.refresh()
    assert virtual_address.enabled == va_enabled_orig
    assert virtual_address.description == "test-description"


@meta_test(id="f5mlb-5", tags=[])
def test_restore_after_pool_update(orchestration, bigip, bigip_controller):
    """Managed pool is modified.

    When it realizes that a managed pool was modified, bigip-controller will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed pool and verify reset
    pool = bigip.pool.get(name=obj_name, partition=default_partition)
    pool_lb_orig = pool.loadBalancingMode
    pool.loadBalancingMode = "least-connections-node"
    pool.description = "test-description"
    pool.update()
    utils.wait_for_bigip_controller()
    pool.refresh()
    assert pool.loadBalancingMode == pool_lb_orig
    assert pool.description == "test-description"


@meta_test(id="f5mlb-6", tags=["incomplete"])
def test_restore_after_pool_member_update(
        orchestration, bigip, bigip_controller):
    """Managed pool member is modified.

    When it realizes that a managed pool member was modified, bigip-controller
    will reset the properties that it cares about and ignore the properties
    that it doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    instances = svc.instances.get()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed pool member and verify reset
    pool_member = bigip.pool_member.get(
        name="%s:%d" % (instances[0].host, instances[0].ports[0]),
        pool=obj_name,
        partition=default_partition
    )
    member_state_orig = pool_member.state
    pool_member.description = "test-description"
    pool_member.update(state="user-down", session="user-disabled")
    utils.wait_for_bigip_controller()
    pool_member.refresh()
    assert pool_member.state == member_state_orig
    assert pool_member.description == "test-description"


@meta_test(id="f5mlb-7", tags=[])
def test_restore_after_node_update(orchestration, bigip, bigip_controller):
    """Managed node is modified.

    When it realizes that a managed node was modified, bigip-controller will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()

    # - modify managed node and verify reset
    members = bigip.pool_members.get(partition=default_partition)
    member_node_addrs = sorted([mem.address for mem in members])
    node = bigip.node.get(
        name=member_node_addrs[0], partition=default_partition
    )
    node_state_orig = node.state
    node.state = "user-down"
    node.description = "test-description"
    node.update()
    utils.wait_for_bigip_controller()
    node.refresh()
    assert node.state == node_state_orig
    assert node.description == "test-description"


@meta_test(id="f5mlb-8", tags=[])
def test_restore_after_health_monitor_update(
        orchestration, bigip, bigip_controller):
    """Managed health monitor is modified.

    When it realizes that a managed health monitor was modified,
    bigip-controller will reset the properties that it cares about and ignore
    the properties that it doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed health monitor and verify reset
    health_monitor = bigip.health_monitor.http.get(
        name=obj_name, partition=default_partition
    )
    hm_send_orig = health_monitor.send
    health_monitor.send = "GET /foo HTTP/1.0\\r\\n\\r\\n"
    health_monitor.description = "test-description"
    health_monitor.update()
    utils.wait_for_bigip_controller()
    health_monitor.refresh()
    assert health_monitor.send == hm_send_orig
    assert health_monitor.description == "test-description"


@meta_test(id="f5mlb-9", tags=[])
def test_restore_after_virtual_server_delete(
        orchestration, bigip, bigip_controller):
    """Managed virtual server is deleted.

    When it realizes that a managed virtual server is deleted,
    bigip-controller will recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed virtual server and verify recreate
    assert \
        bigip.virtual_servers.list(partition=default_partition) == [obj_name]
    bigip.virtual_server.delete(obj_name, partition=default_partition)
    utils.wait_for_bigip_controller()
    assert \
        bigip.virtual_servers.list(partition=default_partition) == [obj_name]


@meta_test(id="f5mlb-10", tags=[])
def test_restore_after_virtual_address_delete(
        orchestration, bigip, bigip_controller):
    """Managed virtual address is deleted.

    When it realizes that a managed virtual address is deleted,
    bigip-controller will recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed virtual address and verify recreate
    old_addr = utils.DEFAULT_F5MLB_BIND_ADDR
    new_addr = "192.168.100.1"
    assert \
        bigip.virtual_addresses.list(partition=default_partition) == [old_addr]
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    virtual_server.destination = new_addr + ":80"
    virtual_server.update()
    bigip.virtual_address.delete(old_addr, partition=default_partition)
    assert \
        bigip.virtual_addresses.list(partition=default_partition) == [new_addr]
    utils.wait_for_bigip_controller()
    # FIXME (darzins) Virtual Addresses should auto-delete when unreferenced,
    # but that doesn't happen (Bug 590377)
    assert \
        old_addr in bigip.virtual_addresses.list(partition=default_partition)


@meta_test(id="f5mlb-11", tags=[])
def test_restore_after_pool_delete(orchestration, bigip, bigip_controller):
    """Managed pool is deleted.

    When it realizes that a managed pool is deleted, bigip-controller will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed pool and verify recreate
    assert bigip.pools.list(partition=default_partition) == [obj_name]
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    virtual_server.pool = "None"
    virtual_server.update()
    bigip.pool.delete(name=obj_name, partition=default_partition)
    utils.wait_for_bigip_controller()
    assert bigip.pools.list(partition=default_partition) == [obj_name]


@meta_test(id="f5mlb-12", tags=[])
def test_restore_after_pool_member_delete(
        orchestration, bigip, bigip_controller):
    """Managed pool member is deleted.

    When it realizes that a managed pool member is deleted, bigip-controller
    will recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    objs = utils.get_backend_objects_exp(svc, bigip_controller)
    expected_members = objs['pool_members']

    # - delete managed pool member and verify recreate
    actual_members = sorted(
            bigip.pool_members.list(partition=default_partition))
    assert actual_members == expected_members
    bigip.pool_member.delete(
            name=actual_members[0], partition=default_partition)
    utils.wait_for_bigip_controller()
    actual_members = sorted(
            bigip.pool_members.list(partition=default_partition))
    assert actual_members == expected_members


@meta_test(id="f5mlb-13", tags=[])
def test_restore_after_node_delete(orchestration, bigip, bigip_controller):
    """Managed node is deleted.

    When it realizes that a managed node is deleted, bigip-controller will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()

    # - delete managed node and verify recreate
    # No pool members can exist that use the node, or it can't be deleted
    members = bigip.pool_members.get(partition=default_partition)
    node_names = sorted(bigip.nodes.list(partition=default_partition))
    member_node_addrs = sorted([mem.address for mem in members])
    assert len(node_names), "precondition: need nodes to exist"
    assert node_names == member_node_addrs, \
        "precondition: unexpected nodes don't exist"

    for member in members:
        if member.address == node_names[0]:
            member.delete()
    bigip.node.delete(node_names[0], partition=default_partition)

    utils.wait_for_bigip_controller()
    assert bigip.nodes.list(partition=default_partition) == node_names, \
        "The controller didn't recreate the deleted node"


@meta_test(id="f5mlb-14", tags=[])
def test_restore_after_health_monitor_delete(
        orchestration, bigip, bigip_controller):
    """Managed health monitor is deleted.

    When it realizes that a managed health monitor is deleted, bigip-controller
    will recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed health monitor and verify recreate
    assert (
        bigip.health_monitors.http.list(partition=default_partition) ==
        [obj_name]
    )
    pool = bigip.pool.get(name=obj_name, partition=default_partition)
    pool.monitor = "none"
    pool.update()
    bigip.health_monitor.http.delete(
        name=obj_name, partition=default_partition
    )
    utils.wait_for_bigip_controller()
    assert (
        bigip.health_monitors.http.list(partition=default_partition) ==
        [obj_name]
    )


@meta_test(id="f5mlb-15", tags=[])
def test_restore_after_bigip_controller_delete(
        orchestration, bigip, bigip_controller):
    """Bigip-controller is deleted (and no other changes).

    Neither the bigip nor managed service are changed while bigip-controller
    is gone, so there's nothing for bigip-controller to do when it comes back
    online.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    old_uid = svc.uid
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.delete()
    # - verify managed service is unchanged
    utils.wait_for_bigip_controller()
    assert svc.uid == old_uid
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate bigip-controller and verify restoration
    bigip_controller.create()
    utils.wait_for_bigip_controller()
    assert svc.uid == old_uid
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-16", tags=[])
def test_restore_after_bigip_controller_delete_then_svc_delete(
        orchestration, bigip, bigip_controller):
    """Bigip-controller and managed service are deleted.

    When the bigip-controller comes back online, it realizes that the managed
    bigip objects are orphaned and reaps them.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.delete()
    # - delete the managed service
    if utils.is_kubernetes():
        orchestration.namespace = "default"
    svc.delete()
    utils.wait_for_bigip_controller()
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate bigip-controller and verify restoration
    bigip_controller.create()
    utils.wait_for_bigip_controller()
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-17", tags=[])
def test_restore_after_bigip_controller_delete_then_svc_update(
        orchestration, bigip, bigip_controller):
    """Bigip-controller deleted, then managed service is changed.

    When the bigip-controller comes back online, it realizes that the managed
    bigip objects are orphaned (because the managed service is no longer
    properly configured to register with bigip-controller) and reaps them.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.delete()
    # - change the managed service
    utils.unmanage_northsouth_service(orchestration, svc)
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate bigip-controller and verify restoration
    bigip_controller.create()
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-18", tags=[])
def test_restore_after_bigip_controller_delete_then_backend_delete(
        orchestration, bigip, bigip_controller):
    """Bigip-controller and backend objects are deleted.

    When the bigip-controller comes back online, it realizes that managed bigip
    objects are missing, so it creates new ones.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.delete()
    # - delete the managed virtual server
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    obj_name = utils.get_backend_object_name(svc)
    bigip.virtual_server.delete(name=obj_name, partition=default_partition)
    utils.wait_for_bigip_controller()
    orig_vs_list = backend_objs_exp.pop('virtual_servers')
    orig_va_list = backend_objs_exp.pop('virtual_addresses')
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate bigip-controller and verify restoration
    bigip_controller.create()
    utils.wait_for_bigip_controller()
    backend_objs_exp['virtual_servers'] = orig_vs_list
    backend_objs_exp['virtual_addresses'] = orig_va_list
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-19", tags=[])
def test_restore_after_bigip_controller_delete_then_backend_update(
        orchestration, bigip, bigip_controller):
    """Bigip-controller deleted, then backend objects are changed.

    When the bigip-controller comes back online, it realizes that managed bigip
    objects were modified, so it resets the properties that it cares about and
    ignores the properties that it doesn't care about.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.delete()
    # - change the managed virtual server
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    obj_name = utils.get_backend_object_name(svc)
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    old_dest = virtual_server.destination
    new_addr = "192.168.100.1"
    new_port = "8080"
    new_dest = "/%s/%s:%s" % (default_partition, new_addr, new_port)
    assert new_dest != old_dest
    new_desc = "test-description"
    virtual_server.destination = new_dest
    virtual_server.description = new_desc
    virtual_server.update()
    virtual_server.refresh()
    assert virtual_server.destination == new_dest
    assert virtual_server.description == new_desc
    # - recreate bigip-controller and verify restoration
    bigip_controller.create()
    utils.wait_for_bigip_controller()
    virtual_server.refresh()
    assert virtual_server.destination == old_dest
    assert virtual_server.description == new_desc
    backend_objs_exp['virtual_addresses'] += [new_addr]
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-20", tags=[])
def test_restore_after_bigip_controller_suspend(
        orchestration, bigip, bigip_controller):
    """Bigip-controller is suspended (no other changes occur).

    Neither the bigip nor managed service are changed while bigip-controller
    is gone, so there's nothing for bigip-controller to do when it comes back
    online.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    old_uid = svc.uid
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.suspend()
    # - verify managed service is unchanged
    utils.wait_for_bigip_controller()
    assert svc.uid == old_uid
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume bigip-controller and verify restoration
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.resume()
    utils.wait_for_bigip_controller()
    assert svc.uid == old_uid
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-21", tags=[])
def test_restore_after_bigip_controller_suspend_then_svc_delete(
        orchestration, bigip, bigip_controller):
    """Bigip-controller suspended, then managed service is deleted.

    When the bigip-controller comes back online, it realizes that the managed
    bigip objects are orphaned and reaps them.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.suspend()
    # - delete the managed service
    if utils.is_kubernetes():
        orchestration.namespace = "default"
    svc.delete()
    utils.wait_for_bigip_controller()
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume bigip-controller and verify restoration
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.resume()
    utils.wait_for_bigip_controller()
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-22", tags=[])
def test_restore_after_bigip_controller_suspend_then_svc_update(
        orchestration, bigip, bigip_controller):
    """Bigip-controller suspended, then managed service is changed.

    When the bigip-controller comes back online, it realizes that the managed
    bigip objects are orphaned (because the managed service is no longer
    properly configured to register with bigip-controller) and reaps them.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.suspend()
    # - change the managed service
    utils.unmanage_northsouth_service(orchestration, svc)
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume bigip-controller and verify restoration
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.resume()
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-23", tags=[])
def test_restore_after_bigip_controller_suspend_then_backend_delete(
        orchestration, bigip, bigip_controller):
    """Bigip-controller suspended, then backend objects are deleted.

    When the bigip-controller comes back online, it realizes that managed bigip
    objects are missing, so it creates new ones.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.suspend()
    # - delete the managed virtual server
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    obj_name = utils.get_backend_object_name(svc)
    bigip.virtual_server.delete(name=obj_name, partition=default_partition)
    orig_vs_list = backend_objs_exp.pop('virtual_servers')
    orig_va_list = backend_objs_exp.pop('virtual_addresses')
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume bigip-controller and verify restoration
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.resume()
    utils.wait_for_bigip_controller()
    backend_objs_exp['virtual_servers'] = orig_vs_list
    backend_objs_exp['virtual_addresses'] = orig_va_list
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-24", tags=[])
def test_restore_after_bigip_controller_suspend_then_backend_update(
        orchestration, bigip, bigip_controller):
    """Bigip-controller suspended, then backend objects are changed.

    When the bigip-controller comes back online, it realizes that managed bigip
    objects were modified, so it resets the properties that it cares about and
    ignores the properties that it doesn't care about.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.suspend()
    # - change the managed virtual server
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    obj_name = utils.get_backend_object_name(svc)
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    old_dest = virtual_server.destination
    new_addr = "192.168.100.1"
    new_port = "8080"
    new_dest = "/%s/%s:%s" % (default_partition, new_addr, new_port)
    assert new_dest != old_dest
    new_desc = "test-description"
    virtual_server.destination = new_dest
    virtual_server.description = new_desc
    virtual_server.update()
    virtual_server.refresh()
    assert virtual_server.destination == new_dest
    assert virtual_server.description == new_desc
    # - resume bigip-controller and verify restoration
    if utils.is_kubernetes():
        orchestration.namespace = utils.controller_namespace()
    bigip_controller.resume()
    utils.wait_for_bigip_controller()
    virtual_server.refresh()
    assert virtual_server.destination == old_dest
    assert virtual_server.description == new_desc
    backend_objs_exp['virtual_addresses'] += [new_addr]
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-25", tags=["incomplete"])
def test_restore_after_partition_delete_has_backup(
        orchestration, bigip, bigip_controller):
    """One (of two) partitions with bigip-controller objects is deleted.

    When it realizes that a partition with managed objects was deleted,
    bigip-controller will recreate them on the next available managed
    partition.
    """
    pass


@meta_test(id="f5mlb-26", tags=["incomplete"])
def test_restore_after_partition_delete_no_backup(
        orchestration, bigip, bigip_controller):
    """Sole partition with bigip-controller objects is deleted.

    When it realizes that a partition with managed objects was deleted,
    bigip-controller will recreate them on the next managed partition that
    becomes available.
    """
    pass


@meta_test(id="f5mlb-64", tags=[])
def test_restore_after_svc_becomes_unmanaged(
        orchestration, bigip, bigip_controller):
    """Bigip-controller decorations are removed from a managed service.

    When the bigip-controller realizes that the managed bigip objects are
    orphaned, it reaps them.
    """
    svc = utils.create_managed_northsouth_service(orchestration)
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - remove bigip-controller decorations from the managed service
    utils.unmanage_northsouth_service(orchestration, svc)
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}
