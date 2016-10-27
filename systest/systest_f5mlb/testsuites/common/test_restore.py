"""Test suite to verify f5mlb's ability to restore target configs."""


from pytest import meta_suite, meta_test

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "restore"])

RESTORE_TIMEOUT = 5


@meta_test(id="f5mlb-2", tags=[])
def test_restore_after_backend_create(orchestration, bigip, f5mlb):
    """Verify response when unmanaged bigip objects are added.

    When it realizes that unmanaged bigip objects have been added, f5mlb will
    remove them.
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
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-3", tags=[])
def test_restore_after_virtual_server_update(orchestration, bigip, f5mlb):
    """Verify response when managed virtual server is modified.

    When it realizes that a managed virtual server was modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed virtual server and verify reset
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    vs_dest_orig = virtual_server.destination
    virtual_server.destination = "192.168.100.1:8080"
    virtual_server.description = "test-description"
    virtual_server.update()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    virtual_server.refresh()
    assert virtual_server.destination == vs_dest_orig
    assert virtual_server.description == "test-description"


@meta_test(id="f5mlb-4", tags=[])
def test_restore_after_virtual_address_update(orchestration, bigip, f5mlb):
    """Verify response when managed virtual address is modified.

    When it realizes that a managed virtual address was modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()

    # - modify managed virtual address and verify reset
    virtual_address = bigip.virtual_address.get(
        name=svc.labels['F5_0_BIND_ADDR'], partition=default_partition
    )
    va_enabled_orig = virtual_address.enabled
    virtual_address.enabled = "no"
    virtual_address.description = "test-description"
    virtual_address.update()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    virtual_address.refresh()
    assert virtual_address.enabled == va_enabled_orig
    assert virtual_address.description == "test-description"


@meta_test(id="f5mlb-5", tags=[])
def test_restore_after_pool_update(orchestration, bigip, f5mlb):
    """Verify response when managed pool is modified.

    When it realizes that a managed pool was modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed pool and verify reset
    pool = bigip.pool.get(name=obj_name, partition=default_partition)
    pool_lb_orig = pool.loadBalancingMode
    pool.loadBalancingMode = "least-connections-node"
    pool.description = "test-description"
    pool.update()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    pool.refresh()
    assert pool.loadBalancingMode == pool_lb_orig
    assert pool.description == "test-description"


@meta_test(id="f5mlb-6", tags=["incomplete"])
def test_restore_after_pool_member_update(orchestration, bigip, f5mlb):
    """Verify response when managed pool member is modified.

    When it realizes that a managed pool member was modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
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
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    pool_member.refresh()
    assert pool_member.state == member_state_orig
    assert pool_member.description == "test-description"


@meta_test(id="f5mlb-7", tags=[])
def test_restore_after_node_update(orchestration, bigip, f5mlb):
    """Verify response when managed node is modified.

    When it realizes that a managed node was modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    instances = svc.instances.get()

    # - modify managed node and verify reset
    node = bigip.node.get(
        name=instances[0].host, partition=default_partition
    )
    node_state_orig = node.state
    node.state = "user-down"
    node.description = "test-description"
    node.update()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    node.refresh()
    assert node.state == node_state_orig
    assert node.description == "test-description"


@meta_test(id="f5mlb-8", tags=[])
def test_restore_after_health_monitor_update(orchestration, bigip, f5mlb):
    """Verify response when managed health monitor is modified.

    When it realizes that a managed health monitor was modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    obj_name = utils.get_backend_object_name(svc)

    # - modify managed health monitor and verify reset
    health_monitor = bigip.health_monitor.http.get(
        name=obj_name, partition=default_partition
    )
    hm_send_orig = health_monitor.send
    health_monitor.send = "GET /foo HTTP/1.0\\r\\n\\r\\n"
    health_monitor.description = "test-description"
    health_monitor.update()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    health_monitor.refresh()
    assert health_monitor.send == hm_send_orig
    assert health_monitor.description == "test-description"


@meta_test(id="f5mlb-9", tags=[])
def test_restore_after_virtual_server_delete(orchestration, bigip, f5mlb):
    """Verify response when managed virtual server is deleted.

    When it realizes that a managed virtual server is deleted, f5mlb will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed virtual server and verify recreate
    assert \
        bigip.virtual_servers.list(partition=default_partition) == [obj_name]
    bigip.virtual_server.delete(obj_name, partition=default_partition)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert \
        bigip.virtual_servers.list(partition=default_partition) == [obj_name]


@meta_test(id="f5mlb-10", tags=[])
def test_restore_after_virtual_address_delete(orchestration, bigip, f5mlb):
    """Verify response when managed virtual address is deleted.

    When it realizes that a managed virtual address is deleted, f5mlb will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed virtual address and verify recreate
    old_addr = svc.labels['F5_0_BIND_ADDR']
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
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    # FIXME (darzins) Virtual Addresses should auto-delete when unreferenced,
    # but that doesn't happen (Bug 590377)
    assert \
        old_addr in bigip.virtual_addresses.list(partition=default_partition)


@meta_test(id="f5mlb-11", tags=[])
def test_restore_after_pool_delete(orchestration, bigip, f5mlb):
    """Verify response when managed pool is deleted.

    When it realizes that a managed pool is deleted, f5mlb will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    obj_name = utils.get_backend_object_name(svc)

    # - delete managed pool and verify recreate
    assert bigip.pools.list(partition=default_partition) == [obj_name]
    virtual_server = bigip.virtual_server.get(
        name=obj_name, partition=default_partition
    )
    virtual_server.pool = "None"
    virtual_server.update()
    bigip.pool.delete(name=obj_name, partition=default_partition)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert bigip.pools.list(partition=default_partition) == [obj_name]


@meta_test(id="f5mlb-12", tags=[])
def test_restore_after_pool_member_delete(orchestration, bigip, f5mlb):
    """Verify response when managed pool member is deleted.

    When it realizes that a managed pool member is deleted, f5mlb will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    instances = svc.instances.get()
    obj_name = "%s:%d" % (instances[0].host, instances[0].ports[0])

    # - delete managed pool member and verify recreate
    assert bigip.pool_members.list(partition=default_partition) == [obj_name]
    bigip.pool_member.delete(name=obj_name, partition=default_partition)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert bigip.pool_members.list(partition=default_partition) == [obj_name]


@meta_test(id="f5mlb-13", tags=[])
def test_restore_after_node_delete(orchestration, bigip, f5mlb):
    """Verify response when managed node is deleted.

    When it realizes that a managed node is deleted, f5mlb will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
    instances = svc.instances.get()
    obj_name = instances[0].host
    member_name = "%s:%d" % (instances[0].host, instances[0].ports[0])

    # - delete managed node and verify recreate
    assert bigip.nodes.list(partition=default_partition) == [obj_name]
    bigip.pool_member.delete(name=member_name, partition=default_partition)
    bigip.node.delete(obj_name, partition=default_partition)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert bigip.nodes.list(partition=default_partition) == [obj_name]


@meta_test(id="f5mlb-14", tags=[])
def test_restore_after_health_monitor_delete(orchestration, bigip, f5mlb):
    """Verify response when managed health monitor is deleted.

    When it realizes that a managed health monitor is deleted, f5mlb will
    recreate it.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    svc = utils.create_managed_service(orchestration)
    utils.wait_for_f5mlb()
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
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert (
        bigip.health_monitors.http.list(partition=default_partition) ==
        [obj_name]
    )


@meta_test(id="f5mlb-15", tags=[])
def test_restore_after_f5mlb_delete(orchestration, bigip, f5mlb):
    """Verify response when f5mlb is deleted (no other changes occur).

    Neither the bigip nor managed service are changed while f5mlb is gone, so
    there's nothing for f5mlb to do when it comes back online.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    old_svc = svc.freeze()
    f5mlb.delete()
    # - verify managed service is unchanged
    utils.wait_for_f5mlb()
    assert svc.diff(old_svc) == {}
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate f5mlb and verify restoration
    f5mlb = utils.create_f5mlb(orchestration)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert svc.diff(old_svc) == {}
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-16", tags=[])
def test_restore_after_f5mlb_delete_then_svc_delete(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb and the managed service are deleted.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned and reaps them.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    f5mlb.delete()
    # - delete the managed service
    svc.delete()
    utils.wait_for_f5mlb()
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate f5mlb and verify restoration
    f5mlb = utils.create_f5mlb(orchestration)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-17", tags=[])
def test_restore_after_f5mlb_delete_then_svc_update(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb deleted, then managed service is changed.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned (because the managed service is no longer properly
    configured to register with f5mlb) and reaps them.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    f5mlb.delete()
    # - change the managed service
    svc.labels = {}
    svc.update()
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate f5mlb and verify restoration
    f5mlb = utils.create_f5mlb(orchestration)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-18", tags=[])
def test_restore_after_f5mlb_delete_then_backend_delete(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb and backend objects are deleted.

    When the f5mlb comes back online, it realizes that managed bigip objects
    are missing, so it creates new ones.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    f5mlb.delete()
    # - delete the managed virtual server
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    obj_name = utils.get_backend_object_name(svc)
    bigip.virtual_server.delete(name=obj_name, partition=default_partition)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    orig_vs_list = backend_objs_exp.pop('virtual_servers')
    orig_va_list = backend_objs_exp.pop('virtual_addresses')
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - recreate f5mlb and verify restoration
    f5mlb = utils.create_f5mlb(orchestration)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    backend_objs_exp['virtual_servers'] = orig_vs_list
    backend_objs_exp['virtual_addresses'] = orig_va_list
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-19", tags=[])
def test_restore_after_f5mlb_delete_then_backend_update(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb deleted, then backend objects are changed.

    When the f5mlb comes back online, it realizes that managed bigip objects
    were modified, so it resets the properties that it cares about and ignores
    the properties that it doesn't care about.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    f5mlb.delete()
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
    # - recreate f5mlb and verify restoration
    f5mlb = utils.create_f5mlb(orchestration)
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    virtual_server.refresh()
    assert virtual_server.destination == old_dest
    assert virtual_server.description == new_desc
    backend_objs_exp['virtual_addresses'] += [new_addr]
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-20", tags=[])
def test_restore_after_f5mlb_suspend(orchestration, bigip, f5mlb):
    """Verify response when f5mlb is suspended (no other changes occur).

    Neither the bigip nor managed service are changed while f5mlb is gone, so
    there's nothing for f5mlb to do when it comes back online.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    old_svc = svc.freeze()
    f5mlb.suspend()
    # - verify managed service is unchanged
    utils.wait_for_f5mlb()
    assert svc.diff(old_svc) == {}
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume f5mlb and verify restoration
    f5mlb.resume()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert svc.diff(old_svc) == {}
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-21", tags=[])
def test_restore_after_f5mlb_suspend_then_svc_delete(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb suspended, then managed service is deleted.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned and reaps them.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    f5mlb.suspend()
    # - delete the managed service
    svc.delete()
    utils.wait_for_f5mlb()
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume f5mlb and verify restoration
    f5mlb.resume()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    assert not orchestration.app.exists(svc.id)
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-22", tags=[])
def test_restore_after_f5mlb_suspend_then_svc_update(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb suspended, then managed service is changed.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned (because the managed service is no longer properly
    configured to register with f5mlb) and reaps them.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    f5mlb.suspend()
    # - change the managed service
    svc.labels = {}
    svc.update()
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume f5mlb and verify restoration
    f5mlb.resume()
    utils.wait_for_f5mlb()
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="f5mlb-23", tags=[])
def test_restore_after_f5mlb_suspend_then_backend_delete(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb suspended, then backend objects are deleted.

    When the f5mlb comes back online, it realizes that managed bigip objects
    are missing, so it creates new ones.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    f5mlb.suspend()
    # - delete the managed virtual server
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    obj_name = utils.get_backend_object_name(svc)
    bigip.virtual_server.delete(name=obj_name, partition=default_partition)
    orig_vs_list = backend_objs_exp.pop('virtual_servers')
    orig_va_list = backend_objs_exp.pop('virtual_addresses')
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - resume f5mlb and verify restoration
    f5mlb.resume()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    backend_objs_exp['virtual_servers'] = orig_vs_list
    backend_objs_exp['virtual_addresses'] = orig_va_list
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-24", tags=[])
def test_restore_after_f5mlb_suspend_then_backend_update(
        orchestration, bigip, f5mlb):
    """Verify response when f5mlb suspended, then backend objects are changed.

    When the f5mlb comes back online, it realizes that managed bigip objects
    were modified, so it resets the properties that it cares about and ignores
    the properties that it doesn't care about.
    """
    svc = utils.create_managed_service(orchestration)
    backend_objs_exp = utils.get_backend_objects_exp(svc)
    f5mlb.suspend()
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
    # - resume f5mlb and verify restoration
    f5mlb.resume()
    utils.wait_for_f5mlb(RESTORE_TIMEOUT)
    virtual_server.refresh()
    assert virtual_server.destination == old_dest
    assert virtual_server.description == new_desc
    backend_objs_exp['virtual_addresses'] += [new_addr]
    assert utils.get_backend_objects(bigip) == backend_objs_exp


@meta_test(id="f5mlb-25", tags=["incomplete"])
def test_restore_after_partition_delete_has_backup(
        orchestration, bigip, f5mlb):
    """Check response when one of the partitions with f5mlb objects is deleted.

    When it realizes that a partition with managed objects was deleted, f5mlb
    will recreate them on the next available managed partition.
    """
    pass


@meta_test(id="f5mlb-26", tags=["incomplete"])
def test_restore_after_partition_delete_no_backup(orchestration, bigip, f5mlb):
    """Verify response when sole partition with f5mlb objects is deleted.

    When it realizes that a partition with managed objects was deleted, f5mlb
    will recreate them on the next managed partition that becomes available.
    """
    pass
