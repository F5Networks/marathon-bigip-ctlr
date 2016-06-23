"""Test suite to verify end-to-end scenarios in a marathon environment."""


from pytest import meta_suite, meta_test

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "e2e"])


@meta_test(id="f5mlb-1", tags=[])
def test_e2e(marathon, bigip, f5mlb):
    """End-to-end f5mlb test.

    Verify the most common f5mlb operations and interactions.
    """
    assert marathon.app.exists(f5mlb.id)
    assert f5mlb.instances.count() == 1
    # - verify no bigip objects exist
    assert utils.get_f5mlb_objects(bigip) == {}

    # - start unmanaged service (no f5mlb labels)
    utils.create_unmanaged_service(marathon, "svc-1")
    # - verify no bigip objects created for unmanaged service
    utils.wait_for_f5mlb()
    assert utils.get_f5mlb_objects(bigip) == {}

    # - start managed service (has f5mlb labels)
    svc_2 = utils.create_managed_service(marathon, "svc-2")
    # - verify new bigip objects created for managed service
    utils.wait_for_f5mlb()
    instances = svc_2.instances.get()
    obj_name = utils.get_backend_object_name(svc_2)
    backend_objs_exp = {
        'virtual_servers': [obj_name],
        'virtual_addresses': [svc_2.labels['F5_0_BIND_ADDR']],
        'pools': [obj_name],
        'pool_members': [
            "%s:%d" % (instances[0].host, instances[0].ports[0])
        ],
        'health_monitors': [obj_name],
        'nodes': [instances[0].host]
    }
    assert utils.get_f5mlb_objects(bigip) == backend_objs_exp

    # - scale managed service to 2 instances
    svc_2.scale(2)
    assert svc_2.instances.count() == 2
    # - verify num f5mlb instances unchanged
    utils.wait_for_f5mlb()
    assert f5mlb.instances.count() == 1
    # - verify bigip pool members is changed
    instances = svc_2.instances.get()
    backend_objs_exp['pool_members'] = sorted([
        "%s:%d" % (instances[0].host, instances[0].ports[0]),
        "%s:%d" % (instances[1].host, instances[1].ports[0]),
    ])
    assert utils.get_f5mlb_objects(bigip) == backend_objs_exp

    # - scale managed service to 0 instances
    svc_2.scale(0)
    assert svc_2.instances.count() == 0
    # - verify num f5mlb instances unchanged
    utils.wait_for_f5mlb()
    assert f5mlb.instances.count() == 1
    # - verify bigip pool members are changed
    backend_objs_exp.pop('pool_members')
    backend_objs_exp.pop('nodes')
    assert utils.get_f5mlb_objects(bigip) == backend_objs_exp

    # - scale managed service to 1 instance
    svc_2.scale(1)
    assert svc_2.instances.count() == 1
    # - verify num f5mlb instances unchanged
    utils.wait_for_f5mlb()
    assert f5mlb.instances.count() == 1
    # - verify bigip pool members is changed
    instances = svc_2.instances.get()
    backend_objs_exp['pool_members'] = [
        "%s:%d" % (instances[0].host, instances[0].ports[0]),
    ]
    backend_objs_exp['nodes'] = [instances[0].host]
    assert utils.get_f5mlb_objects(bigip) == backend_objs_exp

    # - delete managed service
    svc_2.delete()
    # - verify bigip objects are also destroyed
    utils.wait_for_f5mlb()
    assert utils.get_f5mlb_objects(bigip) == {}
    # - verify f5mlb app remains
    assert marathon.app.exists(f5mlb.id)
    assert f5mlb.instances.count() == 1
