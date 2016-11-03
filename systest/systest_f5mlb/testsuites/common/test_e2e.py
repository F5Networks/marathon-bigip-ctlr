"""Test suite to verify end-to-end scenarios."""

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "e2e"])


@meta_test(id="f5mlb-1", tags=[])
def test_e2e(ssh, orchestration, bigip, bigip_controller):
    """End-to-end north-south test.

    Verify the most common north-south operations and interactions.
    """
    # - verify no bigip objects exist
    assert utils.get_backend_objects(bigip) == {}

    # - start unmanaged service (no bigip-controller decorations)
    utils.create_unmanaged_service(orchestration, "svc-1")
    # - verify no bigip objects created for unmanaged service
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}

    # - start managed service (has bigip-controller decorations)
    svc_2 = utils.create_managed_northsouth_service(orchestration, "svc-2")
    # - verify new bigip objects created for managed service
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc_2)
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - scale managed service to 2 instances
    svc_2.scale(2)
    assert svc_2.instances.count() == 2
    if symbols.orchestration == "marathon":
        # - verify bigip pool members are changed
        instances = svc_2.instances.get()
        backend_objs_exp['pool_members'] = sorted([
            "%s:%d" % (instances[0].host, instances[0].ports[0]),
            "%s:%d" % (instances[1].host, instances[1].ports[0]),
        ])
    # - note that the k8s version of the bigip-controller does NOT add/remove
    #   pool members on the bigip
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(ssh, svc_2)

    # - scale managed service to 0 instances
    svc_2.scale(0)
    assert svc_2.instances.count() == 0
    if symbols.orchestration == "marathon":
        # - verify bigip pool members are changed
        backend_objs_exp.pop('pool_members')
        backend_objs_exp.pop('nodes')
    # - note that the k8s version of the bigip-controller does NOT add/remove
    #   pool members on the bigip
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - scale managed service to 1 instance
    svc_2.scale(1)
    assert svc_2.instances.count() == 1
    # - verify bigip pool members are changed
    instances = svc_2.instances.get()
    backend_objs_exp['pool_members'] = [
        "%s:%d" % (instances[0].host, instances[0].ports[0]),
    ]
    backend_objs_exp['nodes'] = [instances[0].host]
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - delete managed service
    svc_2.delete()
    # - verify bigip objects are also destroyed
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}
