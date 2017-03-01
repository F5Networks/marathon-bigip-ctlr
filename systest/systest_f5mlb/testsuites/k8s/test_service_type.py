"""Test suite to verify service type ClusterIP."""

from pytest import meta_suite, meta_test
from .. import utils

pytestmark = meta_suite(tags=["func", "k8s", "openshift", "no_marathon"])


@meta_test(id="k8s-2", tags=[])
def test_service_type(ssh, orchestration, bigip, bigip_controller):
    """Verify explicit ClusterIP service."""
    assert utils.get_backend_objects(bigip) == {}, \
        'No bigip objects should exist.'
    service_type = 'ClusterIP'
    svc = utils.create_managed_northsouth_service(orchestration, 'svc',
                                                  service_type=service_type)
    svc.scale(2)
    utils.wait_for_bigip_controller()
    assert len(svc.instances.get()) == 2, 'Precondition check for 2 pods.'

    if bigip_controller.pool_mode == utils.POOL_MODE_CLUSTER:
        expected_backend = utils.get_backend_objects_exp(svc, bigip_controller)
        actual_backend = utils.get_backend_objects(bigip)
        assert actual_backend == expected_backend, \
            'BigIP not in expected state.'
        msg = "Pool mode: %s - Unable to reach a %s service." % \
            (bigip_controller.pool_mode, service_type)
        utils.verify_bigip_round_robin(ssh, svc, msg=msg)
    else:
        msg = "Pool mode: %s - Service type %s should be ignored by BigIP." % \
            (bigip_controller.pool_mode, service_type)
        assert utils.get_backend_objects(bigip) == {}, msg
