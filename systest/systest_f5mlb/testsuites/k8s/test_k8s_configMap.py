"""Test suites specific to k8s."""

from pytest import meta_suite, meta_test

from .. import utils


pytestmark = meta_suite(tags=["func", "k8s", "no_marathon"])


@meta_test(id="k8s-1", tags=[])
def test_k8s_configMap_filter(ssh, orchestration, bigip,
                              bigip_controller):
    """Test if the configMap in k8s controller watches objects with only.

    f5 labels.
    """
    # - verify no bigip objects exist
    assert utils.get_backend_objects(bigip) == {}
    # - start managed service that has bigip-controller decorations with
    # the correct label defined in the defaults in utils.py
    svc = utils.create_managed_northsouth_service(orchestration, "svc")
    utils.wait_for_bigip_controller()
    backend_objs_exp = utils.get_backend_objects_exp(svc, bigip_controller)
    # - verify new bigip objects created for managed service
    assert utils.get_backend_objects(bigip) == backend_objs_exp
    # - Deleting the configmap
    orchestration.app.delete_configmap("%s-map" % svc.id)
    utils.wait_for_bigip_controller()
    # - verify after delete there are no bigip objects
    assert utils.get_backend_objects(bigip) == {}
    # - create a service with config map that has the wrong label
    wrong_label_config = utils.DEFAULT_SVC_CONFIG
    wrong_label_config['labels'] = {'notF5type': "not-virtual-server"}
    svc_2 = utils.create_managed_northsouth_service(orchestration, "svc-2",
                                                    config=wrong_label_config)
    utils.wait_for_bigip_controller()
    # - verify with wrong label no bigip objects are created
    assert utils.get_backend_objects(bigip) == {}
    # - Deleting the configmap svc-2-map
    orchestration.app.delete_configmap("%s-map" % svc_2.id)
    utils.wait_for_bigip_controller()
    # - verify deleting does not cause any change
    assert utils.get_backend_objects(bigip) == {}
