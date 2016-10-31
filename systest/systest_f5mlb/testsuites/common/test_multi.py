"""Test suite to verify scenarios with more than one bigip-controller."""


from pytest import meta_suite, meta_test


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "multi"])


@meta_test(id="f5mlb-55", tags=["incomplete"])
def test_multiple_managed_services(orchestration, bigip_controller):
    """Multiple managed services using the same bigip-controller.

    The fact that there are multiple managed services using the same
    bigip-controller should be transparent to the user (ie. we expect no
    observable change in system behavior).
    """
    pass


@meta_test(id="f5mlb-56", tags=["incomplete"])
def test_multiple_bigip_controller_instances(orchestration, bigip_controller):
    """Multiple instances of the same bigip-controller.

    The fact that there are multiple instances of the same bigip-controller
    should be transparent to the user (ie. no observable change in system
    behavior).
    """
    pass


@meta_test(id="f5mlb-57", tags=["incomplete"])
def test_multiple_bigip_controllers_different_config(orchestration):
    """Multiple bigip-controllers with different configurations.

    Verify system response when we configure two separate bigip-controllers
    with different configurations.
    """
    pass


@meta_test(id="f5mlb-58", tags=["incomplete"])
def test_multiple_bigip_controllers_same_config(orchestration):
    """Multiple bigip-controllers with the same configuration.

    Verify system response when we configure two separate bigip-controllers
    with the same configuration.
    """
    pass
