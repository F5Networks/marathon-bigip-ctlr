"""Test suite to verify scenarios with more than one f5mlb."""


from pytest import meta_suite, meta_test


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "multi"])


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_multiple_managed_services(orchestration, f5mlb):
    """Multiple managed services using the same f5mlb.

    The fact that there are multiple managed services using the same f5mlb
    should be transparent to the user (ie. we expect no observable change in
    system behavior).
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_multiple_f5mlb_instances(orchestration, f5mlb):
    """Multiple instances of the same f5mlb app.

    The fact that there are multiple instances of the same f5mlb app should be
    transparent to the user (ie. no observable change in system behavior).
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_multiple_f5mlbs_different_config(orchestration):
    """Multiple f5mlb apps with different configurations.

    Verify system response when we configure two separate f5mlb apps with
    different configurations.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_multiple_f5mlbs_same_config(orchestration):
    """Multiple f5mlb apps with the same configuration.

    Verify system response when we configure two separate f5mlb apps with the
    same configuration.
    """
    pass
