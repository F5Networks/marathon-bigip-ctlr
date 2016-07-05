"""Test suite to verify end-to-end scenarios in a marathon environment."""


from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "e2e"])


@meta_test(id="f5mlb-1", tags=[])
def test_e2e(ssh, marathon, bigip, f5mlb):
    """End-to-end f5mlb test.

    Verify the most common f5mlb operations and interactions.
    """
    assert marathon.app.exists(f5mlb.id)
    assert f5mlb.instances.count() == 1
    # - verify no bigip objects exist
    assert utils.get_backend_objects(bigip) == {}

    # - start unmanaged service (no f5mlb labels)
    utils.create_unmanaged_service(marathon, "svc-1")
    # - verify no bigip objects created for unmanaged service
    utils.wait_for_f5mlb()
    assert utils.get_backend_objects(bigip) == {}

    # - start managed service (has f5mlb labels)
    svc_2 = utils.create_managed_service(marathon, "svc-2")
    # - verify new bigip objects created for managed service
    utils.wait_for_f5mlb()
    backend_objs_exp = utils.get_backend_objects_exp(svc_2)
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - scale managed service to 2 instances
    svc_2.scale(2)
    assert svc_2.instances.count() == 2
    # - verify num f5mlb instances unchanged
    utils.wait_for_f5mlb()
    assert f5mlb.instances.count() == 1
    # - verify bigip pool members are changed
    instances = svc_2.instances.get()
    backend_objs_exp['pool_members'] = sorted([
        "%s:%d" % (instances[0].host, instances[0].ports[0]),
        "%s:%d" % (instances[1].host, instances[1].ports[0]),
    ])
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - verify round-robin load balancing
    svc_url = (
        "http://%s:%s"
        % (svc_2.labels['F5_0_BIND_ADDR'], svc_2.labels['F5_0_PORT'])
    )
    pool_members = []
    for instance in svc_2.instances.get():
        pool_members.append("%s:%d" % (instance.host, instance.ports[0]))
    curl_cmd = "curl -s %s" % svc_url
    msg = "Hello from %s :0)"
    assert ssh.run(symbols.bastion, curl_cmd) == msg % pool_members[0]
    assert ssh.run(symbols.bastion, curl_cmd) == msg % pool_members[1]
    assert ssh.run(symbols.bastion, curl_cmd) == msg % pool_members[0]
    assert ssh.run(symbols.bastion, curl_cmd) == msg % pool_members[1]
    assert ssh.run(symbols.bastion, curl_cmd + "/app") == svc_2.app_id

    # - scale managed service to 0 instances
    svc_2.scale(0)
    assert svc_2.instances.count() == 0
    # - verify num f5mlb instances unchanged
    utils.wait_for_f5mlb()
    assert f5mlb.instances.count() == 1
    # - verify bigip pool members are changed
    backend_objs_exp.pop('pool_members')
    backend_objs_exp.pop('nodes')
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - scale managed service to 1 instance
    svc_2.scale(1)
    assert svc_2.instances.count() == 1
    # - verify num f5mlb instances unchanged
    utils.wait_for_f5mlb()
    assert f5mlb.instances.count() == 1
    # - verify bigip pool members are changed
    instances = svc_2.instances.get()
    backend_objs_exp['pool_members'] = [
        "%s:%d" % (instances[0].host, instances[0].ports[0]),
    ]
    backend_objs_exp['nodes'] = [instances[0].host]
    assert utils.get_backend_objects(bigip) == backend_objs_exp

    # - delete managed service
    svc_2.delete()
    # - verify bigip objects are also destroyed
    utils.wait_for_f5mlb()
    assert utils.get_backend_objects(bigip) == {}
    # - verify f5mlb app remains
    assert marathon.app.exists(f5mlb.id)
    assert f5mlb.instances.count() == 1
