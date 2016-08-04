"""Test suite to verify https scenarios in a marathon environment."""


import copy

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "https"])


@meta_test(id="f5mlb-62", tags=[])
def test_https(ssh, marathon, bigip, f5mlb):
    """Verify system behavior with basic https config."""
    # - start managed service
    labels = copy.deepcopy(utils.DEFAULT_SVC_LABELS)
    labels['F5_0_SSL_PROFILE'] = utils.DEFAULT_SVC_SSL_PROFILE
    svc = utils.create_managed_service(
        marathon,
        labels=labels,
        health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_TCP
    )
    utils.wait_for_f5mlb()
    svc.scale(2)
    assert svc.instances.count() == 2
    utils.wait_for_f5mlb()
    svc_url = "%s:%s" % (svc.labels['F5_0_BIND_ADDR'], svc.labels['F5_0_PORT'])

    # - verify SSL profile is attached to virtual server on the backend
    obj_name = utils.get_backend_object_name(svc)
    vs = bigip.virtual_server.get(
        name=obj_name, partition=utils.DEFAULT_F5MLB_PARTITION
    )
    profiles = vs.profiles_s.get_collection()
    assert profiles[0].fullPath == "/" + svc.labels['F5_0_SSL_PROFILE']

    # - verify http request fails
    http_url = "http://" + svc_url
    curl_cmd = "curl -s -k %s" % http_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res == ""

    # - verify https request succeeds
    https_url = "https://" + svc_url
    curl_cmd = "curl -s -k %s" % https_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res.startswith("Hello from")

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(ssh, svc)
