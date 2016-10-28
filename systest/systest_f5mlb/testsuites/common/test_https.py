"""Test suite to verify https scenarios in an orchestration environment."""


import copy

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "https"])


@meta_test(id="f5mlb-62", tags=[])
def test_https(ssh, orchestration, bigip, bigip_controller):
    """Verify system behavior with basic https config."""
    # - start managed service
    config = _get_https_config()
    svc = utils.create_managed_northsouth_service(
        orchestration,
        health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_TCP,
        config=config
    )
    utils.wait_for_bigip_controller()
    svc.scale(2)
    assert svc.instances.count() == 2
    utils.wait_for_bigip_controller()
    svc_url = "%s:%s" % (
        utils.DEFAULT_F5MLB_BIND_ADDR, utils.DEFAULT_F5MLB_PORT
    )

    # - verify SSL profile is attached to virtual server on the backend
    obj_name = utils.get_backend_object_name(svc)
    vs = bigip.virtual_server.get(
        name=obj_name, partition=utils.DEFAULT_F5MLB_PARTITION
    )
    profiles = vs.profiles_s.get_collection()
    assert profiles[0].fullPath == "/" + utils.DEFAULT_SVC_SSL_PROFILE

    # - verify http request fails
    http_url = "http://" + svc_url
    curl_cmd = "curl --connect-time 1 -s -k %s" % http_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res == ""

    # - verify https request succeeds
    https_url = "https://" + svc_url
    curl_cmd = "curl --connect-time 1 -s -k %s" % https_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert res.startswith("Hello from")

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(ssh, svc)


def _get_https_config():
    if symbols.orchestration == "marathon":
        cfg = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
        cfg['F5_0_SSL_PROFILE'] = utils.DEFAULT_SVC_SSL_PROFILE
    if symbols.orchestration == "k8s":
        cfg = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
        cfg['data']['data']['virtualServer']['frontend']['sslProfile'] = {
            'f5ProfileName': utils.DEFAULT_SVC_SSL_PROFILE
        }
    return cfg
