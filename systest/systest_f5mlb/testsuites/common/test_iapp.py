"""Test suite to verify iApp scenarios in an orchestration environment."""


import copy

from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "https"])


@meta_test(id="f5mlb-63", tags=[])
def test_iapp_f5_http(ssh, orchestration, bigip, bigip_controller):
    """Basic iApp config."""
    # - start managed service
    iapp = SampleHttpIApp()
    config = _get_iapp_config(iapp)
    svc = utils.create_managed_northsouth_service(
        orchestration,
        health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_TCP,
        config=config
    )
    utils.wait_for_bigip_controller()
    svc.scale(2)
    assert svc.instances.count() == 2
    utils.wait_for_bigip_controller()

    # - verify iApp objects exist
    partition = utils.DEFAULT_F5MLB_PARTITION
    prefix = "%s_iapp_" % svc.id.replace("/", "")
    iapps = bigip.iapps.list(prefix, partition)
    iapp_name = iapps[0]
    vs_name = iapp_name + "_vs"
    pool_name = iapp_name + "_pool"
    hm_name = iapp_name + "_http_monitor"
    assert bigip.virtual_servers.list(vs_name, partition) == [vs_name]
    assert bigip.pools.list(pool_name, partition) == [pool_name]
    # FIXME (kevin): remove when k8s-bigip-ctlr supports health monitors
    if symbols.orchestration == "marathon":
        assert bigip.health_monitors.http.list(hm_name, partition) == [hm_name]

    # - verify iApp variables
    iapp_obj = bigip.iapp.get(name=iapp_name, partition=partition)
    vars_act = {var['name']: var['value'] for var in iapp_obj.variables}
    vars_exp = iapp.vars
    assert vars_act == vars_exp

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(ssh, svc)


def _get_iapp_config(iapp):
    if symbols.orchestration == "marathon":
        cfg = {
            'F5_PARTITION': utils.DEFAULT_F5MLB_PARTITION,
            'F5_0_IAPP_TEMPLATE': iapp.name,
            'F5_0_IAPP_POOL_MEMBER_TABLE_NAME': iapp.table,
        }
        for k, v in iapp.options.iteritems():
            cfg['F5_0_IAPP_OPTION_' + k] = v
        for k, v in iapp.vars.iteritems():
            cfg['F5_0_IAPP_VARIABLE_' + k] = v
    if symbols.orchestration == "k8s":
        cfg = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
        cfg['data']['data']['virtualServer'].pop('frontend')
        cfg['data']['data']['virtualServer']['frontend'] = {
            'partition': utils.DEFAULT_F5MLB_PARTITION,
            'iapp': iapp.name,
            'iappTableName': iapp.table,
            'iappOptions': iapp.options,
            'iappVariables': iapp.vars
        }
    return cfg


class SampleHttpIApp(object):
    """Test instance of the standard F5 HTTP iApp."""

    def __init__(self):
        """Initialize members."""
        self.name = "/Common/f5.http"
        self.table = "pool__members"
        self.options = {'description': "This is a test iApp"}

        CREATE_NEW = "/#create_new#"
        DONT_USE = "/#do_not_use#"
        self.vars = {
            'net__client_mode': "wan",
            'net__server_mode': "lan",
            'pool__addr': utils.DEFAULT_F5MLB_BIND_ADDR,
            'pool__port': str(utils.DEFAULT_F5MLB_PORT),
            'pool__pool_to_use': CREATE_NEW,
            'pool__lb_method': "round-robin",
            'pool__http': CREATE_NEW,
            'pool__mask': "255.255.255.255",
            'pool__persist': DONT_USE,
            'monitor__monitor': CREATE_NEW,
            'monitor__uri': "/",
            'monitor__frequency': "30",
            'monitor__response': "none",
            'ssl_encryption_questions__advanced': "yes",
            'net__vlan_mode': "all",
            'net__snat_type': "automap",
            'client__tcp_wan_opt': CREATE_NEW,
            'client__standard_caching_with_wa': CREATE_NEW,
            'client__standard_caching_without_wa': DONT_USE,
            'server__tcp_lan_opt': CREATE_NEW,
            'server__oneconnect': CREATE_NEW,
            'server__ntlm': DONT_USE,
        }
