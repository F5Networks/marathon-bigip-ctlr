"""Test suite to verify iApp scenarios in an orchestration environment."""


from pytest import meta_suite, meta_test

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "https"])


@meta_test(id="f5mlb-63", tags=[])
def test_iapp_f5_http(ssh, orchestration, bigip, f5mlb):
    """Basic iApp config."""
    # - start managed service
    CREATE_NEW = "/#create_new#"
    DONT_USE = "/#do_not_use#"
    labels = {
        'F5_PARTITION': utils.DEFAULT_F5MLB_PARTITION,
        'F5_0_IAPP_TEMPLATE': "/Common/f5.http",
        'F5_0_IAPP_OPTION_description': "This is a test iApp",
        'F5_0_IAPP_VARIABLE_net__client_mode': "wan",
        'F5_0_IAPP_VARIABLE_net__server_mode': "lan",
        'F5_0_IAPP_POOL_MEMBER_TABLE_NAME': "pool__members",
        'F5_0_IAPP_VARIABLE_pool__addr': utils.DEFAULT_F5MLB_BIND_ADDR,
        'F5_0_IAPP_VARIABLE_pool__port': str(utils.DEFAULT_F5MLB_PORT),
        'F5_0_IAPP_VARIABLE_pool__pool_to_use': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_pool__lb_method': "round-robin",
        'F5_0_IAPP_VARIABLE_pool__http': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_pool__mask': "255.255.255.255",
        'F5_0_IAPP_VARIABLE_pool__persist': DONT_USE,
        'F5_0_IAPP_VARIABLE_monitor__monitor': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_monitor__uri': "/",
        'F5_0_IAPP_VARIABLE_monitor__frequency': "30",
        'F5_0_IAPP_VARIABLE_monitor__response': "none",
        'F5_0_IAPP_VARIABLE_ssl_encryption_questions__advanced': "yes",
        'F5_0_IAPP_VARIABLE_net__vlan_mode': "all",
        'F5_0_IAPP_VARIABLE_net__snat_type': "automap",
        'F5_0_IAPP_VARIABLE_client__tcp_wan_opt': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_client__standard_caching_with_wa': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_client__standard_caching_without_wa': DONT_USE,
        'F5_0_IAPP_VARIABLE_server__tcp_lan_opt': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_server__oneconnect': CREATE_NEW,
        'F5_0_IAPP_VARIABLE_server__ntlm': "/#do_not_use#",
    }
    svc = utils.create_managed_service(
        orchestration,
        labels=labels,
        health_checks=utils.DEFAULT_SVC_HEALTH_CHECKS_TCP
    )
    utils.wait_for_f5mlb()
    svc.scale(2)
    assert svc.instances.count() == 2
    utils.wait_for_f5mlb()

    # - verify iApp objects exist
    partition = utils.DEFAULT_F5MLB_PARTITION
    iapp_name = "%s_iapp_%s" % (svc.id.replace("/", ""), "10001")
    vs_name = iapp_name + "_vs"
    pool_name = iapp_name + "_pool"
    hm_name = iapp_name + "_http_monitor"
    assert bigip.iapps.list(iapp_name, partition) == [iapp_name]
    assert bigip.virtual_servers.list(vs_name, partition) == [vs_name]
    assert bigip.pools.list(pool_name, partition) == [pool_name]
    assert bigip.health_monitors.http.list(hm_name, partition) == [hm_name]

    # - verify iApp variables
    iapp = bigip.iapp.get(name=iapp_name, partition=partition)
    vars_act = {var['name']: var['value'] for var in iapp.variables}
    lbl_prefix = "F5_0_IAPP_VARIABLE_"
    vars_exp = {
        k.replace(lbl_prefix, ""): v for k, v in labels.iteritems()
        if k.startswith(lbl_prefix)
    }
    assert vars_act == vars_exp

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(
        ssh, svc,
        protocol="http",
        ipaddr=utils.DEFAULT_F5MLB_BIND_ADDR,
        port=utils.DEFAULT_F5MLB_PORT
    )
