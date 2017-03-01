# Copyright 2017 F5 Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test suite to verify iApp scenarios in an orchestration environment."""


import copy
import os

from pytest import meta_suite, meta_test
from pytest import symbols
from pytest import fixture

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "openshift", "https"])


@fixture(scope='module')
def appsvcs_template(request, ssh, bigip):
    """Fixture for loading and deleting the appsvcs iApp template.

    Fixture is defined at 'module' scope so that it runs after
    BIG-IP teardown
    """
    template_name = 'appsvcs_integration_v2.0.002'
    template_file = template_name + '.tmpl'
    bigip_file_path = '/var/config/rest/downloads/'
    tmsh_cmd = 'tmsh load sys application template'

    # - Upload and install the iApp template
    bigip._conn.shared.file_transfer.uploads.upload_file(
        os.path.dirname(__file__) + '/' + template_file)
    ssh_cmd = tmsh_cmd + ' ' + bigip_file_path + template_file
    bigip_host = symbols.bigip_ssh_username + '@' + symbols.bigip_mgmt_ip
    ssh.run(bigip_host, ssh_cmd)

    def delete_template():
        tmsh_cmd = 'tmsh delete sys application template'
        ssh.run(bigip_host, tmsh_cmd + ' ' + template_name)

    request.addfinalizer(delete_template)


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


@meta_test(id="f5mlb-68", tags=[])
def test_iapp_appsvcs(ssh, orchestration, bigip, bigip_controller,
                      appsvcs_template):
    """Test AppSvcs iApp config."""
    # - start managed service
    iapp = SampleAppSvcsIApp()
    config = _get_iapp_config(iapp)
    svc = utils.create_managed_northsouth_service(
        orchestration,
        id=iapp.svc_name,
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
    vs_name = iapp.vars['vs__Name']
    pool_name = iapp_name + "_pool_0"
    assert bigip.virtual_servers.list(vs_name, partition) == [vs_name]
    assert bigip.pools.list(pool_name, partition) == [pool_name]

    # - verify iApp variables
    iapp_obj = bigip.iapp.get(name=iapp_name, partition=partition)
    vars_act = {var['name']: var['value'] for var in iapp_obj.variables}
    vars_exp = iapp.vars
    assert vars_act == vars_exp

    # - verify round-robin load balancing
    utils.verify_bigip_round_robin(ssh, svc)

    # - test the L7 policy
    svc_url = utils._get_svc_url(svc) + '/env'
    curl_cmd = "curl -k %s" % svc_url
    res = ssh.run(symbols.bastion, curl_cmd)
    assert 'Connection reset by peer' in res


def _get_iapp_config(iapp):
    if symbols.orchestration == "marathon":
        cfg = {
            'F5_PARTITION': utils.DEFAULT_F5MLB_PARTITION,
            'F5_0_IAPP_TEMPLATE': iapp.name,
            'F5_0_IAPP_POOL_MEMBER_TABLE_NAME': iapp.table,
        }
        if iapp.pool_member_table_column_names:
            cfg['F5_0_IAPP_POOL_MEMBER_TABLE_COLUMN_NAMES'] = \
                iapp.pool_member_table_column_names
        for k, v in iapp.options.iteritems():
            cfg['F5_0_IAPP_OPTION_' + k] = v
        for k, v in iapp.vars.iteritems():
            cfg['F5_0_IAPP_VARIABLE_' + k] = v
        for k, v in iapp.tables.iteritems():
            cfg['F5_0_IAPP_TABLE_' + k] = v
    if utils.is_kubernetes():
        cfg = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
        cfg['data']['data']['virtualServer'].pop('frontend')
        cfg['data']['data']['virtualServer']['frontend'] = {
            'partition': utils.DEFAULT_F5MLB_PARTITION,
            'iapp': iapp.name,
            'iappTableName': iapp.table,
            'iappPoolMemberTableColumnNames':
            iapp.pool_member_table_column_names,
            'iappTables': iapp.tables,
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
        self.pool_member_table_column_names = {}
        self.tables = {}

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


class SampleAppSvcsIApp(object):
    """Test instance of the AppSvcs iApp."""

    def __init__(self):
        """Initialize members."""
        self.svc_name = 'appsvc'
        self.name = "/Common/appsvcs_integration_v2.0.002"
        self.table = "pool__Members"
        self.pool_member_table_column_names = \
            "IPAddress, Port, ConnectionLimit"
        self.options = {'description': "This is a test iApp"}
        self.tables = {
            'l7policy__rulesMatch':
            """{"columns": ["Group", "Operand", "Negate",
                "Condition", "Value", "CaseSensitive", "Missing"],
                "rows": [[0, "http-uri/request/path", "no", "starts-with",
                         "/env", "no", "no"],
                        ["default", "", "no", "", "", "no", "no"]]
            }""",
            'l7policy__rulesAction':
            """{"columns": ["Group", "Target", "Parameter"],
                "rows": [[0, "forward/request/reset", "none" ],
                         ["default", "forward/request/select/pool", "pool:0"]]
            }""",
            'pool__Pools':
            """{"columns": ["Index", "Name", "Description", "LbMethod",
                "Monitor", "AdvOptions"],
                "rows": [["0", "", "", "round-robin", "0", "none"]]
            }""",
            'monitor__Monitors':
            """{"columns": ["Index", "Name", "Type", "Options"],
                "rows": [["0", "/Common/tcp", "none", "none"]]
            }"""
        }
        self.vars = {
            'pool__addr': utils.DEFAULT_F5MLB_BIND_ADDR,
            'pool__port': str(utils.DEFAULT_F5MLB_PORT),
            'pool__mask': "255.255.255.255",
            'vs__Name': "appsvc_iapp_vs",
            'vs__ProfileClientProtocol': "/Common/tcp-wan-optimized",
            'vs__ProfileServerProtocol': "/Common/tcp-lan-optimized",
            'vs__ProfileHTTP': "/Common/http",
            'vs__SNATConfig': "automap",
            'iapp__logLevel': "7",
            'iapp__routeDomain': "auto",
            'iapp__mode': "auto",
            'pool__DefaultPoolIndex': "0",
            'l7policy__strategy': "/Common/first-match"
        }
