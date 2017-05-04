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

"""Helper functions for orchestration tests."""


import copy
import json
import re
import time
import subprocess
import pykube


from copy import deepcopy
from pytest import symbols


def is_kubernetes():
    """Return whether current orchestration provides k8s behavior."""
    if symbols.orchestration == "openshift" or symbols.orchestration == "k8s":
        return True
    return False


REGISTRY = "docker-registry.pdbld.f5net.com"
TEST_NGINX_IMG = \
        "docker-registry.pdbld.f5net.com/systest-common/test-nginx:20170211"

DEFAULT_BIGIP_PASSWORD = "admin"
DEFAULT_BIGIP_USERNAME = "admin"

DEFAULT_DEPLOY_TIMEOUT = 6 * 60

DEFAULT_F5MLB_CPUS = 0.1
DEFAULT_F5MLB_MEM = 48
# FIXME(kenr): If we want to make general use of a second bigip in k8s, we
#              need to remove hard-coded use of this in the functions below.
DEFAULT_F5MLB_BIND_ADDR = symbols.bigip_ext_ip
BIGIP2_F5MLB_BIND_ADDR = getattr(symbols, 'bigip2_ext_ip', None)
DEFAULT_F5MLB_MODE = "http"
DEFAULT_F5MLB_NAME = "test-bigip-controller"
BIGIP2_F5MLB_NAME = "test-bigip-controller2"
DEFAULT_F5MLB_PARTITION = "test"
DEFAULT_F5MLB_PORT = 8080
DEFAULT_F5MLB_LB_ALGORITHM = "round-robin"
if symbols.orchestration == "marathon":
    DEFAULT_F5MLB_WAIT = 5
elif is_kubernetes():
    DEFAULT_F5MLB_WAIT = 20
DEFAULT_F5MLB_VERIFY_INTERVAL = 2
DEFAULT_F5MLB_NODE_POLL_INTERVAL = 1
DEFAULT_F5MLB_NAMESPACE = "default"

DEFAULT_SVC_CPUS = 0.1
DEFAULT_SVC_HEALTH_CHECKS_HTTP = [
    {
        'path': "/",
        'protocol': "HTTP",
        'max_consecutive_failures': 3,
        'port_index': 0,
        'interval_seconds': 5,
        'grace_period_seconds': 10,
        'timeout_seconds': 5
    }
]
DEFAULT_SVC_HEALTH_CHECKS_TCP = [
    {
        'protocol': "TCP",
        'max_consecutive_failures': 3,
        'port_index': 0,
        'interval_seconds': 5,
        'grace_period_seconds': 10,
        'timeout_seconds': 5
    }
]
DEFAULT_SVC_INSTANCES = 1
DEFAULT_SVC_MEM = 32
DEFAULT_SVC_SSL_PROFILE = "Common/clientssl"
DEFAULT_SVC_PORT = 80

DEFAULT_BIGIP_MGMT_IP = symbols.bigip_mgmt_ip
DEFAULT_BIGIP2_MGMT_IP = getattr(symbols, 'bigip2_mgmt_ip', None)

POOL_MODE_NODEPORT = 'nodeport'
POOL_MODE_CLUSTER = 'cluster'
POOL_MODES = [POOL_MODE_NODEPORT, POOL_MODE_CLUSTER]

DEFAULT_BIGIP_VXLAN_PROFILE = "vxlan-multipoint"
DEFAULT_BIGIP_VXLAN_TUNNEL = "vxlan-tunnel-mp"
DEFAULT_BIGIP_OPENSHIFT_SELFNAME = "openshift-selfip"
DEFAULT_BIGIP_OPENSHIFT_SELFIP = "10.131.255.1/14"
DEFAULT_BIGIP_OPENSHIFT_SUBNET = "10.131.255.0/31"
DEFAULT_OPENSHIFT_USER = "run-as-anyid"
DEFAULT_OPENSHIFT_ADMIN = "bigip-controller"

DEFAULT_APP_IMG = TEST_NGINX_IMG
DEFAULT_APP_PORT_MAPPING = [
    {
        'container_port': DEFAULT_SVC_PORT,
        'host_port': 0,
        'protocol': "tcp"
    }
]

NODE_UNIN_YAML = '/home/centos/openshift-ansible/playbooks/adhoc/uninstall.yml'
NODE_SCALE_YAML = \
    '/home/centos/openshift-ansible/playbooks/byo/openshift-node/scaleup.yml'
ANSIBLE_HOSTS_SCRIPT = '/home/centos/openshift/ansible_replace.py'

if symbols.orchestration == "marathon":
    DEFAULT_F5MLB_CONFIG = {
        "MARATHON_URL": symbols.marathon_url,
        "F5_CC_SYSLOG_SOCKET": "/dev/null",
        "F5_CC_PARTITIONS": DEFAULT_F5MLB_PARTITION,
        "F5_CC_BIGIP_HOSTNAME": DEFAULT_BIGIP_MGMT_IP,
        "F5_CC_BIGIP_USERNAME": DEFAULT_BIGIP_USERNAME,
        "F5_CC_BIGIP_PASSWORD": DEFAULT_BIGIP_PASSWORD,
        "F5_CC_VERIFY_INTERVAL": str(DEFAULT_F5MLB_VERIFY_INTERVAL)
    }
    BIGIP2_F5MLB_CONFIG = copy.deepcopy(DEFAULT_F5MLB_CONFIG)
    BIGIP2_F5MLB_CONFIG['F5_CC_BIGIP_HOSTNAME'] = DEFAULT_BIGIP2_MGMT_IP

    DEFAULT_SVC_CONFIG = {
        'F5_PARTITION': DEFAULT_F5MLB_PARTITION,
        'F5_0_BIND_ADDR': DEFAULT_F5MLB_BIND_ADDR,
        'F5_0_PORT': DEFAULT_F5MLB_PORT,
        'F5_0_MODE': DEFAULT_F5MLB_MODE,
        'F5_0_BALANCE': DEFAULT_F5MLB_LB_ALGORITHM,
    }
    BIGIP2_SVC_CONFIG = copy.deepcopy(DEFAULT_SVC_CONFIG)
    BIGIP2_SVC_CONFIG['F5_0_BIND_ADDR'] = BIGIP2_F5MLB_BIND_ADDR
elif is_kubernetes():
    F5MLB_KUBE_CONFIG_USERNAME_IDX = 5
    F5MLB_KUBE_CONFIG_PASSWORD_IDX = 7
    DEFAULT_F5MLB_CONFIG = {
        'cmd': "/app/bin/k8s-bigip-ctlr",
        'args': [
            "--bigip-partition", DEFAULT_F5MLB_PARTITION,
            "--bigip-url", DEFAULT_BIGIP_MGMT_IP,
            "--bigip-username", DEFAULT_BIGIP_USERNAME,
            "--bigip-password", DEFAULT_BIGIP_PASSWORD,
            "--verify-interval", str(DEFAULT_F5MLB_VERIFY_INTERVAL),
            "--namespace", DEFAULT_F5MLB_NAMESPACE,
            "--node-poll-interval", str(DEFAULT_F5MLB_NODE_POLL_INTERVAL)
        ],
        'env': {}
    }
    BIGIP2_F5MLB_CONFIG = copy.deepcopy(DEFAULT_F5MLB_CONFIG)
    BIGIP2_F5MLB_CONFIG['args'][3] = DEFAULT_BIGIP2_MGMT_IP

    DEFAULT_SVC_CONFIG = {
        'name': "x",
        'labels': {'f5type': "virtual-server"},
        'data': {
            'data': {
                'virtualServer': {
                    'backend': {
                        'serviceName': "x",
                        'servicePort': DEFAULT_SVC_PORT,
                        'healthMonitors': [{
                            'send': "GET / HTTP/1.0\\r\\n\\r\\n",
                            'interval': 25,
                            'timeout': 20,
                            'protocol': "http"
                            }
                        ]
                    },
                    'frontend': {
                        'partition': DEFAULT_F5MLB_PARTITION,
                        'mode': DEFAULT_F5MLB_MODE,
                        'balance': DEFAULT_F5MLB_LB_ALGORITHM,
                        'virtualAddress': {
                            'bindAddr': DEFAULT_F5MLB_BIND_ADDR,
                            'port': DEFAULT_F5MLB_PORT
                        }
                    }
                }
            },
            'schema': 'f5schemadb://bigip-virtual-server_v0.1.3.json'
        }
    }
    BIGIP2_SVC_CONFIG = copy.deepcopy(DEFAULT_SVC_CONFIG)
    BIGIP2_SVC_CONFIG['data']['data']['virtualServer']['frontend'][
            'virtualAddress']['bindAddr'] = BIGIP2_F5MLB_BIND_ADDR

if symbols.orchestration == "openshift":
    vxlan_name = ("/" + DEFAULT_F5MLB_PARTITION + "/" +
                  DEFAULT_BIGIP_VXLAN_TUNNEL)
    DEFAULT_F5MLB_CONFIG['args'].append('--openshift-sdn-name')
    DEFAULT_F5MLB_CONFIG['args'].append(vxlan_name)

    BIGIP2_F5MLB_CONFIG['args'].append('--openshift-sdn-name')
    BIGIP2_F5MLB_CONFIG['args'].append(vxlan_name)


_next_id = 1
LOG_TIMEOUT = 10 * 60


def controller_namespace():
    """Return the appropriate namespace for kubernetes flavor."""
    if is_kubernetes():
        return 'kube-system'
    return None


def unique_id(prefix):
    """Convert a base name into an id unique to the test session."""
    global _next_id
    id = prefix+'-'+str(_next_id)
    _next_id += 1
    return id


def create_managed_northsouth_service(
        orchestration, id=None,
        cpus=DEFAULT_SVC_CPUS,
        mem=DEFAULT_SVC_MEM,
        labels={},
        timeout=DEFAULT_DEPLOY_TIMEOUT,
        health_checks=DEFAULT_SVC_HEALTH_CHECKS_HTTP,
        num_instances=DEFAULT_SVC_INSTANCES,
        config=DEFAULT_SVC_CONFIG,
        wait_for_deploy=True,
        service_type="NodePort",
        namespace=DEFAULT_F5MLB_NAMESPACE):
    """Create a microservice with bigip-controller decorations."""
    if id is None:
        id = unique_id("test-svc")
    # - note that we have to have to make a copy of the "labels" dictionary
    #   before we try to mutate it, otherwise the mutated version will persist
    #   through subsequent calls to "create_managed_service"
    # - we found this issue in the iapp test, where the next test that ran
    #   after the iapp test had its labels set to a combination of the iapp
    #   test's labels plus the non-iapp test's labels
    # - this was a Python scoping surprise to me!
    _lbls = copy.deepcopy(labels)
    if symbols.orchestration == "marathon":
        _lbls.update(config)
    if is_kubernetes():
        #  save the current namespace the orchestration was created in
        _old_namespace = orchestration.namespace
        orchestration.namespace = namespace
    if symbols.orchestration == "openshift":
        service_account = DEFAULT_OPENSHIFT_USER
    else:
        service_account = None

    print '%s: create_managed_northsouth_service: CALL systest-common'
    try:
        svc = orchestration.app.create(
            id=id,
            cpus=cpus,
            mem=mem,
            timeout=timeout,
            container_img=TEST_NGINX_IMG,
            labels=_lbls,
            container_port_mappings=[
                {
                    'container_port': DEFAULT_SVC_PORT,
                    'host_port': 0,
                    'service_port': 0,
                    'protocol': "tcp"
                }
            ],
            container_force_pull_image=True,
            health_checks=health_checks,
            num_instances=num_instances,
            wait_for_deploy=wait_for_deploy,
            service_account=service_account,
            service_type=service_type,
            namespace=namespace
        )
        # By waiting until the app is deployed before creating the VS Resource,
        # the big-ip won't fail any health checks, and things go faster.
        #
        # The reverse order is tested in ??????
        if is_kubernetes():
            config['name'] = "%s-map" % id
            vs = config['data']['data']['virtualServer']
            vs['backend']['serviceName'] = id
            orchestration.app.create_configmap(config)

        return svc

    finally:
        # Set the orchestration namespace back to the original
        if is_kubernetes():
            orchestration.namespace = _old_namespace


def unmanage_northsouth_service(orchestration, svc):
    """Remove bigip-controller decorations from a managed microservice."""
    if symbols.orchestration == "marathon":
        svc.labels = {}
        svc.update()
    if is_kubernetes():
        orchestration.namespace = "default"
        orchestration.app.delete_configmap("%s-map" % svc.id)


class BigipController(object):
    """Manage a bigip-controller instance."""

    def __init__(
            self, orchestration, id=None, cpus=DEFAULT_F5MLB_CPUS,
            mem=DEFAULT_F5MLB_MEM, timeout=DEFAULT_DEPLOY_TIMEOUT,
            config=DEFAULT_F5MLB_CONFIG, wait_for_deploy=True,
            pool_mode=POOL_MODE_CLUSTER):
        """Make new object, but don't create service."""
        if id is None:
            id = unique_id(DEFAULT_F5MLB_NAME)
        self.orchestration = orchestration
        self.pool_mode = pool_mode
        if symbols.orchestration == "marathon":
            self.app_kwargs = {
                'id': id,
                'cpus': cpus,
                'mem': mem,
                'timeout': timeout,
                'container_img': symbols.bigip_controller_img,
                'container_force_pull_image': True,
                'env': config,
                'wait_for_deploy': wait_for_deploy,
                }
        elif is_kubernetes():
            service_account = None
            if symbols.orchestration == "openshift":
                service_account = DEFAULT_OPENSHIFT_ADMIN

            self.app_kwargs = {
                'id': id,
                'cpus': cpus,
                'mem': mem,
                'timeout': timeout,
                'container_img': symbols.bigip_controller_img,
                'container_force_pull_image': True,
                'cmd': config['cmd'],
                'args': config['args'] + ['--pool-member-type', pool_mode],
                'env': config['env'],
                'wait_for_deploy': wait_for_deploy,
                'service_account': service_account,
                }
        else:
            assert False, "Unsupported orchestration " + orchestration

    def create(self):
        """Create and start the controller instance."""
        if is_kubernetes():
            save_namespace = self.orchestration.namespace
            self.orchestration.namespace = controller_namespace()
            self.app = self.orchestration.app.create(**self.app_kwargs)
            self.orchestration.namespace = save_namespace
        else:
            self.app = self.orchestration.app.create(**self.app_kwargs)
        return self

    def delete(self):
        """Delete the controller instance."""
        if self.app:
            self.app.delete()
        self.app = None

    def suspend(self):
        """Suspend the controller instance."""
        self.app.suspend()

    def resume(self):
        """Resume the controller instance."""
        self.app.resume()


def create_unmanaged_service(orchestration, id, labels={},
                             app_port_mapping=DEFAULT_APP_PORT_MAPPING,
                             app_container_img=DEFAULT_APP_IMG):
    """Create a microservice with no bigip-controller decorations."""
    if symbols.orchestration == "openshift":
        service_account = DEFAULT_OPENSHIFT_USER
    else:
        service_account = None
    if is_kubernetes():
        orchestration.namespace = "default"

    return orchestration.app.create(
        id=id,
        cpus=DEFAULT_SVC_CPUS,
        mem=DEFAULT_SVC_MEM,
        timeout=DEFAULT_DEPLOY_TIMEOUT,
        container_img=app_container_img,
        labels=labels,
        container_port_mappings=app_port_mapping,
        container_force_pull_image=True,
        service_account=service_account
    )


def get_backend_object_name(svc, port_idx=0):
    """Generate expected backend object name."""
    if symbols.orchestration == "marathon":
        return (
            "%s_%s"
            % (
                svc.id.replace("/", ""),
                str(svc.labels['F5_%d_PORT' % port_idx])
            )
        )
    if is_kubernetes():
        return (
            "%s_%s-map" % (svc.namespace, svc.id)
        )


def wait_for_bigip_controller(num_seconds=DEFAULT_F5MLB_WAIT):
    """Wait for bigip-controller to restore expected state (or not!)."""
    time.sleep(num_seconds)


def update_svc_config(config, orchestration, svc_id):
    """Update a service's configuration."""
    if symbols.orchestration == 'marathon':
        orchestration.app.update(svc_id, cpus=DEFAULT_SVC_CPUS,
                                 mem=DEFAULT_SVC_MEM, labels=config,
                                 timeout=DEFAULT_DEPLOY_TIMEOUT,
                                 wait_for_deploy=True,
                                 health_checks=DEFAULT_SVC_HEALTH_CHECKS_HTTP)
    elif is_kubernetes():
        config['name'] = svc_id + "-map"
        config['data']['data']['virtualServer']['backend']['serviceName'] = \
            svc_id
        orchestration.app.update_configmap(config)


def get_iapp_config(iapp):
    if symbols.orchestration == "marathon":
        cfg = {
            'F5_PARTITION': DEFAULT_F5MLB_PARTITION,
            'F5_0_IAPP_TEMPLATE': iapp.name,
        }
        if hasattr(iapp, 'pool_member_table_name'):
            cfg['F5_0_IAPP_POOL_MEMBER_TABLE_NAME'] = \
                iapp.pool_member_table_name
        if hasattr(iapp, 'pool_member_table'):
            cfg['F5_0_IAPP_POOL_MEMBER_TABLE'] = \
                json.dumps(iapp.pool_member_table)
        for k, v in iapp.options.iteritems():
            cfg['F5_0_IAPP_OPTION_' + k] = v
        for k, v in iapp.vars.iteritems():
            cfg['F5_0_IAPP_VARIABLE_' + k] = v
        for k, v in iapp.tables.iteritems():
            cfg['F5_0_IAPP_TABLE_' + k] = json.dumps(v)
    if is_kubernetes():
        cfg = copy.deepcopy(DEFAULT_SVC_CONFIG)
        cfg['data']['data']['virtualServer'].pop('frontend')
        cfg['data']['data']['virtualServer']['frontend'] = {
            'partition': DEFAULT_F5MLB_PARTITION,
            'iapp': iapp.name,
            'iappPoolMemberTable': iapp.pool_member_table,
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
        self.options = {'description': "This is a test iApp"}
        self.pool_member_table = {
            "name": "pool__members",
            "columns": [{"name": "addr", "kind": "IPAddress"},
                        {"name": "port", "kind": "Port"},
                        {"name": "connection_limit", "value": "0"}]
        }
        self.tables = {}

        CREATE_NEW = "/#create_new#"
        DONT_USE = "/#do_not_use#"
        self.vars = {
            'net__client_mode': "wan",
            'net__server_mode': "lan",
            'pool__addr': DEFAULT_F5MLB_BIND_ADDR,
            'pool__port': str(DEFAULT_F5MLB_PORT),
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


def get_backend_objects(bigip, partition=DEFAULT_F5MLB_PARTITION):
    """Get the resources managed by BIG-IP."""
    ret = {}

    if not bigip.partition.exists(name=partition):
        return {}

    # - get list of virtual servers
    virtual_servers = bigip.virtual_servers.list(partition=partition)
    if virtual_servers:
        ret['virtual_servers'] = virtual_servers

    # - get list of virtual addresses
    virtual_addresses = bigip.virtual_addresses.list(partition=partition)
    if virtual_addresses:
        ret['virtual_addresses'] = virtual_addresses

    # - get list of pools
    pools = bigip.pools.list(partition=partition)
    if pools:
        ret['pools'] = pools

    # - get list of pool members
    pool_members = bigip.pool_members.list(partition=partition)
    if pool_members:
        ret['pool_members'] = sorted(pool_members)

    # - get list of health monitors
    health_monitors = bigip.health_monitors.list(partition=partition)
    if health_monitors:
        ret['health_monitors'] = health_monitors

    # - get list of nodes
    nodes = bigip.nodes.list(partition=partition)
    if nodes:
        ret['nodes'] = sorted(nodes)

    return ret


def get_backend_fdb_endpoints(bigip,
                              vxlan_tunnel=DEFAULT_BIGIP_VXLAN_TUNNEL,
                              partition=DEFAULT_F5MLB_PARTITION):
    """Get FDB endpoints for named VxLAN Tunnel."""
    ret = []

    fdb_tunnel = bigip.fdb_tunnel.get(name=vxlan_tunnel, partition=partition)

    if hasattr(fdb_tunnel, 'records'):
        for item in fdb_tunnel.records:
            ret.append(item['endpoint'])

    return ret


def get_backend_pool_members_exp(svc, bigip_controller, port_idx=0):
    """Return a list of pool member addr:port."""
    if bigip_controller.pool_mode == POOL_MODE_NODEPORT:
        nodes = symbols.worker_default_ips
        port = svc.get_service_node_port(port_idx)
        return ["{:s}:{:d}".format(x, port) for x in nodes]
    else:
        instances = svc.instances.get()
        pm = ["{:s}:{:d}".format(x.host, x.ports[port_idx]) for x in instances]
        return pm


def get_backend_objects_exp(svcs, bigip_controller, pool_only=False):
    """A dict of the expected backend resources."""
    if type(svcs) is not list:
        svcs = [svcs]
    if bigip_controller.pool_mode == POOL_MODE_NODEPORT:
        nodes = symbols.worker_default_ips
    else:
        nodes = []
    object_names = []
    virtual_addr = []
    pool_members = []
    for service in svcs:
        if bigip_controller.pool_mode == POOL_MODE_CLUSTER:
            for i in service.instances.get():
                nodes.append(i.host)
        object_names.append(get_backend_object_name(service))
        if symbols.orchestration == "marathon":
            virtual_addr.append(service.labels['F5_0_BIND_ADDR'])
        elif is_kubernetes() and not pool_only:
            ips = get_k8s_status_ip_address(service)
            for ip in ips:
                virtual_addr.append(ip)
        for pool_member in get_backend_pool_members_exp(
                service, bigip_controller):
            pool_members.append(pool_member)
    object_names = sorted(object_names)
    ret = {
        'virtual_servers': object_names,
        'virtual_addresses': sorted(virtual_addr),
        'health_monitors': object_names,
        'pools': object_names,
        'pool_members': sorted(pool_members),
        'nodes': sorted(nodes),
    }
    # pool only mode does not create virtual servers or virtual addresses
    if pool_only:
        del ret['virtual_servers']
        del ret['virtual_addresses']
    # get_backend_objects doesn't return non-empty lists
    for k, v in ret.items():
        if not v:
            del ret[k]
    return ret


def verify_backend_objs(bigip, svc, bigip_controller, pool_only=False):
    """Verify backend objs are expected."""
    backend_objs_exp = get_backend_objects_exp(svc, bigip_controller,
                                               pool_only=pool_only)
    assert get_backend_objects(bigip) == backend_objs_exp
    if is_kubernetes() and not pool_only:
        assert (get_backend_objects(bigip)['virtual_addresses'] ==
                get_k8s_status_ip_address(svc))
    elif is_kubernetes() and pool_only:
        assert (get_backend_objects(bigip).get('virtual_addresses', None) is
                None)


def wait_for_backend_objects(
        bigip, objs_exp, partition=DEFAULT_F5MLB_PARTITION, timeout=60):
    """Verify that the actual backend resources match what's expected."""
    interval = 2
    duration = 0
    while get_backend_objects(bigip) != objs_exp and duration <= timeout:
        time.sleep(interval)
        duration += interval
    assert get_backend_objects(bigip) == objs_exp


def verify_bigip_round_robin(ssh, svc, protocol=None, ipaddr=None, port=None,
                             msg=""):
    """Verify round-robin load balancing behavior."""
    # - bigip round robin is not as predictable as we would like (ie. you
    #   can't be sure that two consecutive requests will be sent to two
    #   separate pool members - but if you send enough requests, the responses
    #   will average out to something like what you expected).
    svc_url = _get_svc_url(svc, protocol, ipaddr, port)
    num_members = svc.instances.count()
    num_requests = num_members * 10
    min_res_per_member = 2

    # - send the target number of requests and collect the responses
    act_responses = {}
    curl_cmd = "curl -s -k %s" % svc_url
    ptn = re.compile("^Hello from .+ :0\)$")
    for i in range(num_requests):
        res = ssh.run(symbols.bastion, curl_cmd)
        # - verify response looks good
        assert re.match(ptn, res), msg
        if res not in act_responses:
            act_responses[res] = 1
        else:
            act_responses[res] += 1

    # - verify we got at least 2 responses from each member
    for k, v in act_responses.iteritems():
        assert v >= min_res_per_member, msg


def deploy_controller(request, orchestration, env_vars={}, mode=None,
                      user=None, pwd=None):
    """Configure and deploy marathon or k8s BIGIP controller."""
    if mode is None:
        mode = request.config._meta.vars.get(
            'controller-pool-mode', POOL_MODE_CLUSTER)
    assert mode in POOL_MODES, "controller-pool-mode var is invalid"
    ctlr_config = deepcopy(DEFAULT_F5MLB_CONFIG)

    if user is not None:
        if symbols.orchestration == "marathon":
            ctlr_config['F5_CC_BIGIP_USERNAME'] = user
        elif is_kubernetes():
            ctlr_config['args'][F5MLB_KUBE_CONFIG_USERNAME_IDX] = user
    if pwd is not None:
        if symbols.orchestration == "marathon":
            ctlr_config['F5_CC_BIGIP_PASSWORD'] = pwd
        elif is_kubernetes():
            ctlr_config['args'][F5MLB_KUBE_CONFIG_PASSWORD_IDX] = pwd

    for key in env_vars:
        val = env_vars[key]
        if symbols.orchestration == 'marathon':
            ctlr_config[key] = val
        elif symbols.orchestration == 'k8s':
            ctlr_config['env'].update({key: str(val)})

    controller = BigipController(orchestration, cpus=0.5,
                                 mem=128, config=ctlr_config,
                                 pool_mode=mode).create()
    return controller


def get_app_instance(app, marathon_instance_number=0,
                     k8s_namespace='kube-system'):
    """Return app instance."""
    if symbols.orchestration == 'marathon':
        return app.app.instances.get()[marathon_instance_number]
    elif is_kubernetes():
        pod_name = app.app_kwargs['id']
        result = get_k8s_pod_name_and_namespace(pod_name)
        assert result, 'Could not find pod %s' % pod_name
        for pod in result:
            (name, namespace) = pod
            if namespace == k8s_namespace:
                return (name, namespace)
        return (None, None)


def get_k8s_status_ip_address(svcs):
    """Return the IP address contained in the status annotation."""
    if type(svcs) is not list:
        svcs = [svcs]
    status = []
    for service in svcs:
        cm = pykube.ConfigMap.objects(service._api).filter(
            namespace=service._namespace).get_by_name(
                "{}-map".format(service.id))
        annotations = cm.obj['metadata']['annotations']
        status.append(annotations['status.virtual-server.f5.com/ip'])
    return sorted(status)


def get_k8s_pod_name_and_namespace(pod_name):
    """Get full pod name and namespace of matching k8s pod(s)."""
    matches = []
    pod_cmd = ['kubectl', 'get', 'pods', '--all-namespaces']
    output = subprocess.check_output(pod_cmd)
    output_lines = output.split('\n')
    for line in output_lines:
        if pod_name in line:
            splits = line.split()
            namespace = splits[0]
            name = splits[1]
            matches.append((name, namespace))
    return matches


def get_k8s_pod_ip(pod_name):
    """Get the ip for a specific pod referenced by name."""
    pod_cmd = ['kubectl', 'describe', 'pods', pod_name]
    output = subprocess.check_output(pod_cmd)

    return re.search(r'^Node:\s+([^/]+)/\S+$', output,
                     flags=re.MULTILINE).group(1)


def get_k8s_pod_logs(pod_name, namespace):
    """Get logs of pod specified by name and namespace."""
    log_cmd = ['kubectl', 'logs', '--namespace', namespace, pod_name]
    log = subprocess.check_output(log_cmd)
    if log is not None:
        return log
    else:
        return ''


def get_dcos_task_logs(task_id):
    """Get logs of task specified by task id."""
    log_cmd = ['dcos', 'task', 'log', '--lines=999999', task_id]
    log = subprocess.check_output(log_cmd)
    if log is not None:
        return log
    else:
        return ''


def check_logs(app, start_str, stop_str='\n'):
    """Search the log of an app for a matching string."""
    search_index = 0
    log_time = time.time()

    while time.time() - log_time < LOG_TIMEOUT:
        if symbols.orchestration == 'marathon':
            if hasattr(symbols, 'mesos_flavor') and \
               symbols.mesos_flavor == 'dcos':
                log_output = get_dcos_task_logs(app.id)
            else:
                log_mgr = app.get_stderr()
                log_output = log_mgr.raw
        elif symbols.orchestration == 'k8s':
            (name, namespace) = app
            log_output = get_k8s_pod_logs(name, namespace)
        start_index = log_output.find(start_str, search_index)

        if start_index != -1:
            stop_index = log_output.find(stop_str, start_index)
            search_index = stop_index + 1 if stop_index != -1 else search_index
            yield log_output[start_index + len(start_str):None
                             if stop_index == -1 else stop_index]
    raise Exception('LOG TIMEOUT ERROR')


class NodeController(object):
    """Execute operations on cluster nodes."""

    def __init__(self):
        """The NodeController ctor."""
        if symbols.orchestration == 'openshift':
            pass
        else:
            assert False, "Unsupported orchestration " + symbols.orchestration

        self._teardowns = []

    def push_teardown(self, func, args):
        """Push a teardown onto the stack."""
        def closure():
            func(args)

        self._teardowns.insert(0, closure)

    def run_teardowns(self):
        """Run through teardown stack."""
        for teardown in self._teardowns:
            teardown()

    def clear_teardowns(self):
        """Clear all registered teardowns."""
        self._teardowns = []

    def mark_schedulability(self, schedulable, node):
        """Mark node unschedulable to prepare for evacuation."""
        cmd = ['oc', 'adm', 'manage-node']
        cmd.append(node)
        cmd.append('--schedulable={}'.format(schedulable))
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    def evacuate(self, mark_unschedulable, node):
        """Evacuate nodes from an orchestration environment."""
        if mark_unschedulable is True:
            self.mark_schedulability(False, node)

        cmd = ['oc', 'adm', 'manage-node']
        cmd.append(node)
        cmd.extend(['--evacuate', '--force'])
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    def get_node(self, node):
        """Get node config from an orchestration environment."""
        cmd = ['oc', 'get', '-o', 'yaml', 'nodes']
        cmd.append(node)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        out, _ = p.communicate()

        if p.returncode != 0:
            raise subprocess.CalledProcessError(returncode=p.returncode,
                                                cmd=cmd, output=out)
        return out

    def get_node_ips(self):
        """Get current node ips."""
        jp = '{.items[*].status.addresses[?(@.type=="InternalIP")].address}'
        arg = 'jsonpath={}'.format(jp)
        cmd = ['oc', 'get', 'nodes', '-o', arg]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        out, _ = p.communicate()

        if p.returncode != 0:
            raise subprocess.CalledProcessError(returncode=p.returncode,
                                                cmd=cmd, output=out)

        return out.split()

    def delete_node(self, node):
        """Delete a node from an orchestration environment."""
        cmd = ['oc', 'delete', 'nodes']
        cmd.append(node)
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    def add_node(self, config):
        """Add a node to an orchestration environment."""
        cmd = ['oc', 'create', '-f', '-']
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             stdin=subprocess.PIPE)
        out, _ = p.communicate(input=config)
        if p.returncode != 0:
            raise subprocess.CalledProcessError(returncode=p.returncode,
                                                cmd=cmd, output=out)


def _get_svc_url(svc, protocol=None, ipaddr=None, port=None):
    if symbols.orchestration == "marathon":
        return _get_svc_url_marathon(svc, protocol, ipaddr, port)
    elif is_kubernetes():
        return _get_svc_url_k8s(svc, protocol, ipaddr, port)


def _get_svc_url_marathon(svc, protocol=None, ipaddr=None, port=None):
    if protocol is None:
        if 'F5_0_SSL_PROFILE' in svc.labels:
            protocol = "https"
        else:
            protocol = "http"
    if ipaddr is None:
        if 'F5_0_BIND_ADDR' in svc.labels:
            ipaddr = svc.labels['F5_0_BIND_ADDR']
        else:
            ipaddr = DEFAULT_F5MLB_BIND_ADDR
    if port is None:
        if 'F5_0_PORT' in svc.labels:
            port = svc.labels['F5_0_PORT']
        else:
            port = DEFAULT_F5MLB_PORT
    return "%s://%s:%s" % (protocol, ipaddr, port)


def _get_svc_url_k8s(svc, protocol=None, ipaddr=None, port=None):
    vs_config = svc.vs_config
    # - we can't just assume that virtualAddress will exist because the
    #   virtual server might have been configured by an iApp
    vs_addr = vs_config.get('frontend', {}).get('virtualAddress', {})
    if protocol is None:
        if 'sslProfile' in vs_config.get('frontend', {}):
            protocol = "https"
        else:
            protocol = "http"
    if ipaddr is None:
        if 'bindAddr' in vs_addr:
            ipaddr = vs_addr['bindAddr']
        else:
            ipaddr = DEFAULT_F5MLB_BIND_ADDR
    if port is None:
        if 'port' in vs_addr:
            port = vs_addr['port']
        else:
            port = DEFAULT_F5MLB_PORT
    return "%s://%s:%s" % (protocol, ipaddr, port)
