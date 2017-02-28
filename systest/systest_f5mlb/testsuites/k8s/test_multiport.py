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

"""Test suites specific to k8s multiport."""

import time
import json
import copy
import pykube

from multiprocessing import TimeoutError
from pytest import meta_suite, meta_test
from systest_f5mlb.testsuites import utils
import icontrol.session


pytestmark = meta_suite(tags=["func", "k8s", "no_marathon",
                              "no_pool_mode_nodeport"])


POD_TEMPLATE = json.loads("""{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    "name": "xxxxxxxx",
    "labels": {
      "app": "webservers",
      "test-scope": "test"
    }
  },
  "spec": {
    "containers": [
      {
        "name": "webserver",
        "image": "xxxxxxxx",
        "ports": [
          {
            "containerPort": 0,
            "name": "xxxxxxxx",
            "protocol": "TCP"
          }
        ],
        "resources": {
          "limits": {
            "cpu": "0.1",
            "memory": "32Mi"
          }
        }
      }
    ]
  }
}""")


SERVICE_TEMPLATE = json.loads("""{
  "kind": "Service",
  "apiVersion": "v1",
  "metadata": {
    "name": "xxxxxxxx",
    "labels": {
      "test-scope": "test"
    }
  },
  "spec": {
    "type": "ClusterIP",
    "ports": [
      {
        "name": "xxxxxxxx",
        "protocol": "xxxxxxxx",
        "targetPort": "xxxxxxxx",
        "port": 0
      }
    ],
    "selector": {
      "app": "webservers"
    }
  }
}""")


CONFIGMAP_TEMPLATE = json.loads("""{
  "kind": "ConfigMap",
  "apiVersion": "v1",
  "metadata": {
    "name": "xxxxxxxx",
    "namespace": "default",
    "labels": {
      "f5type": "virtual-server",
      "test-scope": "test"
    }
  },
  "data": {
    "data": "xxxxxxxx",
    "schema": "f5schemadb://bigip-virtual-server_v0.1.2.json"
  }
}""")

VIRTUAL_SERVER_TEMPLATE = json.loads("""{
  "virtualServer": {
    "backend": {
      "healthMonitors": [
        {
          "interval": 5,
          "protocol": "xxxxxxxx",
          "send": "xxxxxxxx",
          "timeout": 2
        }
      ],
      "serviceName": "xxxxxxxx",
      "servicePort": 0
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "xxxxxxxx",
      "partition": "xxxxxxxx",
      "virtualAddress": {
        "bindAddr": "xxxxxxxx",
        "port": 0
      }
    }
  }
}""")


@meta_test(id="k8s-3", tags=[])
def test_k8s_multiport_pods_with_multiple_ports(ssh, orchestration, bigip,
                                                bigip_controller):
    """Test named ports get correctly mapped to a single virtual server."""
    # verify no bigip objects exist
    assert bigip_controller.pool_mode == utils.POOL_MODE_CLUSTER,\
        "Test expects pool member mode to be CLUSTER"
    assert utils.get_backend_objects(bigip) == {},\
        "Test expects BigIP to initial contain no objects"

    api = orchestration.conn

    named_ports = {}
    named_ports['foo'] = []
    named_ports['bar'] = []
    named_ports['baz'] = []

    #
    # 1. Create 3 pods and configure service to include ports tagged with 'foo'
    #    (There should be 3 of them)
    #
    pod1_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod1_cfg, 'pod1')
    _configure_pod_port(pod1_cfg, 0, 'foo', '8080')
    _configure_pod_port(pod1_cfg, 1, 'bar', '8081')

    pod1_obj = _create_pod(api, pod1_cfg)
    pod_ip = _get_pod_ip(pod1_obj)
    named_ports['foo'].append(pod_ip + ":8080")
    named_ports['bar'].append(pod_ip + ":8081")

    pod2_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod2_cfg, 'pod2')
    _configure_pod_port(pod2_cfg, 0, 'bar', '8081')
    _configure_pod_port(pod2_cfg, 1, 'foo', '8080')

    pod2_obj = _create_pod(api, pod2_cfg)
    pod_ip = _get_pod_ip(pod2_obj)
    named_ports['bar'].append(pod_ip + ":8081")
    named_ports['foo'].append(pod_ip + ":8080")

    pod3_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod3_cfg, 'pod3')
    _configure_pod_port(pod3_cfg, 0, 'foo', '80')
    _configure_pod_port(pod3_cfg, 1, 'baz', '8080')

    pod3_obj = _create_pod(api, pod3_cfg)
    pod_ip = _get_pod_ip(pod3_obj)
    named_ports['foo'].append(pod_ip + ":80")
    named_ports['baz'].append(pod_ip + ":8080")

    # create service for target foo
    svc_cfg = _copy_template(SERVICE_TEMPLATE)
    _configure_service_name(svc_cfg, 'svc-1')
    _configure_service_port(svc_cfg, 0, name='port-a', protocol='TCP',
                            targetPort='foo', servicePort=80)
    _create_service(api, svc_cfg)

    # create virtual server for target foo
    vs_cfg = _copy_template(VIRTUAL_SERVER_TEMPLATE)
    _configure_virtualserver(vs_cfg, fe_mode='http',
                             fe_bind_addr=utils.symbols.bigip_ext_ip,
                             fe_bind_port=80, be_service_name='svc-1',
                             be_service_port=80)
    cmap_cfg = _copy_template(CONFIGMAP_TEMPLATE)
    _configure_configmap(cmap_cfg, 'cmap-1', vs_cfg)
    _create_configmap(api, cmap_cfg)

    vs_name_cfg = _get_virtual_server_name('cmap-1', 80)
    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, named_ports['foo'])

    #
    # 2. Add another pod containing a port tagged with 'foo'
    #    There should now be four ports tagged with 'foo'
    #
    pod4_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod4_cfg, 'pod4')
    _configure_pod_port(pod4_cfg, 0, 'foo', '9090')

    pod4_obj = _create_pod(api, pod4_cfg)
    pod_ip = _get_pod_ip(pod4_obj)
    named_ports['foo'].append(pod_ip + ":9090")

    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, named_ports['foo'])

    #
    # 3. Add another unrelated pod and verify there are still 4 'foo' ports
    #
    pod5_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod5_cfg, 'pod5')
    _configure_pod_port(pod5_cfg, 0, 'bar', '9090')

    pod5_obj = _create_pod(api, pod5_cfg)
    pod_ip = _get_pod_ip(pod5_obj)
    named_ports['bar'].append(pod_ip + ":9090")

    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, named_ports['foo'])

    #
    # 4. Switch service to only port 80 (there is only one)
    #
    svc_cfg['spec']['ports'][0]['targetPort'] = 80
    _update_service(api, svc_cfg)

    port_80 = _get_pod_ip(pod3_obj) + ":80"
    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, [port_80])

    #
    # 5. Switch service to use ports marked with 'bar' (there are three)
    #
    svc_cfg['spec']['ports'][0]['targetPort'] = 'bar'
    _update_service(api, svc_cfg)

    # verify there are three pool members
    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, named_ports['bar'])

    #
    # 6. Delete pod that isn't part of service (foo/baz pod)
    #
    pod4_obj.delete()
    named_ports['foo'].pop()

    # verify there are still three pool members
    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, named_ports['bar'])

    #
    # 7. Delete pod that is part of service (foo/baz pod)
    #
    pod5_obj.delete()
    named_ports['bar'].pop()

    # verify there are now two pool members (added an assert to check logic)
    assert len(named_ports['bar']) == 2, \
        "There should only be two bar ports configured in the pods"
    _verify_virtual_server_objects(bigip, 1, vs_name_cfg, named_ports['bar'])


@meta_test(id="k8s-4", tags=[])
def test_k8s_multiport_service_with_multiple_ports(ssh, orchestration, bigip,
                                                   bigip_controller):
    """Test ports get correctly mapped in a multiport service."""
    # verify no bigip objects exist
    assert bigip_controller.pool_mode == utils.POOL_MODE_CLUSTER,\
        "Test expects pool member mode to be CLUSTER"
    assert utils.get_backend_objects(bigip) == {},\
        "Test expects BigIP to initial contain no objects"

    api = orchestration.conn

    named_ports = {}
    named_ports['foo'] = []
    named_ports['bar'] = []

    #
    # 1. Create 2 identical pods (each with 2 ports)
    #
    pod1_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod1_cfg, 'pod1')
    _configure_pod_port(pod1_cfg, 0, 'foo', '8080')
    _configure_pod_port(pod1_cfg, 1, 'bar', '8081')

    pod2_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod2_cfg, 'pod2')
    _configure_pod_port(pod2_cfg, 0, 'foo', '8080')
    _configure_pod_port(pod2_cfg, 1, 'bar', '8081')

    pod1_obj = _create_pod(api, pod1_cfg)
    pod_ip = _get_pod_ip(pod1_obj)
    named_ports['foo'].append(pod_ip + ":8080")
    named_ports['bar'].append(pod_ip + ":8081")

    pod2_obj = _create_pod(api, pod2_cfg)
    pod_ip = _get_pod_ip(pod2_obj)
    named_ports['foo'].append(pod_ip + ":8080")
    named_ports['bar'].append(pod_ip + ":8081")

    #
    # 2. Create one service  with two ports, each going to one of the pod ports
    #
    svc_cfg = _copy_template(SERVICE_TEMPLATE)
    _configure_service_name(svc_cfg, 'svc-1')
    _configure_service_port(svc_cfg, 0, name='port-a', protocol='TCP',
                            targetPort='foo', servicePort=80)
    _configure_service_port(svc_cfg, 1, name='port-b', protocol='TCP',
                            targetPort='bar', servicePort=8080)
    _create_service(api, svc_cfg)

    #
    # 3. Create virtual server for port-a (80) and verify Big-IP is configured
    #
    vs1_cfg = _copy_template(VIRTUAL_SERVER_TEMPLATE)
    _configure_virtualserver(vs1_cfg, fe_mode='http',
                             fe_bind_addr=utils.symbols.bigip_ext_ip,
                             fe_bind_port=80, be_service_name='svc-1',
                             be_service_port=80)
    cmap1_cfg = _copy_template(CONFIGMAP_TEMPLATE)
    _configure_configmap(cmap1_cfg, 'cmap-1', vs1_cfg)
    cmap1_obj = _create_configmap(api, cmap1_cfg)

    vs_name_port_a = _get_virtual_server_name('cmap-1', 80)
    _verify_virtual_server_objects(bigip, 1, vs_name_port_a,
                                   named_ports['foo'])

    #
    # 4. Create virtual server for port-b (8080) and verify Big-IP has 2 vs
    #
    vs2_cfg = _copy_template(VIRTUAL_SERVER_TEMPLATE)
    _configure_virtualserver(vs2_cfg, fe_mode='http',
                             fe_bind_addr=utils.symbols.bigip_ext_ip,
                             fe_bind_port=8080, be_service_name='svc-1',
                             be_service_port=8080)
    cmap2_cfg = _copy_template(CONFIGMAP_TEMPLATE)
    _configure_configmap(cmap2_cfg, 'cmap-2', vs2_cfg)
    _create_configmap(api, cmap2_cfg)

    vs_name_port_b = _get_virtual_server_name('cmap-2', 8080)
    _verify_virtual_server_objects(bigip, 2, vs_name_port_a,
                                   named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_port_b,
                                   named_ports['bar'])

    #
    # 5. Remove VS for port-a and verify Big-IP is still configured for port-b
    #
    cmap1_obj.delete()

    _verify_virtual_server_objects(bigip, 1, vs_name_port_b,
                                   named_ports['bar'])


@meta_test(id="k8s-5", tags=[])
def test_k8s_multiport_shared_service_port(ssh, orchestration, bigip,
                                           bigip_controller):
    """Test ports get correctly mapped in a multiport service."""
    # verify no bigip objects exist
    assert bigip_controller.pool_mode == utils.POOL_MODE_CLUSTER,\
        "Test expects pool member mode to be CLUSTER"
    assert utils.get_backend_objects(bigip) == {},\
        "Test expects BigIP to initial contain no objects"

    api = orchestration.conn

    named_ports = {}
    named_ports['foo'] = []
    named_ports['bar'] = []

    #
    # 1. Create 2 identical pods (each with 2 ports)
    #
    pod1_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod1_cfg, 'pod1')
    _configure_pod_port(pod1_cfg, 0, 'foo', '8080')
    _configure_pod_port(pod1_cfg, 1, 'bar', '8081')

    pod2_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod2_cfg, 'pod2')
    _configure_pod_port(pod2_cfg, 0, 'foo', '8080')
    _configure_pod_port(pod2_cfg, 1, 'bar', '8081')

    pod1_obj = _create_pod(api, pod1_cfg)
    pod_ip = _get_pod_ip(pod1_obj)
    named_ports['foo'].append(pod_ip + ":8080")
    named_ports['bar'].append(pod_ip + ":8081")

    pod2_obj = _create_pod(api, pod2_cfg)
    pod_ip = _get_pod_ip(pod2_obj)
    named_ports['foo'].append(pod_ip + ":8080")
    named_ports['bar'].append(pod_ip + ":8081")

    #
    # 2. Create one service with two ports, each going to one of the pod ports
    #
    svc_cfg = _copy_template(SERVICE_TEMPLATE)
    _configure_service_name(svc_cfg, 'svc-1')
    _configure_service_port(svc_cfg, 0, name='port-a', protocol='TCP',
                            targetPort='foo', servicePort=80)
    _configure_service_port(svc_cfg, 1, name='port-b', protocol='TCP',
                            targetPort='bar', servicePort=8080)
    _create_service(api, svc_cfg)

    #
    # 3. Create a virtual server for service port-a (80) and verify
    #
    vs1_cfg = _copy_template(VIRTUAL_SERVER_TEMPLATE)
    _configure_virtualserver(vs1_cfg, fe_mode='http',
                             fe_bind_addr=utils.symbols.bigip_ext_ip,
                             fe_bind_port=80, be_service_name='svc-1',
                             be_service_port=80)
    cmap1_cfg = _copy_template(CONFIGMAP_TEMPLATE)
    _configure_configmap(cmap1_cfg, 'cmap-1', vs1_cfg)
    _create_configmap(api, cmap1_cfg)

    vs_name_cfg1 = _get_virtual_server_name('cmap-1', 80)
    _verify_virtual_server_objects(bigip, 1, vs_name_cfg1, named_ports['foo'])

    #
    # 4. Create another virtual server for service port-a (80) and verify
    #
    vs2_cfg = _copy_template(VIRTUAL_SERVER_TEMPLATE)
    _configure_virtualserver(vs2_cfg, fe_mode='http',
                             fe_bind_addr=utils.symbols.bigip_ext_ip,
                             fe_bind_port=8080, be_service_name='svc-1',
                             be_service_port=80, be_hm_protocol='tcp',
                             be_hm_send='')
    cmap2_cfg = _copy_template(CONFIGMAP_TEMPLATE)
    _configure_configmap(cmap2_cfg, 'cmap-2', vs2_cfg)
    cmap2_obj = _create_configmap(api, cmap2_cfg)

    vs_name_cfg2 = _get_virtual_server_name('cmap-2', 8080)
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['foo'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/tcp')

    #
    # 5. Add third pod and verify both VS are updated on Big-IP
    #
    pod3_cfg = _copy_template(POD_TEMPLATE)
    _configure_pod_name(pod3_cfg, 'pod3')
    _configure_pod_port(pod3_cfg, 0, 'foo', '8080')
    _configure_pod_port(pod3_cfg, 1, 'bar', '8081')

    pod3_obj = _create_pod(api, pod3_cfg)
    pod_ip = _get_pod_ip(pod3_obj)
    named_ports['foo'].append(pod_ip + ":8080")
    named_ports['bar'].append(pod_ip + ":8081")

    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['foo'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/tcp')

    #
    # 6. Modify 2nd virtual server to use different service port
    #
    vs2_cfg['virtualServer']['backend']['servicePort'] = 8080
    _configure_configmap(cmap2_cfg, 'cmap-2', vs2_cfg)
    _update_configmap(api, cmap2_cfg)

    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['bar'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/tcp')

    #
    # 7. Remove 3rd pod and verify both VS are updated
    #
    pod3_obj.delete()
    named_ports['foo'].pop()
    named_ports['bar'].pop()

    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['bar'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/tcp')

    #
    # 8. Modify 2nd virtual server to use same port again
    #
    vs2_cfg['virtualServer']['backend']['servicePort'] = 80
    _configure_configmap(cmap2_cfg, 'cmap-2', vs2_cfg)
    _update_configmap(api, cmap2_cfg)

    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['foo'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/tcp')

    #
    # 9. Delete 2nd virtual server and verify original VS is unaffected
    #
    cmap2_obj.delete()

    _verify_virtual_server_objects(bigip, 1, vs_name_cfg1, named_ports['foo'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')

    #
    # 10. Re-add 2nd virtual server that uses same health monitor as first
    #
    vs2_cfg['virtualServer']['backend']['healthMonitors'] = \
        copy.deepcopy(vs1_cfg['virtualServer']['backend']['healthMonitors'])
    _configure_configmap(cmap2_cfg, 'cmap-2', vs2_cfg)
    _create_configmap(api, cmap2_cfg)

    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['foo'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/http')

    #
    # 11. Remove 2nd pod and verify both VS are updated (pointing at same svc)
    #
    pod2_obj.delete()
    named_ports['foo'].pop()
    named_ports['bar'].pop()

    # extra assert to verify each service refers to only one pod port
    assert len(named_ports['foo']) == 1, \
        "There should only be one foo port configured in the pod"
    assert len(named_ports['bar']) == 1, \
        "There should only be one bar port configured in the pod"

    _verify_virtual_server_objects(bigip, 2, vs_name_cfg1, named_ports['foo'])
    _verify_virtual_server_objects(bigip, 2, vs_name_cfg2, named_ports['foo'])
    _verify_health_monitor_object(bigip, vs_name_cfg1, '/Common/http')
    _verify_health_monitor_object(bigip, vs_name_cfg2, '/Common/http')


def _get_pod_ip(pod):
    return pod.obj['status']['podIP']


def _get_virtual_server_name(cfgmap_name, vs_dest_port):
    """Create the virtual service name based on the k8s config map values."""
    return utils.DEFAULT_F5MLB_NAMESPACE + "_" + cfgmap_name


def _copy_template(template):
    pod = copy.deepcopy(template)
    return pod


def _configure_virtualserver(
        vs_cfg, fe_mode, fe_bind_addr, fe_bind_port, be_service_name,
        be_service_port, be_hm_protocol='http',
        be_hm_send='GET / HTTP/1.0\\r\\n\\r\\n'):
    frontend = vs_cfg['virtualServer']['frontend']
    backend = vs_cfg['virtualServer']['backend']
    frontend['mode'] = fe_mode
    frontend['partition'] = utils.DEFAULT_F5MLB_PARTITION
    frontend['virtualAddress']['bindAddr'] = fe_bind_addr
    frontend['virtualAddress']['port'] = fe_bind_port
    backend['serviceName'] = be_service_name
    backend['servicePort'] = be_service_port
    backend['healthMonitors'][0]['protocol'] = be_hm_protocol
    if be_hm_send:
        backend['healthMonitors'][0]['send'] = be_hm_send
    else:
        del backend['healthMonitors'][0]['send']


def _configure_configmap(cmap_cfg, name, data):
    cmap_cfg['metadata']['name'] = name
    cmap_cfg['data']['data'] = json.dumps(data)


def _configure_pod_name(pod_cfg, name):
    pod_cfg['metadata']['name'] = name
    pod_cfg['spec']['containers'][0]['image'] = \
        'docker-registry.pdbld.f5net.com/systest-common/test-nginx:20170211'


def _configure_service_name(service_cfg, name):
    service_cfg['metadata']['name'] = name


def _configure_pod_port(pod_cfg, index, name, port):
    ports_cfg = pod_cfg['spec']['containers'][0]['ports']
    if index == len(ports_cfg):
        # This assumes ports are added sequentially, otherwise
        # an exception will occur due to incorrect programming
        ports_cfg.append({'protocol': 'TCP'})

    ports_cfg[index]['name'] = name
    ports_cfg[index]['containerPort'] = port


def _configure_service_port(service_cfg, index, name, protocol, targetPort,
                            servicePort):
    ports_cfg = service_cfg['spec']['ports']
    if index == len(ports_cfg):
        # This assumes ports are added sequentially, otherwise
        # an exception will occur due to incorrect programming
        ports_cfg.append({})

    ports_cfg[index]['name'] = name
    ports_cfg[index]['protocol'] = protocol
    ports_cfg[index]['targetPort'] = targetPort
    ports_cfg[index]['port'] = servicePort


def _create_pod(api, config):
    pod = pykube.Pod(api, config)
    pod.create()

    timeout = 60
    interval = 2
    duration = 0
    while duration <= timeout:
        if pod.exists():
            pod.reload()
            status = pod.obj['status']['phase']
            if status == 'Running':
                return pod
        time.sleep(interval)
        duration += interval

    raise TimeoutError(
        'Pod {} has not been created after {}s.'.format(
            config['metadata']['name'], timeout))


def _create_service(api, config):
    service = pykube.Service(api, config)
    service.create()

    timeout = 60
    interval = 2
    duration = 0
    while duration <= timeout:
        if service.exists():
            service.reload()
            return service
        time.sleep(interval)
        duration += interval

    raise TimeoutError(
        'Service {} has not been created after {}s.'.format(
            config['metadata']['name'], timeout))


def _update_service(api, config):
    service = pykube.Service(api, config)
    service.update()


def _create_configmap(api, config):
    configmap = pykube.ConfigMap(api, config)
    configmap.create()

    timeout = 60
    interval = 2
    duration = 0
    while duration <= timeout:
        if configmap.exists():
            configmap.reload()
            return configmap
        time.sleep(interval)
        duration += interval

    raise TimeoutError(
        'ConfigMap {} has not been created after {}s.'.format(
            config['metadata']['name'], timeout))


def _update_configmap(api, config):
    configmap = pykube.ConfigMap(api, config)
    configmap.update()


def _verify_virtual_server_objects(bigip, expected_vs_count,
                                   vs_name, expected_pool_members):
    """Verify the expected pool members exists for a virtual server."""
    actual_vs_count = 0
    actual_pool_members = []

    timeout = 60
    interval = 2
    duration = 0
    verified = False
    while not verified and duration <= timeout:
        try:
            actual_vs_count = len(bigip.virtual_servers.list(
                partition=utils.DEFAULT_F5MLB_PARTITION))

            if actual_vs_count != expected_vs_count:
                continue

            actual_pool_members = bigip.pool_members.list(
                partition=utils.DEFAULT_F5MLB_PARTITION, pool=vs_name)
            actual_pool_members.sort()
            expected_pool_members.sort()
            if actual_pool_members != expected_pool_members:
                continue
            verified = True
        except icontrol.exceptions.iControlUnexpectedHTTPError:
            pass
        finally:
            if not verified:
                time.sleep(interval)
                duration += interval

    if not verified:
        assert actual_vs_count == expected_vs_count
        assert actual_pool_members == expected_pool_members,\
            "BigIP pool members should match the service endpoints"


def _verify_health_monitor_object(bigip, health_name, expected_health_type):
    """Verify the health monitor inherits from the specified type."""
    actual_health_type = None

    timeout = 60
    interval = 2
    duration = 0
    verified = False
    while not verified and duration <= timeout:
        hm_obj = bigip.health_monitor.get(
            name=health_name, partition=utils.DEFAULT_F5MLB_PARTITION)
        if hm_obj is not None:
            actual_health_type = hm_obj.defaultsFrom
            if actual_health_type == expected_health_type:
                verified = True
        if not verified:
            time.sleep(interval)
            duration += interval

    if not verified:
        assert actual_health_type == expected_health_type,\
            "Health monitor should match config map spec"
