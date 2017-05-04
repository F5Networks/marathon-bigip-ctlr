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

"""Test suites specific to k8s namespaces."""

# import copy
import copy
import subprocess

from pytest import meta_suite, meta_test, symbols

from .. import utils


pytestmark = meta_suite(tags=["func", "k8s", "openshift", "no_marathon"])


@meta_test(id="k8s-7", tags=[])
def test_k8s_namespace_label(ssh, orchestration, bigip,
                             bigip_controller_factory, namespaces_factory,
                             openshift_service_acct_factory):
    """Test adding and removing labels from a namespace."""
    assert utils.get_backend_objects(bigip) == {}

    label_config = copy.deepcopy(utils.DEFAULT_F5MLB_CONFIG)
    label_config['args'][10] = '--namespace-label'
    label_config['args'][11] = 'watching'
    bigip_controller = bigip_controller_factory(ctlr_config=label_config)

    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    frontend = config['data']['data']['virtualServer']['frontend']
    frontend['virtualAddress']['bindAddr'] = '1.2.3.4'

    ns_foo = namespaces_factory("foo")
    ns_bar = namespaces_factory("bar")

    if symbols.orchestration == "openshift":
        openshift_service_acct_factory("foo")
        openshift_service_acct_factory("bar")

    svc_foo = utils.create_managed_northsouth_service(
        orchestration, "svc-foo", namespace='foo')
    svc_bar = utils.create_managed_northsouth_service(
        orchestration, "svc-bar", config=config, namespace='bar')

    # wait for the controller and services to come up and verify the bigip is
    # still empty
    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}

    # Add labels to the namespaces, one is correct, one is wrong
    ns_foo.obj["metadata"]["labels"] = {"watching": "yes"}
    ns_foo.update()
    ns_bar.obj["metadata"]["labels"] = {"nowatch": "no"}
    ns_bar.update()

    utils.wait_for_bigip_controller()
    # There should only be objects from one service
    utils.verify_backend_objs(bigip, svc_foo, bigip_controller)

    delete_label = ['kubectl', 'label', 'namespace', 'foo', 'watching-']
    subprocess.check_output(delete_label)

    utils.wait_for_bigip_controller()
    # Deleting the label should remove all objects
    assert utils.get_backend_objects(bigip) == {}

    add_label_foo = ['kubectl', 'label', 'namespace', 'foo', 'watching=yes']
    subprocess.check_output(add_label_foo)
    add_label_bar = ['kubectl', 'label', 'namespace', 'bar', 'watching=yes']
    subprocess.check_output(add_label_bar)

    utils.wait_for_bigip_controller()
    # Two objects should exists
    utils.verify_backend_objs(bigip, [svc_foo, svc_bar], bigip_controller)

    delete_label_foo = ['kubectl', 'label', 'namespace', 'foo', 'watching-']
    subprocess.check_output(delete_label_foo)
    delete_label_bar = ['kubectl', 'label', 'namespace', 'bar', 'watching-']
    subprocess.check_output(delete_label_bar)

    utils.wait_for_bigip_controller()
    # Deleting the label should remove all objects
    assert utils.get_backend_objects(bigip) == {}


@meta_test(id="k8s-8", tags=[])
def test_k8s_namespaces_all(ssh, orchestration, bigip,
                            bigip_controller_factory, namespaces_factory,
                            openshift_service_acct_factory):
    """Test adding and removing namespaces with services while watching all
    namespaces."""
    assert utils.get_backend_objects(bigip) == {}

    label_config = copy.deepcopy(utils.DEFAULT_F5MLB_CONFIG)
    del label_config['args'][10:12]
    bigip_controller = bigip_controller_factory(ctlr_config=label_config)
    # Assert no objects are on the bigip after the controller comes up
    assert utils.get_backend_objects(bigip) == {}

    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    frontend = config['data']['data']['virtualServer']['frontend']
    frontend['virtualAddress']['bindAddr'] = '1.2.3.4'

    # Create two namespaces with a service in each
    ns_alpha = namespaces_factory("alpha")
    ns_bravo = namespaces_factory("bravo")

    if symbols.orchestration == "openshift":
        openshift_service_acct_factory("alpha")
        openshift_service_acct_factory("bravo")

    svc_alpha = utils.create_managed_northsouth_service(
        orchestration, "svc-alpha", namespace='alpha')
    svc_bravo = utils.create_managed_northsouth_service(
        orchestration, "svc-bravo", config=config, namespace='bravo')

    utils.wait_for_bigip_controller()
    # Two objects should exists on the bigip
    utils.verify_backend_objs(bigip, [svc_alpha, svc_bravo], bigip_controller)

    # delete one of the namespaces and the service associated with it
    ns_alpha.delete()

    utils.wait_for_bigip_controller()
    # One object should exists on the bigip
    utils.verify_backend_objs(bigip, svc_bravo, bigip_controller)

    # delete the 2nd namespace and the service associated with it
    ns_bravo.delete()

    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}

    # recreate the first namespace to verify add and delete of the same ns
    ns_alpha = namespaces_factory("alpha")
    svc_alpha = utils.create_managed_northsouth_service(
        orchestration, "svc-alpha", namespace='alpha')

    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc_alpha, bigip_controller)

    # create a new namespace and add it
    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    frontend = config['data']['data']['virtualServer']['frontend']
    frontend['virtualAddress']['bindAddr'] = '5.6.7.8'
    namespaces_factory("charlie")
    svc_charlie = utils.create_managed_northsouth_service(
        orchestration, "svc-charlie", config=config, namespace='charlie')

    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(
        bigip, [svc_alpha, svc_charlie], bigip_controller)


@meta_test(id="k8s-9", tags=[])
def test_k8s_namespaces_list(ssh, orchestration, bigip,
                             bigip_controller_factory, namespaces_factory,
                             openshift_service_acct_factory):
    """Test adding and removing namespaces with services while watching a list
    of namespaces."""
    assert utils.get_backend_objects(bigip) == {}

    namespaces = ["delta", "echo"]

    label_config = copy.deepcopy(utils.DEFAULT_F5MLB_CONFIG)
    del label_config['args'][10:12]
    for ns in namespaces:
        label_config['args'].extend(['--namespace', ns])
    bigip_controller = bigip_controller_factory(ctlr_config=label_config)
    # Assert no objects are on the bigip after the controller comes up
    assert utils.get_backend_objects(bigip) == {}

    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    frontend = config['data']['data']['virtualServer']['frontend']
    frontend['virtualAddress']['bindAddr'] = '1.2.3.4'

    # Create two namespaces with a service in each
    ns_delta = namespaces_factory("delta")
    ns_echo = namespaces_factory("echo")

    if symbols.orchestration == "openshift":
        openshift_service_acct_factory("delta")
        openshift_service_acct_factory("echo")

    svc_delta = utils.create_managed_northsouth_service(
        orchestration, "svc-delta", namespace='delta')
    svc_echo = utils.create_managed_northsouth_service(
        orchestration, "svc-echo", config=config, namespace='echo')

    utils.wait_for_bigip_controller()
    # Two objects should exists on the bigip
    utils.verify_backend_objs(bigip, [svc_delta, svc_echo], bigip_controller)

    # delete one of the namespaces and the service associated with it
    ns_delta.delete()

    utils.wait_for_bigip_controller()
    # One object should exists on the bigip
    utils.verify_backend_objs(bigip, svc_echo, bigip_controller)

    # delte the 2nd namespace and the service associated with it
    ns_echo.delete()

    utils.wait_for_bigip_controller()
    assert utils.get_backend_objects(bigip) == {}

    # recreate the first namespace to verify add and delete of the same ns
    ns_delta = namespaces_factory("delta")
    svc_delta = utils.create_managed_northsouth_service(
        orchestration, "svc-delta", namespace='delta')

    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc_delta, bigip_controller)

    # create a new unwatched namespace and add a service
    config = copy.deepcopy(utils.DEFAULT_SVC_CONFIG)
    frontend = config['data']['data']['virtualServer']['frontend']
    frontend['virtualAddress']['bindAddr'] = '5.6.7.8'
    namespaces_factory("foxtrot")
    utils.create_managed_northsouth_service(
        orchestration, "svc-foxtrot", config=config, namespace='foxtrot')

    # the service should not be added for an unwatched namespace
    utils.wait_for_bigip_controller()
    utils.verify_backend_objs(bigip, svc_delta, bigip_controller)
