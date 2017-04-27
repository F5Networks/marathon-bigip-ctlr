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

"""Test suite to verify scenarios with reconfigs from the orchestration env."""

from collections import namedtuple

from pytest import meta_suite
from pytest import meta_test

import icontrol.session
from systest_f5mlb.testsuites import utils

pytestmark = meta_suite(
    tags=["func", "marathon", "openshift", "k8s", "auth"]
)

# The external radius server has one user configured as user1/secretpass
_RADIUS_APP_ID = 'radius'

_VALID_ROLE = 'resource-admin'
_INVALID_ROLE = 'operator'
_VALID_EXT_USER = 'user1'
_VALID_EXT_PWD = 'secretpass'
_INVALID_EXT_PWD = 'badpass'


@meta_test(id="f5mlb-72", tags=[])
def test_ext_auth_valid_user_valid_role(orchestration, request,
                                        bigip, radius):
    """Create virtual server using a valid external user with proper role.

    Configure the bigip to use an external authentication service and then
    verify that the controller can create objects when given a valid external
    user with the correct role assigned.
    """
    (radius_ip, radius_port) = _get_radius_instance_address(radius)
    with BigipRadiusAuth(bigip, radius_ip, radius_port, _VALID_ROLE):
        with BigipAuthController(request, orchestration, _VALID_EXT_USER,
                                 _VALID_EXT_PWD) as controller:
            _verify_bigip_updates(orchestration, bigip, controller, True)


@meta_test(id="f5mlb-73", tags=[])
def test_ext_auth_invalid_user_valid_role(orchestration, request,
                                          bigip, radius):
    """Create virtual server using an invalid external user with proper role.

    Configure the bigip to use an external authentication service and then
    verify that the controller will not create objects when given an invalid
    external user even if the correct role is assigned. Note: 'invalid user'
    can be either an invalid user name or an invalid password (tested here).
    """
    (radius_ip, radius_port) = _get_radius_instance_address(radius)
    with BigipRadiusAuth(bigip, radius_ip, radius_port, _VALID_ROLE):
        with BigipAuthController(request, orchestration, _VALID_EXT_USER,
                                 _INVALID_EXT_PWD) as controller:
            _verify_bigip_updates(orchestration, bigip, controller, False)


@meta_test(id="f5mlb-74", tags=[])
def test_ext_auth_valid_user_invalid_role(orchestration, request,
                                          bigip, radius):
    """Create virtual server using a valid external user with improper role.

    Configure the bigip to use an external authentication service and then
    verify that the controller will not create objects when given a valid
    external user with a role that doesn't include CRUD permissions.
    """
    (radius_ip, radius_port) = _get_radius_instance_address(radius)
    with BigipRadiusAuth(bigip, radius_ip, radius_port, _INVALID_ROLE):
        with BigipAuthController(request, orchestration, _VALID_EXT_USER,
                                 _VALID_EXT_PWD) as controller:
            _verify_bigip_updates(orchestration, bigip, controller, False)


@meta_test(id="f5mlb-75", tags=[])
def test_local_valid_user_valid_role(orchestration, request, bigip):
    """Create virtual server using a local user with a proper role.

    Configure the bigip to use a non-admin local user that has a role
    configured which supports CRUD operations using the REST api.
    Verify the objects are created.
    """
    with BigipLocalUser(bigip, "user1", "superSecretPwd1", _VALID_ROLE):
        with BigipAuthController(request, orchestration, "user1",
                                 "superSecretPwd1") as controller:
            _verify_bigip_updates(orchestration, bigip, controller, True)


@meta_test(id="f5mlb-76", tags=[])
def test_local_invalid_user_valid_role(orchestration, request, bigip):
    """Create virtual server using an invalid local user with a proper role.

    Configure the bigip to use a non-admin local user that has a proper
    role for CRUD operations, but the password is invalid. Verify objects
    are not created.
    """
    with BigipLocalUser(bigip, "user1", "superSecretPwd1", _VALID_ROLE):
        with BigipAuthController(request, orchestration, "user1",
                                 password="wrongPassword") as controller:
            _verify_bigip_updates(orchestration, bigip, controller, False)


@meta_test(id="f5mlb-77", tags=[])
def test_local_valid_user_invalid_role(orchestration, request, bigip):
    """Create virtual server using a valid local user with an improper role.

    Configure the bigip to use a non-admin local user that has a role
    which doesn't support CRUD operations.  Verify objects are not created.
    """
    with BigipLocalUser(bigip, "user1", "superSecretPwd1", _INVALID_ROLE):
        with BigipAuthController(request, orchestration, "user1",
                                 password="superSecretPwd1") as controller:
            _verify_bigip_updates(orchestration, bigip, controller, False)


class BigipAuthController(object):
    def __init__(self, request, orchestration, username, password):
        self.request = request
        self.orchestration = orchestration
        self.username = username
        self.password = password
        self.controller = None

    def __enter__(self):
        self.controller = utils.deploy_controller(
            self.request, self.orchestration, user=self.username,
            pwd=self.password)
        return self.controller

    def __exit__(self, type, value, traceback):
        if self.controller:
            old_namespace = self.orchestration.namespace
            self.orchestration.namespace = utils.controller_namespace()
            self.controller.delete()
            self.controller = None
            self.orchestration.namespace = old_namespace


class BigipRadiusAuth(object):
    def __init__(self, bigip, radius_ip, radius_port, role):
        self.bigip = bigip
        self.radius_ip = radius_ip
        self.radius_port = radius_port
        self.role = role

    def __enter__(self):
        _add_bigip_radius_service(
            self.bigip, self.radius_ip, self.radius_port, self.role)
        return self

    def __exit__(self, type, value, traceback):
        _remove_bigip_radius_service(self.bigip)


def _add_bigip_radius_service(bigip, ip, port, role):
    # The SDK to date (4/20/17) does not support configuring
    # external auth servers, so we drop down to the f5-icontrol-rest
    # API layer.
    session = bigip._conn._meta_data['icr_session']
    base_uri = bigip._conn._meta_data['uri'] + 'tm/auth/'

    # Configure the BIG-IP for the radius server
    radius_server_options = {
        "name": "system_auth_name1",
        "port": port,
        "server": ip,
        "secret": "supersecret"
    }
    try:
        session.post(base_uri + 'radius-server',
                     json=radius_server_options)
    except icontrol.exceptions.iControlUnexpectedHTTPError as e:
        if e.response.status_code == 409:
            # If this resource already exists, try updating it to
            # get the new port and address
            del radius_server_options['name']
            session.put(base_uri + 'radius-server/system_auth_name1',
                        json=radius_server_options)
        else:
            raise e

    # Configure the BIG-IP to use this specific radius-server
    radius_options = {
        "name": "system-auth",
        "servers": [
            "system_auth_name1"
        ]
    }
    try:
        session.post(base_uri + 'radius',
                     json=radius_options)
    except icontrol.exceptions.iControlUnexpectedHTTPError as e:
        if e.response.status_code != 409:
            raise e

    # Configure the BIG-IP external authentication role
    auth_role_options = {
        "default-role": role
    }
    session.put(base_uri + 'remote-user',
                json=auth_role_options)

    # Configure the BIG-IP to use radius for user authentication
    # (this should be last since it disables local users except admin)
    auth_source_options = {
        "type": "radius"
    }
    session.put(base_uri + 'source',
                json=auth_source_options)


def _remove_bigip_radius_service(bigip):
    # The SDK to date (4/20/17) does not support configuring
    # external auth servers, so we drop down to the f5-icontrol-rest
    # API layer.
    session = bigip._conn._meta_data['icr_session']
    base_uri = bigip._conn._meta_data['uri'] + 'tm/auth/'

    # Configure the BIG-IP to use local user authentication
    auth_source_options = {
        "type": "local"
    }
    session.put(base_uri + 'source',
                json=auth_source_options)

    # Remove the specific radius-server from the radius configuration
    radius_options = {
        "servers": [
        ]
    }
    session.put(base_uri + 'radius/system-auth',
                json=radius_options)

    # Delete the radius configuration from the BIG-IP
    session.delete(base_uri + 'radius/system-auth')

    # Delete the specific radius server from the BIG-IP
    session.delete(base_uri + 'radius-server/system_auth_name1')


class BigipLocalUser(object):
    def __init__(self, bigip, username, password, role):
        self.bigip = bigip
        self.username = username
        self.password = password
        self.role = role

    def __enter__(self):
        _add_bigip_local_user(
            self.bigip, self.username, self.password, self.role)
        return self

    def __exit__(self, type, value, traceback):
        # FIXME(kenr): Big-IP occassionally has problems deleting users
        #              completely. Once a user has been partially deleted,
        #              it will not show up when queried, but the user
        #              cannot be recreated.
        _remove_bigip_local_user(self.bigip, self.username)


def _add_bigip_local_user(bigip, username, password, role):
    options = {
        "password": password,
        "partition-access": [
            {
                "name": "all-partitions",
                "role": role
            }
        ]
    }
    try:
        bigip._conn.tm.auth.users.user.create(name=username, **options)
    except icontrol.exceptions.iControlUnexpectedHTTPError as e:
        if e.response.status_code == 409:
            # If this user already exists (possibly due to a previous
            # systest run being aborted), try updating it to specify
            # the new role
            user = bigip._conn.tm.auth.users.user.load(name=username)
            user.modify(**options)
        else:
            raise e


def _remove_bigip_local_user(bigip, username):
    user = bigip._conn.tm.auth.users.user.load(name=username)
    user.delete()


def _get_radius_instance_address(radius_svc):
    # Create a pseudo app that get_app_instance() will be happy with
    RadiusApp = namedtuple('RadiusApp', ['app', 'app_kwargs'])
    kwargs = {'id': _RADIUS_APP_ID}
    app = RadiusApp(app=radius_svc, app_kwargs=kwargs)
    app_instance = utils.get_app_instance(app, k8s_namespace='default')

    ip = None
    port = None
    if utils.is_kubernetes():
        (pod_name, pod_namespace) = app_instance
        ip = utils.get_k8s_pod_ip(pod_name)
        port = radius_svc.service_node_port
    else:
        ip = app_instance.host
        port = app_instance.ports[0]
    return (ip, port)


def _verify_bigip_updates(orchestration, bigip, controller, valid_user):
    # Should not have any objects to start
    utils.wait_for_backend_objects(bigip, {})

    # Start managed service
    svc = utils.create_managed_northsouth_service(orchestration)
    assert svc.instances.count() > 0

    # Verify new bigip objects created for managed service if user has
    # proper credentials
    try:
        expected_objs = {}
        if valid_user:
            utils.wait_for_bigip_controller()
            expected_objs = utils.get_backend_objects_exp(svc, controller)
        utils.wait_for_backend_objects(bigip, expected_objs)
    finally:
        svc.delete()
        utils.wait_for_backend_objects(bigip, {})
