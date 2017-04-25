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

import icontrol.session

from pytest import meta_suite
from pytest import meta_test

pytestmark = meta_suite(
    tags=["func", "marathon", "openshift", "k8s", "auth"]
)

_RADIUS_APP_ID = 'radius'

_VALID_ROLE = 'resource-admin'
_INVALID_ROLE = 'operator'
_VALID_EXT_USER = 'user1'
_VALID_EXT_PWD = 'secretpass'
_INVALID_EXT_PWD = 'badpass'


@meta_test(id="f5mlb-72", tags=["incomplete"])
def test_ext_auth_valid_user_valid_role(orchestration, request,
                                        bigip, radius):
    """Create virtual server using a valid external user with proper role.

    Configure the bigip to use an external authentication service and then
    verify that the controller can create objects when given a valid external
    user with the correct role assigned.
    """
    pass


@meta_test(id="f5mlb-73", tags=["incomplete"])
def test_ext_auth_invalid_user_valid_role(orchestration, request,
                                          bigip, radius):
    """Create virtual server using an invalid external user with proper role.

    Configure the bigip to use an external authentication service and then
    verify that the controller will not create objects when given an invalid
    external user even if the correct role is assigned. Note: 'invalid user'
    can be either an invalid user name or an invalid password.
    """
    pass


@meta_test(id="f5mlb-74", tags=["incomplete"])
def test_ext_auth_valid_user_invalid_role(orchestration, request,
                                          bigip, radius):
    """Create virtual server using a valid external user with improper role.

    Configure the bigip to use an external authentication service and then
    verify that the controller will not create objects when given a valid
    external user with a role that doesn't include CRUD permissions.
    """
    pass


@meta_test(id="f5mlb-75", tags=["incomplete"])
def test_local_valid_user_valid_role(orchestration, request, bigip):
    """Create virtual server using a local user with a proper role.

    Configure the bigip to use a non-admin local user that has a role
    configured which supports CRUD operations using the REST api.
    Verify the objects are created.
    """
    pass


@meta_test(id="f5mlb-76", tags=["incomplete"])
def test_local_invalid_user_valid_role(orchestration, request, bigip):
    """Create virtual server using an invalid local user with a proper role.

    Configure the bigip to use a non-admin local user that has a proper
    role for CRUD operations, but the password is invalid. Verify objects
    are not created.
    """
    pass


@meta_test(id="f5mlb-77", tags=["incomplete"])
def test_local_valid_user_invalid_role(orchestration, request, bigip):
    """Create virtual server using a valid local user with an improper role.

    Configure the bigip to use a non-admin local user that has a role
    which doesn't support CRUD operations.  Verify objects are not created.
    """
    pass


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

    # Configure the BIG-IP to use radius for user authentication
    auth_source_options = {
        "type": "radius"
    }
    session.put(base_uri + 'source',
                json=auth_source_options)

    # Configure the BIG-IP external authentication role
    auth_role_options = {
        "default-role": role
    }
    session.put(base_uri + 'remote-user',
                json=auth_role_options)


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
