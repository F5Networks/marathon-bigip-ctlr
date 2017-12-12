#!/usr/bin/env python
#
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

"""marathon-bigip-ctlr.

marathon-bigip-ctlr is a service discovery and load balancing tool
for Marathon to configure an F5 BIG-IP. It reads the Marathon task information
and dynamically generates BIG-IP configuration details.

To gather the task information, marathon-bigip-ctlr needs to know where
to find Marathon. The service configuration details are stored in labels.

Every service port in Marathon can be configured independently.

### Configuration
Service configuration lives in Marathon via labels.
marathon-bigip-ctlr just needs to know where to find Marathon.
"""

from __future__ import print_function

import json
import logging
from operator import attrgetter
import os
import os.path
import re
import sys
import time
import threading
from itertools import cycle
from urlparse import urlparse

import configargparse
import requests
from requests.exceptions import ConnectionError
from sseclient import SSEClient

from common import (set_logging_args, set_marathon_auth_args,
                    setup_logging, get_marathon_auth_params, resolve_ip,
                    validate_bigip_address)
from f5_cccl.api import F5CloudServiceManager
from f5_cccl.exceptions import F5CcclError
from f5_cccl.utils.mgmt import mgmt_root


# BIG-IP load-balancing methods
lb_methods = [
    "dynamic-ratio-member",
    "dynamic-ratio-node",
    "fastest-app-response",
    "fastest-node",
    "least-connections-member",
    "least-connections-node",
    "least-sessions",
    "observed-member",
    "observed-node",
    "predictive-member",
    "predictive-node",
    "ratio-least-connections-member",
    "ratio-least-connections-node",
    "ratio-member",
    "ratio-node",
    "round-robin",
    "ratio-session",
    "weighted-least-connections-member",
    "weighted-least-connections-node"
]


class InvalidServiceDefinitionError(ValueError):
    """Parser or validator encountered error in user's service definition.

    Raising this error will cause the service to not be defined on BIG-IP.
    For example, if while parsing F5_2_MODE the parser decides the mode is
    invalid, it can raise this error and the 2nd service port (F5_2_*) won't
    be defined.
    A helpful error is logged to the user at loglevel warning.
    """

# Setter function callbacks that correspond to specific labels: they will
# handle validating the value (v) and setting attributes on the object (x).
# These functions are used for exact matches (resp. prefix matches below).


def set_bindAddr(x, v):
    """App label callback.

    Set the Virtual Server address from label F5_n_BIND_ADDR
    """
    x.bindAddr = v


def set_port(x, v):
    """App label callback.

    Set the service port from label F5_n_PORT
    """
    x.servicePort = int(v)


def set_mode(x, v):
    """App label callback.

    Set the mode from label F5_n_MODE
    """
    x.mode = v


def set_balance(x, v):
    """App label callback.

    Set the load-balancing method from label F5_n_BALANCE
    """
    x.balance = v


def set_profile(x, v):
    """App label callback.

    Set the SSL Profile from label F5_n_SSL_PROFILE
    """
    x.profile = v


def set_iapp(x, v):
    """App label callback.

    Set the iApp template from label F5_n_IAPP_TEMPLATE
    """
    x.iapp = v


loggedIappPoolMemberTableNameDeprecated = False


def set_iapp_pool_member_table_name(x, v):
    """App label callback.

    Set the pool-member table name in the iApp from label
    F5_n_IAPP_POOL_MEMBER_TABLE_NAME
    """
    global loggedIappPoolMemberTableNameDeprecated
    if hasattr(x, 'iappPoolMemberTable'):
        raise InvalidServiceDefinitionError(
            ("You can only specify one of IAPP_POOL_MEMBER_TABLE_NAME or "
             "IAPP_POOL_MEMBER_TABLE, not both")
        )
    if not loggedIappPoolMemberTableNameDeprecated:
        logger.info(
            ("Using IAPP_POOL_MEMBER_TABLE_NAME is deprecated; see "
             "IAPP_POOL_MEMBER_TABLE")
        )
        loggedIappPoolMemberTableNameDeprecated = True
    x.iappPoolMemberTableName = v


def set_iapp_pool_member_table(x, v):
    """App label callback.

    Take the user's description for how to fill out the iApp's pool member
    table.  Every iApp may have a different layout for this table.  We need to
    provide the pool member IPs and ports, so we'll need to know what those
    columns are named.  If there are other columns, we need to let the user
    specify what we should fill in.
    """
    if hasattr(x, 'iappPoolMemberTableName'):
        raise InvalidServiceDefinitionError(
            ("You can only specify one of IAPP_POOL_MEMBER_TABLE_NAME or "
             "IAPP_POOL_MEMBER_TABLE, not both")
        )
    table = None
    try:
        table = json.loads(v)
    except ValueError:
        raise InvalidServiceDefinitionError(
            "IAPP_POOL_MEMBER_TABLE is not valid JSON")

    # FIXME(andrew): This should be done by jsonschema.
    for mandatoryProp in ['name', 'columns']:
        if mandatoryProp not in table:
            raise InvalidServiceDefinitionError(
                "IAPP_POOL_MEMBER_TABLE must have a '%s' field" %
                mandatoryProp)
    if not isinstance(table['name'], basestring):
        raise InvalidServiceDefinitionError(
            "IAPP_POOL_MEMBER_TABLE's 'name' property must be a string")
    if not isinstance(table['columns'], list):
        raise InvalidServiceDefinitionError(
            "IAPP_POOL_MEMBER_TABLE's 'columns' property must be an array")
    for i, col in enumerate(table['columns']):
        # Each column must be either
        # columnWithKind:  { "name": "foo", "kind": "IPAddress" } or
        # columnWithValue: { "name": "foo", "value": "42" }

        # Both column styles need "name"
        if 'name' not in col:
            raise InvalidServiceDefinitionError(
                "IAPP_POOL_MEMBER_TABLE column %d must have a 'name' field" %
                i)

        # Need either 'kind' or 'value'
        if 'kind' in col:
            if col['kind'] not in ['IPAddress', 'Port']:
                raise InvalidServiceDefinitionError(
                    "IAPP_POOL_MEMBER_TABLE column %d kind '%s' unknown" %
                    (i, col['kind']))
        elif 'value' in col:
            # We pass the value opaquely.
            pass
        else:
            raise InvalidServiceDefinitionError(
                ("IAPP_POOL_MEMBER_TABLE column %d must specify either 'kind'"
                 " or 'value'") % i)

    x.iappPoolMemberTable = table


# Dictionary of labels and setter functions, where the labels must match the
# key exactly (after template substitution)
exact_label_keys = {
    'F5_{0}_BIND_ADDR': set_bindAddr,
    'F5_{0}_PORT': set_port,
    'F5_{0}_MODE': set_mode,
    'F5_{0}_BALANCE': set_balance,
    'F5_{0}_SSL_PROFILE': set_profile,
    'F5_{0}_IAPP_TEMPLATE': set_iapp,
    'F5_{0}_IAPP_POOL_MEMBER_TABLE_NAME': set_iapp_pool_member_table_name,
    'F5_{0}_IAPP_POOL_MEMBER_TABLE': set_iapp_pool_member_table,
}

# Setter function callbacks that correspond to specific labels (k) and their
# values (v) to set an attribute on the object (x). These functions are
# associated with the 'label_keys' dictionary that follows.
# The 'k' arg is the actual label key used, because these functions will handle
# any label that prefix-matches a string (e.g. k may be
# F5_0_IAPP_VARIABLE_net__server_mode which prefix-matches
# F5_0_IAPP_VARIABLE_).


def set_iapp_variable(x, k, v):
    """App label callback.

    Set an element in the iApp Variables from label F5_n_IAPP_VARIABLE_*
    """
    x.iappVariables[k] = v


def set_iapp_table(x, k, v):
    """App label callback.

    Set an element in the iApp Tables from label F5_n_IAPP_TABLE_*
    """
    x.iappTables[k] = v


def set_iapp_option(x, k, v):
    """App label callback.

    Set an optional parameter in the iApp from label F5_n_IAPP_OPTION_*
    """
    x.iappOptions[k] = v


# Dictionary of labels and setter functions, where the labels must start with
# the key (after template substitution)
prefix_label_keys = {
    'F5_{0}_IAPP_TABLE_': set_iapp_table,
    'F5_{0}_IAPP_VARIABLE_': set_iapp_variable,
    'F5_{0}_IAPP_OPTION_': set_iapp_option,
}


logger = logging.getLogger('controller')


def healthcheck_timeout_calculate(data):
    """Calculate a BIG-IP Health Monitor timeout.

    Args:
        data: BIG-IP config dict
    """
    # Calculate timeout
    # See the f5 monitor docs for explanation of settings:
    # https://goo.gl/JJWUIg
    # Formula to match up the cloud settings with f5 settings:
    # (( maxConsecutiveFailures - 1) * intervalSeconds )
    # + timeoutSeconds + 1
    timeout = (
        ((data['maxConsecutiveFailures'] - 1) * data['intervalSeconds']) +
        data['timeoutSeconds'] + 1
    )
    return timeout


def get_protocol(protocol):
    """Return the protocol (tcp or udp).

    This converts from the marathon protocol (udp, tcp, or http) to the BIG-IP
    protocol (udp or tcp); http is handled at a different layer on top of tcp
    in BIG-IP config
    """
    if str(protocol).lower() == 'tcp':
        return 'tcp'
    if str(protocol).lower() == 'http':
        return 'tcp'
    if str(protocol).lower() == 'udp':
        return 'udp'
    return None


def is_label_data_valid(app):
    """Validate the Marathon app's label data.

    Args:
        app: The app to be validated
    """
    is_valid = True
    msg = 'Application label {0} for {1} contains an invalid value: {2}'

    # Validate mode
    if get_protocol(app.mode) is None:
        logger.error(msg.format('F5_MODE', app.appId, app.mode))
        is_valid = False

    # Validate port
    if app.servicePort < 1 or app.servicePort > 65535:
        logger.error(msg.format('F5_PORT', app.appId, app.servicePort))
        is_valid = False

    # Validate address
    if app.bindAddr is not None:
        if not validate_bigip_address(app.bindAddr):
            logger.error(msg.format('F5_BIND_ADDR', app.appId, app.bindAddr))
            is_valid = False

    # Validate load-balancing method
    if app.balance is not None and app.balance not in lb_methods:
        logger.error(msg.format('F5_BALANCE', app.appId, app.balance))
        is_valid = False

    return is_valid


def healthcheck_sendstring(data):
    """Return the 'send' string for a health monitor.

    Args:
        data: Health Monitor dict
    """
    if data['protocol'] == "http":
        send_string = 'GET / HTTP/1.0\\r\\n\\r\\n'
        if 'path' in data:
            send_string = 'GET %s HTTP/1.0\\r\\n\\r\\n' % data['path']
        return send_string
    else:
        return None


class MarathonBackend(object):
    """MarathonBackend class.

    Represents a backend server (host and port) that requires
    load balancing
    """

    def __init__(self, host, port, draining):
        """Initialize the backend object."""
        self.host = host
        self.port = port
        self.draining = draining

    def __hash__(self):
        """Host and port for a backend are unique."""
        return hash((self.host, self.port))

    def __repr__(self):
        """String representation of object."""
        return "MarathonBackend(%r, %r)" % (self.host, self.port)


class MarathonService(object):
    """MarathonService class.

    Represents a service in Marathon that requires
    load balancing
    """

    def __init__(self, appId, servicePort, healthCheck):
        """Initialize MarathonService with defaults."""
        self.appId = appId
        self.servicePort = servicePort
        self.backends = set()
        self.hostname = None
        self.sticky = False
        self.redirectHttpToHttps = False
        self.sslCert = None
        self.bindOptions = None
        self.bindAddr = None
        self.partition = None
        self.iapp = None
        self.iappTableName = None
        self.iappTables = {}
        self.iappVariables = {}
        self.iappOptions = {}
        self.mode = 'tcp'
        self.balance = 'round-robin'
        self.profile = None
        self.healthCheck = healthCheck
        self.labels = {}
        if healthCheck:
            for hc in healthCheck:
                if hc['protocol'] == 'HTTP':
                    self.mode = 'http'

    def add_backend(self, host, port, draining):
        """Add a backend to the service."""
        self.backends.add(MarathonBackend(host, port, draining))

    def __hash__(self):
        """Object is identified by servicePort."""
        return hash(self.servicePort)

    def __eq__(self, other):
        """Object is identified by servicePort."""
        return self.servicePort == other.servicePort

    def __repr__(self):
        """String representation of object."""
        return "MarathonService(%r, %r)" % (self.appId, self.servicePort)


class MarathonApp(object):
    """MarathonApp class.

    Represents an application in Marathon
    """

    def __init__(self, appId, app):
        """Initialize MarathonApp."""
        self.app = app
        self.partition = None
        self.appId = appId

        # port -> MarathonService
        self.services = dict()

    def __hash__(self):
        """Object is identified by appId."""
        return hash(self.appId)

    def __eq__(self, other):
        """Object is identified by appId."""
        return self.appId == other.appId


class Marathon(object):
    """Marathon class.

    Manages access to Marathon
        * Subscribe for events
        * Processes event
        * Retrieves Marathon application state
    """

    def __init__(self, hosts, health_check, auth, ca_cert=None):
        """Initialize the Marathon object."""
        self.__hosts = hosts
        self.__health_check = health_check
        self.__auth = auth
        self.__cycle_hosts = cycle(self.__hosts)
        self.__verify = False
        if ca_cert:
            self.__verify = ca_cert

    def api_req_raw(self, method, path, auth, **kwargs):
        """Send an API request to Marathon and return the response."""
        for host in self.__hosts:
            path_str = os.path.join(host, 'v2')

            for path_elem in path:
                path_str = path_str + "/" + path_elem
            response = requests.request(
                method,
                path_str,
                auth=auth,
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                **kwargs
            )

            logger.debug("%s %s", method, response.url)
            if response.status_code == 200:
                break

        response.raise_for_status()

        if 'message' in response.json():
            response.reason = "%s (%s)" % (
                response.reason,
                response.json()['message'])
        return response

    def api_req(self, method, path, **kwargs):
        """Send an API request to Marathon and return the JSON response."""
        return self.api_req_raw(method, path, self.__auth,
                                verify=self.__verify, **kwargs).json()

    # Lists all running apps.
    def list(self):
        """Get the app list from Marathon."""
        logger.info('fetching apps')
        return self.api_req('GET', ['apps'],
                            params={'embed': 'apps.tasks'})["apps"]

    def health_check(self):
        """Get health check."""
        return self.__health_check

    def get_event_stream(self, timeout):
        """Get the Server Side Event (SSE) event stream."""
        url = self.host+"/v2/events"
        logger.info(
            "SSE Active, trying fetch events from from {0}".format(url))
        return SSEClient(url, auth=self.__auth, verify=self.__verify,
                         timeout=timeout)

    @property
    def host(self):
        """Cycle the the configured set of Marathon hosts."""
        return next(self.__cycle_hosts)


def get_health_check(app, portIndex):
    """Get the healthcheck for the app."""
    checks = []
    for check in app.get('healthChecks', []):
        if check.get('port') or check.get('portIndex') == portIndex:
            checks.append(check)
    if len(checks) > 0:
        return checks
    return None


def get_apps(apps, health_check):
    """Create a list of app services from the Marathon state."""
    marathon_apps = []
    logger.debug("Marathon apps: %s", [app["id"] for app in apps])

    for app in apps:
        logger.info("Working on app %s", app['id'])
        appId = app['id']
        if appId[1:] == os.environ.get("FRAMEWORK_NAME"):
            continue

        marathon_app = MarathonApp(appId, app)

        if 'F5_PARTITION' in marathon_app.app['labels']:
            marathon_app.partition = \
                marathon_app.app['labels']['F5_PARTITION']
        marathon_apps.append(marathon_app)

        # 'ports' does not exist in Marathon v1.5.2 and when DC/OS Virtual
        # Networking is used.
        service_ports = app.get('ports', [])

        if len(service_ports) == 0:
            # If 'ports' doesn't exist, check 'portMappings'
            portMappings = app.get('container', {}).get('portMappings', [])
            for port in portMappings:
                if 'servicePort' in port:
                    service_ports.append(port['servicePort'])

        logger.debug("Application service ports = %s", (repr(service_ports)))
        logger.debug("Labels for app %s: %s", app['id'],
                     marathon_app.app['labels'])

        if len(service_ports) == 0:
            logger.warning("Warning, no service ports found for " + appId)

        for i, servicePort in enumerate(service_ports):
            try:
                service = MarathonService(
                    appId, servicePort, get_health_check(app, i))
                service.partition = marathon_app.partition

                # Parse the app labels that must match the template exactly
                for key_unformatted in exact_label_keys:
                    key = key_unformatted.format(i)
                    if key in marathon_app.app['labels']:
                        func = exact_label_keys[key_unformatted]
                        func(service, marathon_app.app['labels'][key])

                # Parse the app labels that must start with a template entry
                for key_unformatted in prefix_label_keys:
                    key = key_unformatted.format(i)

                    for label in marathon_app.app['labels']:
                        # Labels can be a combination of predicate +
                        # a variable name
                        if label.startswith(key):
                            func = prefix_label_keys[key_unformatted]
                            func(service,
                                 label[len(key):],
                                 marathon_app.app['labels'][label])

                marathon_app.services[servicePort] = service
            except InvalidServiceDefinitionError as e:
                logger.warning(
                    "App %s, service %d has an invalid config, skipping: %s",
                    appId, i, e)

        for task in app['tasks']:
            # Marathon 0.7.6 bug workaround
            if len(task['host']) == 0:
                logger.warning("Ignoring Marathon task without host " +
                               task['id'])
                continue

            if health_check and 'healthChecks' in app and \
               len(app['healthChecks']) > 0:
                if 'healthCheckResults' not in task:
                    continue
                alive = True
                for result in task['healthCheckResults']:
                    if not result['alive']:
                        alive = False
                if not alive:
                    continue

            task_ports = task['ports']
            draining = False
            if 'draining' in task:
                draining = task['draining']

            # if different versions of app have different number of ports,
            # try to match as many ports as possible
            number_of_defined_ports = min(len(task_ports), len(service_ports))

            for i in range(number_of_defined_ports):
                task_port = task_ports[i]
                service_port = service_ports[i]
                service = marathon_app.services.get(service_port, None)
                if service:
                    service.add_backend(task['host'],
                                        task_port,
                                        draining)

    # Convert into a list for easier consumption
    apps_list = []
    for marathon_app in marathon_apps:
        for service in list(marathon_app.services.values()):
            apps_list.append(service)

    logger.debug("Marathon app list: %s", repr(apps_list))

    return apps_list


def create_config_marathon(cccl, apps):
    """Create a BIG-IP configuration from the Marathon app list.

    Args:
        apps: Marathon app list
    """
    logger.debug(apps)
    for app in apps:
        logger.debug(app.__hash__())

    logger.info("Generating config for BIG-IP")
    services = {
        'virtualServers': [],
        'l7Policies': [],
        'pools': [],
        'monitors': [],
        'iapps': []
    }

    for app in apps:
        # Only handle application if it's partition is one that this script
        # is responsible for
        if cccl.get_partition() != app.partition:
            continue

        # Validate data from the app's labels
        if not app.iapp and not is_label_data_valid(app):
            continue

        # No address or iApp for this port (pool-only config)
        if not app.bindAddr and not app.iapp:
            logger.debug("Creating pool only for %s", app.appId)

        logger.info("Configuring app %s, partition %s", app.appId,
                    app.partition)
        backend = app.appId[1:].replace('/', '_') + '_' + \
            str(app.servicePort)

        frontend_name = "%s_%d" % ((app.appId).lstrip('/'), app.servicePort)
        # The Marathon appId contains the full path, replace all '/' in
        # the name with '_'
        frontend_name = frontend_name.replace('/', '_')

        if app.bindAddr:
            logger.debug("Frontend at %s:%d with backend %s", app.bindAddr,
                         app.servicePort, backend)

        # pool members
        members = []
        key_func = attrgetter('host', 'port')
        for backendServer in sorted(app.backends, key=key_func):
            logger.debug("Found backend server at %s:%d for app %s",
                         backendServer.host, backendServer.port, app.appId)

            # Resolve backendServer hostname to IP address
            ip = resolve_ip(backendServer.host)

            if ip is not None:
                member = {
                    'address': ip,
                    'port': backendServer.port,
                    'session': 'user-enabled'
                }
                members.append(member)
            else:
                logger.warning("Could not resolve ip for host %s, "
                               "ignoring this backend", backendServer.host)

        if app.iapp:
            # Translate from the internal properties we set on app to the
            # naming expected by the iapp.
            # Only set properties that are actually present.
            cfg = {
                'variables': {},
                'tables': {},
                'options': {}
            }
            for k, v in {'template': 'iapp',
                         'tableName': 'iappPoolMemberTableName',
                         'poolMemberTable': 'iappPoolMemberTable',
                         'tables': 'iappTables',
                         'variables': 'iappVariables',
                         'options': 'iappOptions'}.iteritems():
                if hasattr(app, v):
                    cfg[k] = getattr(app, v)

            try:
                # Decode the tables
                for key in app.iappTables:
                    cfg['tables'][key] = json.loads(app.iappTables[key])
            except ValueError:
                logger.error("IAPP TABLE data is not valid JSON")
                continue

            iapp = {
                'name': frontend_name,
                'template': cfg['template'],
                'variables': cfg['variables'],
                'tables': cfg['tables'],
                'options': cfg['options']
            }

            for member in members:
                # iApp will manage member state
                del member['session']

            # Add the poolMemberTable
            if 'poolMemberTable' in cfg:
                cfg['poolMemberTable']['members'] = members
                iapp['poolMemberTable'] = cfg['poolMemberTable']
            elif 'tableName' in cfg:
                # Before adding the flexible poolMemberTable mode, we only
                # supported three fixed columns in order, and connection_limit
                # was hardcoded to 0 ("no limit")
                poolMemberTable = {
                    "name": cfg['tableName'],
                    "columns": [
                        {"name": "addr", "kind": "IPAddress"},
                        {"name": "port", "kind": "Port"},
                        {"name": "connection_limit", "value": "0"}
                    ]
                }
                poolMemberTable['members'] = members
                iapp['poolMemberTable'] = poolMemberTable

            services['iapps'].append(iapp)
        else:
            monitors = []
            if app.healthCheck:
                for counter, hc in enumerate(app.healthCheck):
                    logger.debug("Healthcheck for app '%s': %s",
                                 app.appId, hc)

                    # normalize healthcheck protocol name to lowercase
                    if 'protocol' in hc:
                        hc['type'] = (hc['protocol']).lower()
                    hc.update({
                        'interval': hc['intervalSeconds'],
                        'timeout': healthcheck_timeout_calculate(hc)
                    })

                    # Append the index and protocol to the monitor name to
                    # keep them unique
                    hc['name'] = frontend_name + '_' + str(counter) + '_' + \
                        hc['type']

                    send = healthcheck_sendstring(hc)
                    if send is not None:
                        hc['send'] = send
                    monitors.append(hc)

                services['monitors'] += monitors

            # Parse the SSL profile into partition and name
            profiles = []
            if app.profile:
                profile = app.profile.split('/')
                if len(profile) != 2:
                    logger.error("Could not parse partition and name from"
                                 " SSL profile: %s", app.profile)
                else:
                    profiles.append({'partition': profile[0],
                                     'name': profile[1]})

            # Add appropriate profiles
            if str(app.mode).lower() == 'http':
                # BIG-IP will automatically add the tcp profile for http
                # because it is an inherited profile. Explictly add the tcp
                # profile so that we don't fail comparison matches later.
                profiles.append({'partition': 'Common', 'name': 'http'})
                profiles.append({'partition': 'Common', 'name': 'tcp'})
            elif get_protocol(app.mode) == 'tcp':
                profiles.append({'partition': 'Common', 'name': 'tcp'})

            if app.bindAddr:
                virtual = {
                    'name': frontend_name,
                    'enabled': True,
                    'ipProtocol': get_protocol(app.mode),
                    'destination':
                    "/%s/%s:%d" % (app.partition, app.bindAddr,
                                   app.servicePort),
                    'pool': "/%s/%s" % (app.partition, frontend_name),
                    'sourceAddressTranslation': {'type': 'automap'},
                    'profiles': profiles
                }
                services['virtualServers'].append(virtual)

            pool = {
                'name': frontend_name,
                'monitors': ["/%s/%s" %
                             (app.partition, m['name']) for m in monitors],
                'loadBalancingMode': app.balance,
                'members': members
            }
            services['pools'].append(pool)

    logger.debug("Service Config: %s", json.dumps(services))

    return services


class MarathonEventProcessor(object):
    """MarathonEventProcessor class.

    Processes Marathon events, fetches the Marathon state, and
    reconfigures the BIG-IP
    """

    def __init__(self, marathon, verify_interval, cccls):
        """Class init.

        Starts a thread that waits for Marathon events,
        then configures BIG-IP based on the Marathon state
        """
        self.__marathon = marathon
        # appId -> MarathonApp
        self.__apps = dict()
        self.__cccls = cccls
        self.__verify_interval = verify_interval

        self.__condition = threading.Condition()
        self.__thread = threading.Thread(target=self.do_reset)
        self.__pending_reset = False
        self.__thread.daemon = True
        self.__thread.start()
        self.__timer = None
        self._backoff_timer = 1
        self._max_backoff_time = 128

        # Fetch the base data
        self.reset_from_tasks()

    def do_reset(self):
        """Process the Marathon state and reconfigure the BIG-IP."""
        with self.__condition:
            while True:  # pylint: disable=too-many-nested-blocks
                self.__condition.acquire()
                if not self.__pending_reset:
                    self.__condition.wait()
                self.__pending_reset = False
                self.__condition.release()

                try:
                    start_time = time.time()
                    if self.__timer is not None:
                        # Stop timer
                        self.__timer.cancel()
                        self.__timer = None

                    self.__apps = \
                        sorted(get_apps(self.__marathon.list(),
                                        self.__marathon.health_check()),
                               key=attrgetter('appId', 'servicePort'))

                    incomplete = 0
                    for cccl in self.__cccls:
                        cfg = create_config_marathon(cccl, self.__apps)
                        try:
                            incomplete += cccl.apply_ltm_config(cfg)
                        except F5CcclError as e:
                            logger.error("CCCL Error: %s", e.msg)

                    if incomplete:
                        # Some retryable error occurred),
                        # do a reset so that we try again
                        self.retry_backoff(self.reset_from_tasks)
                    else:
                        # Reconfig was successful
                        self.start_checkpoint_timer()
                        self._backoff_timer = 1

                    perf_enable = os.environ.get('SCALE_PERF_ENABLE')
                    if perf_enable:  # pragma: no cover
                        test_data = {}
                        app_count = 0
                        backend_count = 0
                        for app in self.__apps:
                            if app.partition == 'test':
                                app_count += 1
                                backends = len(app.backends)
                                test_data[app.appId[1:]] = backends
                                backend_count += backends
                        test_data['Total_Services'] = app_count
                        test_data['Total_Backends'] = backend_count
                        test_data['Time'] = time.time()
                        json_data = json.dumps(test_data)
                        logger.info('SCALE_PERF: Test data: %s',
                                    json_data)

                    logger.debug("updating tasks finished, took %s seconds",
                                 time.time() - start_time)

                except ConnectionError:
                    logger.error("Could not connect to Marathon")
                    self.start_checkpoint_timer()
                except Exception:
                    logger.exception("Unexpected error!")
                    self.start_checkpoint_timer()

    def retry_backoff(self, func):
        """Tight loop backoff in case of error response."""
        e = threading.Event()
        logger.error("Error applying config, will try again in %s seconds",
                     self._backoff_timer)
        e.wait(self._backoff_timer)
        if self._backoff_timer < self._max_backoff_time:
            self._backoff_timer *= 2
        func()

    def start_checkpoint_timer(self):
        """Start timer to checkpoint the BIG-IP config."""
        # Start a timer that will force a reconfig in the absence of Marathon
        # events to ensure that the BIG-IP config remains sane
        self.__timer = threading.Timer(self.__verify_interval,
                                       self.reset_from_tasks)
        self.__timer.start()

    def reset_from_tasks(self):
        """Indicate that we need to process the Marathon state."""
        self.__condition.acquire()
        self.__pending_reset = True
        self.__condition.notify()
        self.__condition.release()

    def handle_event(self, event):
        """Check Marathon event.

        If a Marathon event in which we are interested occurs, wake up the
        thread and process the Marathon state
        """
        if event['eventType'] == 'status_update_event' or \
                event['eventType'] == 'event_stream_attached' or \
                event['eventType'] == 'health_status_changed_event' or \
                event['eventType'] == 'app_terminated_event' or \
                event['eventType'] == 'api_post_event':
            self.reset_from_tasks()


def get_arg_parser():
    """Create the parser for the command-line args."""
    parser = configargparse.getArgumentParser()
    parser.add_argument("--longhelp",
                        help="Print out configuration details",
                        action="store_true")
    parser.add_argument("--marathon", "-m",
                        nargs="+",
                        env_var='MARATHON_URL',
                        help="[required] Marathon endpoint, eg. -m " +
                        "http://marathon1:8080 http://marathon2:8080")
    parser.add_argument("--hostname",
                        env_var='F5_CC_BIGIP_HOSTNAME',
                        help="F5 BIG-IP hostname")
    parser.add_argument("--username",
                        env_var='F5_CC_BIGIP_USERNAME',
                        help="F5 BIG-IP username")
    parser.add_argument("--password",
                        env_var='F5_CC_BIGIP_PASSWORD',
                        help="F5 BIG-IP password")
    parser.add_argument("--partition",
                        env_var='F5_CC_PARTITIONS',
                        help="[required] Only generate config for apps which"
                        " match the specified partition."
                        " Can use this arg multiple times to"
                        " specify multiple partitions",
                        action="append",
                        default=list())
    parser.add_argument("--health-check", "-H",
                        env_var='F5_CC_USE_HEALTHCHECK',
                        help="If set, respect Marathon's health check "
                        "statuses before adding the app instance into "
                        "the backend pool.",
                        action="store_true")
    parser.add_argument("--marathon-ca-cert",
                        env_var='F5_CC_MARATHON_CA_CERT',
                        help="CA certificate for Marathon HTTPS connections")
    parser.add_argument('--sse-timeout', "-t", type=int,
                        env_var='F5_CC_SSE_TIMEOUT',
                        default=30, help='Marathon event stream timeout')
    parser.add_argument('--verify-interval', "-v", type=int,
                        env_var='F5_CC_VERIFY_INTERVAL',
                        default=30, help="Interval at which to verify "
                        "the BIG-IP configuration.")
    parser.add_argument("--version",
                        help="Print out version information and exit",
                        action="store_true")

    parser = set_logging_args(parser)
    parser = set_marathon_auth_args(parser)
    return parser


def process_sse_events(processor, events):
    """Process Server Side Events (SSE) from Marathon."""
    for event in events:
        try:
            # logger.info("Received event: {0}".format(event))
            # marathon might also send empty messages as keepalive...
            if event.data.strip() != '':
                # marathon sometimes sends more than one json per event
                # e.g. {}\r\n{}\r\n\r\n
                for real_event_data in re.split(r'\r\n', event.data):
                    data = json.loads(real_event_data)
                    logger.info(
                        "received event of type {0}".format(data['eventType']))
                    if data['eventType'] == 'event_stream_detached':
                        # Need to force reload and re-attach to stream
                        processor.reset_from_tasks()
                        return
                    processor.handle_event(data)
            else:
                logger.info("skipping empty message")
        except Exception:
            logger.error("Event data: %s", event.data)
            logger.exception("Unexpected error!")

            raise


def parse_args(version_data):
    """Entry point for parsing command-line args."""
    # Process arguments
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()

    # Print the long help text if flag is set
    if args.longhelp:
        print(__doc__)
        sys.exit()
    # otherwise make sure that a Marathon URL was specified
    else:
        if args.version:
            print('Version: ', version_data['version'],
                  '\nBuild: ', version_data['build'])
            sys.exit()
        if args.marathon is None:
            arg_parser.error('argument --marathon/-m is required')
        if len(args.partition) == 0:
            arg_parser.error('argument --partition is required: please' +
                             'specify at least one partition name')
        if not args.hostname:
            arg_parser.error('argument --hostname is required: please' +
                             'specify')
        if not args.username:
            arg_parser.error('argument --username is required: please' +
                             'specify')
        if not args.password:
            arg_parser.error('argument --password is required: please' +
                             'specify')
        if args.sse_timeout < 1:
            arg_parser.error('argument --sse-timeout must be > 0')
        if args.verify_interval < 1:
            arg_parser.error('argument --verification-interval must be > 0')

        if not urlparse(args.hostname).scheme:
            args.hostname = "https://" + args.hostname
        url = urlparse(args.hostname)

        if url.scheme and url.scheme != 'https':
            arg_parser.error(
                'argument --hostname requires \'https\' protocol')
        if url.path and url.path != '/':
            arg_parser.error(
                'argument --hostname: path must be empty or \'/\'')

        args.host = url.hostname
        args.port = url.port
        if not args.port:
            args.port = 443

    return args


if __name__ == '__main__':
    # Read version/build info
    version_data = {}
    try:
        with open('VERSION_BUILD.json', 'r') as version_file:
            version_data = json.load(version_file)
    except Exception as e:
        version_data['version'] = 'UNKNOWN_VERSION'
        version_data['build'] = 'UNKNOWN_BUILD'

    # parse args
    args = parse_args(version_data)

    # Setup logging
    setup_logging(logging.getLogger(), args.log_format, args.log_level)

    # Version/build info
    logger.info("Version: %s, Build: %s", version_data['version'],
                version_data['build'])

    # BIG-IP to manage
    bigip = mgmt_root(
        args.host,
        args.username,
        args.password,
        args.port,
        "tmos")

    # Set user-agent for ICR session
    user_agent = 'marathon-bigip-ctlr-' + version_data['version'] + '-' + \
        version_data['build']

    # Management for the BIG-IP partitions
    cccls = []
    for partition in args.partition:
        cccl = F5CloudServiceManager(
            bigip,
            partition,
            user_agent=user_agent,
            prefix="")
        cccls.append(cccl)

    # Set request retries
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(max_retries=3)
    s.mount('http://', a)

    if os.environ.get('SCALE_PERF_ENABLE'):
        logger.info('SCALE_PERF: Started controller at: %f', time.time())

    # Marathon API connector
    marathon = Marathon(args.marathon,
                        args.health_check,
                        get_marathon_auth_params(args),
                        args.marathon_ca_cert)

    processor = MarathonEventProcessor(marathon, args.verify_interval, cccls)
    while True:
        try:
            events = marathon.get_event_stream(args.sse_timeout)
            process_sse_events(processor, events)
        except Exception:
            logger.exception("Marathon event exception:")
            logger.error("Reconnecting to Marathon event stream...")
        time.sleep(1)
