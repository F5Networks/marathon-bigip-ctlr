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

from sseclient import SSEClient
from itertools import cycle
from urlparse import urlparse
from requests.exceptions import ConnectionError
from common import (set_logging_args, set_marathon_auth_args, setup_logging,
                    get_marathon_auth_params)
from _f5 import CloudBigIP

import json
import logging
import os
import os.path
import re
import requests
import sys
import time
import threading
import configargparse


# Setter function callbacks that correspond to specific labels (k) and their
# values (v) to set an attribute on the object (x). These functions are
# associated with the 'label_keys' dictionary that follows.
# The 'k' arg is not used for those labels that uniquely corrrespond to an
# object attribute (e.g. F5_0_PORT), while other labels are a combination of
# a label prefix and attribute name (e.g. F5_0_IAPP_VARIABLE_net__server_mode).

def set_bindAddr(x, k, v):
    """App label callback.

    Setthe Virtual Server address from label F5_n_BIND_ADDR
    """
    x.bindAddr = v


def set_port(x, k, v):
    """App label callback.

    Set the service port from label F5_n_PORT
    """
    x.servicePort = int(v)


def set_mode(x, k, v):
    """App label callback.

    Set the mode from label F5_n_MODE
    """
    x.mode = v


def set_balance(x, k, v):
    """App label callback.

    Set the load-balancing method from label F5_n_BALANCE
    """
    x.balance = v


def set_profile(x, k, v):
    """App label callback.

    Set the SSL Profile from label F5_n_SSL_PROFILE
    """
    x.profile = v


def set_iapp(x, k, v):
    """App label callback.

    Set the iApp template from label F5_n_IAPP_TEMPLATE
    """
    x.iapp = v


def set_iapp_pool_member_table_name(x, k, v):
    """App label callback.

    Set the pool-member table name in the iApp from label
    F5_n_IAPP_POOL_MEMBER_TABLE_NAME
    """
    x.iappTableName = v


def set_iapp_pool_member_table_column_names(x, k, v):
    """App label callback.

    Set the pool-member table column names in the iApp from label
    F5_n_IAPP_POOL_MEMBER_TABLE_COLUMN_NAMES
    """
    x.iappPoolMemberTableColumnNames = [z.strip() for z in v.split(",")]


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


def set_label(x, k, v):
    """App label callback.

    Generric method for capturing a label and its value
    """
    x.labels[k] = v


# Dictionary of labels and setter functions
label_keys = {
    'F5_{0}_BIND_ADDR': set_bindAddr,
    'F5_{0}_PORT': set_port,
    'F5_{0}_MODE': set_mode,
    'F5_{0}_BALANCE': set_balance,
    'F5_{0}_SSL_PROFILE': set_profile,
    'F5_{0}_IAPP_TEMPLATE': set_iapp,
    'F5_{0}_IAPP_POOL_MEMBER_TABLE_NAME': set_iapp_pool_member_table_name,
    'F5_{0}_IAPP_POOL_MEMBER_TABLE_COLUMN_NAMES':
    set_iapp_pool_member_table_column_names,
    'F5_{0}_IAPP_TABLE_': set_iapp_table,
    'F5_{0}_IAPP_VARIABLE_': set_iapp_variable,
    'F5_{0}_IAPP_OPTION_': set_iapp_option
}

logger = logging.getLogger('controller')


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
        self.iappPoolMemberTableColumnNames = \
            ['addr', 'port', 'connection_limit']
        self.iappVariables = {}
        self.iappOptions = {}
        self.mode = 'tcp'
        self.balance = 'round-robin'
        self.profile = None
        self.healthCheck = healthCheck
        self.labels = {}
        if healthCheck:
            if healthCheck['protocol'] == 'HTTP':
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

    def api_req_raw(self, method, path, auth, body=None, **kwargs):
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

    def create(self, app_json):
        """Create a Marathon app."""
        return self.api_req('POST', ['apps'], app_json)

    def get_app(self, appid):
        """Get the info for a Marathon app."""
        logger.info('fetching app %s', appid)
        return self.api_req('GET', ['apps', appid])["app"]

    # Lists all running apps.
    def list(self):
        """Get the app list from Marathon."""
        logger.info('fetching apps')
        return self.api_req('GET', ['apps'],
                            params={'embed': 'apps.tasks'})["apps"]

    def health_check(self):
        """Get health check."""
        return self.__health_check

    def tasks(self):
        """Get Marathon tasks."""
        logger.info('fetching tasks')
        return self.api_req('GET', ['tasks'])["tasks"]

    def add_subscriber(self, callbackUrl):
        """Add a subscriber for use with HTTP callbacks."""
        return self.api_req(
                'POST',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

    def remove_subscriber(self, callbackUrl):
        """Remove a callback used for a subscriber."""
        return self.api_req(
                'DELETE',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

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
    for check in app['healthChecks']:
        # FIXME: There may be more than one health check for a given port or
        # portIndex, but we currently only take the first.
        if check.get('port'):
            return check
        if check.get('portIndex') == portIndex:
            return check
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

        service_ports = app['ports']
        logger.debug("Application service ports = %s" % (repr(service_ports)))
        logger.debug("Labels for app %s: %s", app['id'],
                     marathon_app.app['labels'])

        for i in range(len(service_ports)):
            servicePort = service_ports[i]
            service = MarathonService(
                        appId, servicePort, get_health_check(app, i))
            service.partition = marathon_app.partition

            # Parse the app labels
            for key_unformatted in label_keys:
                key = key_unformatted.format(i)

                for label in marathon_app.app['labels']:
                    # Labels can be a combination of predicate +
                    # a variable name
                    if label.startswith(key):
                        func = label_keys[key_unformatted]
                        func(service,
                             label[len(key):],
                             marathon_app.app['labels'][label])

            marathon_app.services[servicePort] = service

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


class MarathonEventProcessor(object):
    """MarathonEventProcessor class.

    Processes Marathon events, fetches the Marathon state, and
    reconfigures the BIG-IP
    """

    def __init__(self, marathon, verify_interval, bigip):
        """Class init.

        Starts a thread that waits for Marathon events,
        then configures BIG-IP based on the Marathon state
        """
        self.__marathon = marathon
        # appId -> MarathonApp
        self.__apps = dict()
        self.__bigip = bigip
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
            while True:
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

                    self.__apps = get_apps(self.__marathon.list(),
                                           marathon.health_check())
                    if self.__bigip.regenerate_config_f5(self.__apps):
                        # Timeout (or some other retryable error occurred),
                        # do a reset so that we try again
                        self.retry_backoff(self.reset_from_tasks)
                    else:
                        # Reconfig was successful
                        self.start_checkpoint_timer()
                        self._backoff_timer = 1

                    logger.debug("updating tasks finished, took %s seconds",
                                 time.time() - start_time)

                except ConnectionError:
                    logger.error("Could not connect to Marathon")
                    self.start_checkpoint_timer()
                except:
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
                        action="store_true"
                        )
    parser.add_argument("--marathon", "-m",
                        nargs="+",
                        env_var='MARATHON_URL',
                        help="[required] Marathon endpoint, eg. -m " +
                             "http://marathon1:8080 http://marathon2:8080"
                        )
    parser.add_argument("--hostname",
                        env_var='F5_CC_BIGIP_HOSTNAME',
                        help="F5 BIG-IP hostname"
                        )
    parser.add_argument("--username",
                        env_var='F5_CC_BIGIP_USERNAME',
                        help="F5 BIG-IP username"
                        )
    parser.add_argument("--password",
                        env_var='F5_CC_BIGIP_PASSWORD',
                        help="F5 BIG-IP password"
                        )
    parser.add_argument("--partition",
                        env_var='F5_CC_PARTITIONS',
                        help="[required] Only generate config for apps which"
                        " match the specified partition. Use '*' to match all"
                        " partitions.  Can use this arg multiple times to"
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

    parser = set_logging_args(parser)
    parser = set_marathon_auth_args(parser)
    return parser


def process_sse_events(processor, events, bigip):
    """Process Server Side Events (SSE) from Marathon."""
    for event in events:
        try:
            # logger.info("Received event: {0}".format(event))
            # marathon might also send empty messages as keepalive...
            if (event.data.strip() != ''):
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
        except:
            logger.error("Event data: %s", event.data)
            logger.exception("Unexpected error!")

            raise


def parse_args():
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
    # parse args
    args = parse_args()

    bigip = CloudBigIP('marathon', args.host, args.port, args.username,
                       args.password, args.partition)

    # Set request retries
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(max_retries=3)
    s.mount('http://', a)

    # Setup logging
    setup_logging(logger, args.log_format, args.log_level)

    # Marathon API connector
    marathon = Marathon(args.marathon,
                        args.health_check,
                        get_marathon_auth_params(args),
                        args.marathon_ca_cert)

    processor = MarathonEventProcessor(marathon, args.verify_interval,
                                       bigip)
    while True:
        try:
            events = marathon.get_event_stream(args.sse_timeout)
            process_sse_events(processor, events, bigip)
        except:
            logger.exception("Marathon event exception:")
            logger.error("Reconnecting to Marathon event stream...")
        time.sleep(1)
