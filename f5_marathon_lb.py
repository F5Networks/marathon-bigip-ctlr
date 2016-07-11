#!/usr/bin/env python


"""Overview:
### Overview
The f5-marathon-lb is a service discovery and load balancing tool
for Marathon to configure an F5 BIG-IP. It reads the Marathon task information
and dynamically generates BIG-IP configuration details.

To gather the task information, marathon-lb needs to know where
to find Marathon. The service configuration details are stored in labels.

Every service port in Marathon can be configured independently.

### Configuration
Service configuration lives in Marathon via labels.
f5-marathon-lb just needs to know where to find Marathon.
To run in listening mode you must also specify the address + port at
which f5-marathon-lb can be reached by Marathon.
"""

from logging.handlers import SysLogHandler
from wsgiref.simple_server import make_server
from sseclient import SSEClient
from six.moves.urllib import parse
from itertools import cycle
from requests.exceptions import ConnectionError
from common import *
from _f5 import *

import argparse
import json
import logging
import os
import os.path
import stat
import re
import requests
import sys
import time
import dateutil.parser
import math
import threading


# Setter function callbacks that correspond to specific labels (k) and their
# values (v) to set an attribute on the object (x). These functions are
# associated with the 'label_keys' dictionary that follows.
# The 'k' arg is not used for those labels that uniquely corrrespond to an
# object attribute (e.g. F5_0_PORT), while other labels are a combination of
# a label prefix and attribute name (e.g. F5_0_IAPP_VARIABLE_net__server_mode).

def set_bindAddr(x, k, v):
    x.bindAddr = v


def set_port(x, k, v):
    x.servicePort = int(v)


def set_mode(x, k, v):
    x.mode = v


def set_balance(x, k, v):
    x.balance = v


def set_profile(x, k, v):
    x.profile = v


def set_iapp(x, k, v):
    x.iapp = v


def set_iapp_table(x, k, v):
    x.iappTableName = v


def set_iapp_variable(x, k, v):
    x.iappVariables[k] = v


def set_iapp_option(x, k, v):
    x.iappOptions[k] = v


def set_label(x, k, v):
    x.labels[k] = v

# Dictionary of labels and setter functions
label_keys = {
    'F5_{0}_BIND_ADDR': set_bindAddr,
    'F5_{0}_PORT': set_port,
    'F5_{0}_MODE': set_mode,
    'F5_{0}_BALANCE': set_balance,
    'F5_{0}_SSL_PROFILE': set_profile,
    'F5_{0}_IAPP_TEMPLATE': set_iapp,
    'F5_{0}_IAPP_POOL_MEMBER_TABLE_NAME': set_iapp_table,
    'F5_{0}_IAPP_VARIABLE_': set_iapp_variable,
    'F5_{0}_IAPP_OPTION_': set_iapp_option
}

logger = logging.getLogger('marathon_lb')


class MarathonBackend(object):

    def __init__(self, host, port, draining):
        self.host = host
        self.port = port
        self.draining = draining

    def __hash__(self):
        return hash((self.host, self.port))

    def __repr__(self):
        return "MarathonBackend(%r, %r)" % (self.host, self.port)


class MarathonService(object):

    def __init__(self, appId, servicePort, healthCheck):
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
        self.backends.add(MarathonBackend(host, port, draining))

    def __hash__(self):
        return hash(self.servicePort)

    def __eq__(self, other):
        return self.servicePort == other.servicePort

    def __repr__(self):
        return "MarathonService(%r, %r)" % (self.appId, self.servicePort)


class MarathonApp(object):

    def __init__(self, appId, app):
        self.app = app
        self.partition = None
        self.appId = appId

        # port -> MarathonService
        self.services = dict()

    def __hash__(self):
        return hash(self.appId)

    def __eq__(self, other):
        return self.appId == other.appId


class Marathon(object):

    def __init__(self, hosts, health_check, auth):
        # TODO(cmaloney): Support getting master list from zookeeper
        self.__hosts = hosts
        self.__health_check = health_check
        self.__auth = auth
        self.__cycle_hosts = cycle(self.__hosts)

    def api_req_raw(self, method, path, auth, body=None, **kwargs):
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
        if 'message' in response.json():
            response.reason = "%s (%s)" % (
                response.reason,
                response.json()['message'])
        response.raise_for_status()
        return response

    def api_req(self, method, path, **kwargs):
        return self.api_req_raw(method, path, self.__auth, **kwargs).json()

    def create(self, app_json):
        return self.api_req('POST', ['apps'], app_json)

    def get_app(self, appid):
        logger.info('fetching app %s', appid)
        return self.api_req('GET', ['apps', appid])["app"]

    # Lists all running apps.
    def list(self):
        logger.info('fetching apps')
        return self.api_req('GET', ['apps'],
                            params={'embed': 'apps.tasks'})["apps"]

    def health_check(self):
        return self.__health_check

    def tasks(self):
        logger.info('fetching tasks')
        return self.api_req('GET', ['tasks'])["tasks"]

    def add_subscriber(self, callbackUrl):
        return self.api_req(
                'POST',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

    def remove_subscriber(self, callbackUrl):
        return self.api_req(
                'DELETE',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

    def get_event_stream(self, timeout):
        url = self.host+"/v2/events"
        logger.info(
            "SSE Active, trying fetch events from from {0}".format(url))
        return SSEClient(url, auth=self.__auth, timeout=timeout)

    @property
    def host(self):
        return next(self.__cycle_hosts)



class Healthcheck(object):

    def __init__(self, data):
        self.path = None
        self.timeout = None
        self._name = data['name']
        self.protocol = data['protocol']
        self.maxConsecutiveFailures = data['maxConsecutiveFailures']
        self.intervalSeconds = data['intervalSeconds']
        self.timeoutSeconds = data['timeoutSeconds']

    @property
    def name(self):
        return "%s_%s" % (self._name, self.protocol)

    @property
    def get_timeout(self):
        timeout = (((self.maxConsecutiveFailures - 1) * self.intervalSeconds)
                   + self.timeoutSeconds + 1)
        return timeout

def get_health_check(app, portIndex):
    for check in app['healthChecks']:
        # FIXME: There may be more than one health check for a given port or
        # portIndex, but we currently only take the first.
        if check.get('port'):
            return check
        if check.get('portIndex') == portIndex:
            return check
    return None


def get_apps(apps, health_check):
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
                            label.strip(key),
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

    def __init__(self, marathon, bigip):
        self.__marathon = marathon
        # appId -> MarathonApp
        self.__apps = dict()
        self.__bigip = bigip

        self.__condition = threading.Condition()
        self.__thread = threading.Thread(target=self.do_reset)
        self.__pending_reset = False
        self.__thread.start()

        # Fetch the base data
        self.reset_from_tasks()

    def do_reset(self):
        with self.__condition:
            while True:
                self.__condition.acquire()
                if not self.__pending_reset:
                    self.__condition.wait()
                self.__pending_reset = False
                self.__condition.release()

                try:
                    start_time = time.time()

                    self.__apps = get_apps(self.__marathon.list(), marathon.health_check())
                    if self.__bigip.regenerate_config_f5(self.__apps):
                        # Timeout occurred, do a reset so that we try again
                        self.reset_from_tasks()

                    logger.debug("updating tasks finished, took %s seconds",
                                 time.time() - start_time)

                except ConnectionError:
                    logger.error("Could not connect to Marathon")
                except:
                    logger.exception("Unexpected error!")

    def reset_from_tasks(self):
        self.__condition.acquire()
        self.__pending_reset = True
        self.__condition.notify()
        self.__condition.release()

    def handle_event(self, event):
        if event['eventType'] == 'status_update_event' or \
                event['eventType'] == 'event_stream_attached' or \
                event['eventType'] == 'health_status_changed_event' or \
                event['eventType'] == 'app_terminated_event' or \
                event['eventType'] == 'api_post_event':
            self.reset_from_tasks()


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Marathon F5 BIG-IP Load Balancer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--longhelp",
                        help="Print out configuration details",
                        action="store_true"
                        )
    parser.add_argument("--marathon", "-m",
                        nargs="+",
                        help="[required] Marathon endpoint, eg. -m " +
                             "http://marathon1:8080 -m http://marathon2:8080"
                        )
    parser.add_argument("--listening", "-l",
                        help="The address this script listens on for " +
                        "marathon events"
                        )
    parser.add_argument("--callback-url", "-u",
                        help="The HTTP address that Marathon can call this " +
                             "script back at (http://lb1:8080)"
                        )
    parser.add_argument("--hostname",
                        help="F5 BIG-IP hostname"
                        )
    parser.add_argument("--username",
                        help="F5 BIG-IP username"
                        )
    parser.add_argument("--password",
                        help="F5 BIG-IP password"
                        )
    parser.add_argument("--partition",
                        help="[required] Only generate config for apps which"
                        " match the specified partition. Use '*' to match all"
                        " partitions.  Can use this arg multiple times to"
                        " specify multiple partitions",
                        action="append",
                        default=list())
    parser.add_argument("--sse", "-s",
                        help="Use Server Sent Events instead of HTTP "
                        "Callbacks",
                        action="store_true")
    parser.add_argument("--health-check", "-H",
                        help="If set, respect Marathon's health check "
                        "statuses before adding the app instance into "
                        "the backend pool.",
                        action="store_true")
    parser.add_argument('--sse-timeout', "-t", type=int,
                        default=30, help='Marathon event stream timeout')

    parser = set_logging_args(parser)
    parser = set_marathon_auth_args(parser)
    return parser


def run_server(marathon, listen_addr, callback_url, bigip):
    processor = MarathonEventProcessor(marathon, bigip)
    marathon.add_subscriber(callback_url)

    # TODO(cmaloney): Switch to a sane http server
    # TODO(cmaloney): Good exception catching, etc
    def wsgi_app(env, start_response):
        length = int(env['CONTENT_LENGTH'])
        data = env['wsgi.input'].read(length)
        processor.handle_event(json.loads(data.decode('utf-8')))
        # TODO(cmaloney): Make this have a simple useful webui for debugging /
        # monitoring
        start_response('200 OK', [('Content-Type', 'text/html')])

        return ["Got it\n".encode('utf-8')]

    listen_uri = parse.urlparse(listen_addr)
    httpd = make_server(listen_uri.hostname, listen_uri.port, wsgi_app)
    httpd.serve_forever()


def clear_callbacks(marathon, callback_url):
    logger.info("Cleanup, removing subscription to {0}".format(callback_url))
    marathon.remove_subscriber(callback_url)


def process_sse_events(processor, events, bigip):
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
        if args.sse and args.listening:
            arg_parser.error(
                'cannot use --listening and --sse at the same time')
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

    return args


if __name__ == '__main__':
    # parse args
    args = parse_args()

    bigip = MarathonBigIP(args.hostname, args.username, args.password,
                          args.partition)

    # Set request retries
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(max_retries=3)
    s.mount('http://', a)

    # Setup logging
    setup_logging(logger, args.syslog_socket, args.log_format)

    # Marathon API connector
    marathon = Marathon(args.marathon,
                        args.health_check,
                        get_marathon_auth_params(args))

    # If in listening mode, spawn a webserver waiting for events. Otherwise
    # just write the config.
    if args.listening:
        callback_url = args.callback_url or args.listening
        try:
            run_server(marathon, args.listening, callback_url, bigip)
        finally:
            clear_callbacks(marathon, callback_url)
    elif args.sse:
        processor = MarathonEventProcessor(marathon, bigip)
        while True:
            try:
                events = marathon.get_event_stream(args.sse_timeout)
                process_sse_events(processor, events, bigip)
            except:
                logger.error("Reconnecting to Marathon event stream...")
            time.sleep(1)
    else:
        # Generate base config
        bigip.regenerate_config_f5(get_apps(marathon.list(),
                                   marathon.health_check()))
