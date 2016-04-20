#!/usr/bin/env python

"""Overview:
  The marathon-lb is a replacement for the haproxy-marathon-bridge.
  It reads the Marathon task information and dynamically generates
  haproxy configuration details.

  To gather the task information, the marathon-lb needs to know where
  to find Marathon. The service configuration details are stored in labels.

  Every service port in Marathon can be configured independently.


Features:
  - Virtual host aliases for services
  - Soft restart of haproxy
  - SSL Termination
  - (Optional): real-time update from Marathon events


Configuration:
  Service configuration lives in Marathon via labels.
  The marathon-lb just needs to know where to find marathon.
  To run in listening mode you must also specify the address + port at
  which the marathon-lb can be reached by marathon.


Usage:
  $ marathon-lb.py --marathon http://marathon1:8080 \
        --haproxy-config /etc/haproxy/haproxy.cfg

  The user that executes marathon-lb must have the permission to reload
  haproxy.


Operational Notes:
  - When a node in listening mode fails, remove the callback url for that
    node in marathon.
  - If run in listening mode, DNS isn't re-resolved. Restart the process
    periodically to force re-resolution if desired.
  - To avoid configuring itself as a backend when run via Marathon,
    services with appID matching FRAMEWORK_NAME env var will be skipped.
"""

from logging.handlers import SysLogHandler
from operator import attrgetter
from wsgiref.simple_server import make_server
from sseclient import SSEClient
from six.moves.urllib import parse
from itertools import cycle
from common import *
from _f5 import *
from f5.bigip import BigIP

import argparse
import json
import logging
import os
import os.path
import stat
import re
import requests
import shlex
import subprocess
import sys
import socket
import time
import dateutil.parser
import math
import threading


def string_to_bool(s):
    return s.lower() in ["true", "t", "yes", "y"]


def set_hostname(x, k, v):
    x.hostname = v


def set_sticky(x, k, v):
    x.sticky = string_to_bool(v)


def set_redirect_http_to_https(x, k, v):
    x.redirectHttpToHttps = string_to_bool(v)


def set_sslCert(x, k, v):
    x.sslCert = v


def set_bindOptions(x, k, v):
    x.bindOptions = v


def set_bindAddr(x, k, v):
    x.bindAddr = v

def set_port(x, k, v):
    x.servicePort = int(v)


def set_mode(x, k, v):
    x.mode = v


def set_balance(x, k, v):
    x.balance = v


def set_label(x, k, v):
    x.labels[k] = v


label_keys = {
    'F5_{0}_VHOST': set_hostname,
    'F5_{0}_STICKY': set_sticky,
    'F5_{0}_REDIRECT_TO_HTTPS': set_redirect_http_to_https,
    'F5_{0}_SSL_CERT': set_sslCert,
    'F5_{0}_BIND_OPTIONS': set_bindOptions,
    'F5_{0}_BIND_ADDR': set_bindAddr,
    'F5_{0}_PORT': set_port,
    'F5_{0}_MODE': set_mode,
    'F5_{0}_BALANCE': set_balance,
    'F5_{0}_FRONTEND_HEAD': set_label,
    'F5_{0}_BACKEND_REDIRECT_HTTP_TO_HTTPS': set_label,
    'F5_{0}_BACKEND_HEAD': set_label,
    'F5_{0}_HTTP_FRONTEND_ACL': set_label,
    'F5_{0}_HTTPS_FRONTEND_ACL': set_label,
    'F5_{0}_HTTP_FRONTEND_APPID_ACL': set_label,
    'F5_{0}_BACKEND_HTTP_OPTIONS': set_label,
    'F5_{0}_BACKEND_TCP_HEALTHCHECK_OPTIONS': set_label,
    'F5_{0}_BACKEND_HTTP_HEALTHCHECK_OPTIONS': set_label,
    'F5_{0}_BACKEND_STICKY_OPTIONS': set_label,
    'F5_{0}_FRONTEND_BACKEND_GLUE': set_label,
    'F5_{0}_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS': set_label,
    'F5_{0}_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS': set_label,
    'F5_{0}_BACKEND_SERVER_OPTIONS': set_label,
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
        self.bindAddr = '*'
        self.partition = None
        self.mode = 'tcp'
        self.balance = 'round-robin'
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

    def __init__(self, marathon, appId, app):
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

    def get_event_stream(self):
        url = self.host+"/v2/events"
        logger.info(
            "SSE Active, trying fetch events from from {0}".format(url))
        return SSEClient(url, auth=self.__auth)

    @property
    def host(self):
        return next(self.__cycle_hosts)

def has_partition(partitions, app_partition):
    # All partitions / wildcard match
    if '*' in partitions:
        return True

    # empty partition only
    if len(partitions) == 0 and not app_partition:
        raise Exception("No partitions specified")

    # Contains matching partitions
    if app_partition in partitions:
        return True

    return False

ip_cache = dict()


def resolve_ip(host):
    cached_ip = ip_cache.get(host, None)
    if cached_ip:
        return cached_ip
    else:
        try:
            logger.debug("trying to resolve ip address for host %s", host)
            ip = socket.gethostbyname(host)
            ip_cache[host] = ip
            return ip
        except socket.gaierror:
            return None


def config(apps, partitions, bind_http_https, ssl_certs):
    logger.info("generating config")
    f5 = {}
    # partitions this script is responsible for:
    partitions = frozenset(partitions)
    _ssl_certs = ssl_certs or "/etc/ssl/mesosphere.com.pem"
    _ssl_certs = _ssl_certs.split(",")

    if bind_http_https:
        # just passing on this in case this is something we want to use... TBD
        pass

    frontends = str()
    backends = str()
    apps_with_http_appid_backend = []

    for app in sorted(apps, key=attrgetter('appId', 'servicePort')):
        f5_service = {
                'virtual': {},
                'nodes': {},
                'health': {},
                'partition': '',
                'name': ''
                }
        # Only handle application if it's partition is one that this script is
        # responsible for
        if not has_partition(partitions, app.partition):
            logger.info("App (%s) has a partition for which we are not responsible (%s)" % (app.appId, app.partition))
            continue

        f5_service['partition'] = app.partition

        logger.debug("Configuring app '%s', partition '%s'" % (app.appId, app.partition))
        backend = app.appId[1:].replace('/', '_') + '_' + str(app.servicePort)

        frontend_name = "%s" % (app.appId).lstrip('/')
        f5_service['name'] = frontend_name
        logger.debug("frontend at %s:%d with backend %s",
                     app.bindAddr, app.servicePort, backend)

        # if the app has a hostname set force mode to http
        # otherwise recent versions of haproxy refuse to start
        if app.hostname:
            app.mode = 'http'

        f5_service['virtual'].update({
            'id': (app.appId).lstrip('/'),
            'name': frontend_name,
            'destination': app.bindAddr,
            'port': app.servicePort,
            'protocol': app.mode,
            'balance': app.balance,
            })

        if app.healthCheck:
            print "______ HEALTHCHECK VIRT _________"
            print app.healthCheck
            f5_service['health'] = app.healthCheck
            f5_service['health']['name'] = "%s_%s" % (frontend_name, app.healthCheck['protocol'])

            # normalize healtcheck protocol name to lowercase
            if 'protocol' in f5_service['health']:
                f5_service['health']['protocol'] = (f5_service['health']['protocol']).lower()

            print "______ /HEALTHCHECK VIRT _________"

        if app.sticky:
            logger.debug("turning on sticky sessions")

        key_func = attrgetter('host', 'port')
        for backendServer in sorted(app.backends, key=key_func):
            logger.debug(
                "backend server at %s:%d",
                backendServer.host,
                backendServer.port)
            
            f5_node_name = backendServer.host + ':' + str(backendServer.port)
            f5_service['nodes'].update({f5_node_name: {
                'name': backendServer.host + ':' + str(backendServer.port),
                'host': backendServer.host,
                'port': backendServer.port
                }})

            ipv4 = resolve_ip(backendServer.host)

            if ipv4 is not None:
                # TODO:?  Handle hostnames instead of IPs
                pass
            else:
                logger.warning("Could not resolve ip for host %s, "
                               "ignoring this backend",
                               backendServer.host)

        f5.update({frontend_name: f5_service})

    print(json.dumps(f5))

    return f5

def f5_go(config, f5_config):
    logger.debug(config)
    
    # get f5 connection
    try:
        bigip = BigIP(
                f5_config['host'], 
                f5_config['username'],
                f5_config['password']
                )
    except:
        logger.error('exception')

    logger.debug(bigip)

    for partition in f5_config['partitions']:
        logger.debug("Doing config for partition '%s'" % partition)

        marathon_virtual_list = [x for x in config.keys() if '*' not in x]
        marathon_pool_list = [x for x in config.keys() if '*' not in x]

        # this is kinda kludgey, but just iterate over virt name and append protocol
        # to get "marathon_healthcheck_list"
        marathon_healthcheck_list = []
        for v in marathon_virtual_list:
            if 'protocol' in config[v]['health']:
                n = "%s_%s" % (v, config[v]['health']['protocol'])
                marathon_healthcheck_list.append(n)

        # a throw-away big-ip query.  this is to workaround a bug
        # https://bldr-git.int.lineratesystems.com/talley/f5-marathon-lb/issues/1
        _trash = get_pool_list(bigip, partition)

        f5_pool_list = get_pool_list(bigip, partition)
        f5_virtual_list = get_virtual_list(bigip, partition)

        # get_healthcheck_list() returns a dict with healthcheck names for keys and
        # a subkey of "type" with a value of "tcp", "http", etc.  We need to know 
        # the type to correctly reference the resource.  i.e. monitor types are different
        # resources in the f5-sdk
        f5_healthcheck_dict = get_healthcheck_list(bigip, partition)
        print f5_healthcheck_dict
        # and then we need just the list to identify differences from the list 
        # returned from marathon
        f5_healthcheck_list = f5_healthcheck_dict.keys()

        logger.debug("f5_pool_list = %s" % (','.join(f5_pool_list)))
        logger.debug("f5_virtual_list = %s" % (','.join(f5_virtual_list)))
        logger.debug("f5_healthcheck_list = %s" % (','.join(f5_healthcheck_list)))
        logger.debug("marathon_pool_list = %s" % (','.join(marathon_pool_list)))
        logger.debug("marathon_virtual_list = %s" % (','.join(marathon_virtual_list)))

        # virtual delete
        virt_delete = list_diff(f5_virtual_list, marathon_virtual_list)
        logger.debug("virts to delete = %s" % (','.join(virt_delete)))
        for virt in virt_delete:
            virtual_delete(bigip, partition, virt)

        # pool delete
        pool_delete_list = list_diff(f5_pool_list, marathon_pool_list)
        logger.debug("pools to delete = %s" % (','.join(pool_delete_list)))
        for pool in pool_delete_list:
            print "++++++++++++"
            print pool
            print "++++++++++++"
            pool_delete(bigip, partition, pool)
        
        # healthcheck delete
        health_delete = list_diff(f5_healthcheck_list, marathon_virtual_list)
        logger.debug("healthchecks to delete = %s" % (','.join(health_delete)))
        for hc in health_delete:
            healthcheck_delete(bigip, partition, hc, f5_healthcheck_dict[hc]['type'])

        # healthcheck config needs to happen before pool config because the pool
        # is where we add the healthcheck
        # healthcheck add
        # use the name of the virt for the healthcheck
        healthcheck_add = list_diff(marathon_virtual_list, f5_healthcheck_list)
        logger.debug("healthchecks to add = %s" % (','.join(healthcheck_add)))
        for hc in healthcheck_add:
            healthcheck_create(bigip, partition, hc, config[hc]['health'])

        # pool add
        pool_add = list_diff(marathon_pool_list, f5_pool_list)
        logger.debug("pools to add = %s" % (','.join(pool_add)))
        for pool in pool_add:
            pool_create(bigip, partition, pool, config[pool])

        
        # virtual add
        virt_add = list_diff(marathon_virtual_list, f5_virtual_list)
        logger.debug("virts to add = %s" % (','.join(virt_add)))
        for virt in virt_add:
            virtual_create(bigip, partition, virt, config[virt])

        

        # healthcheck intersection

        healthcheck_intersect = list_intersect(marathon_virtual_list, f5_healthcheck_list)
        logger.debug("healthchecks to update = %s" % (','.join(healthcheck_intersect)))
        for hc in healthcheck_intersect:
            healthcheck_update(bigip, partition, hc, config[hc]['health'])

        # pool intersection
        pool_intersect = list_intersect(marathon_pool_list, f5_pool_list)
        logger.debug("pools to update = %s" % (','.join(pool_intersect)))
        for pool in pool_intersect:
            pool_update(bigip, partition, pool, config[pool])
        
        # virt intersection
        virt_intersect = list_intersect(marathon_virtual_list, f5_virtual_list)
        logger.debug("virts to update = %s" % (','.join(virt_intersect)))
        for virt in virt_intersect:
            virtual_update(bigip, partition, virt, config[virt])


        # add/update/remove pool members
        # need to iterate over pool_add and pool_intersect
        # (note that remove a pool also removes members, so don't have to worry
        # about those)
        for pool in list(set(pool_add + pool_intersect)):
            #print pool

            f5_member_list = get_pool_member_list(bigip, partition, pool)
            marathon_member_list = (config[pool]['nodes']).keys()

            member_delete_list = list_diff(f5_member_list, marathon_member_list)
            logger.debug("members to delete = %s" % (','.join(member_delete_list)))
            for member in member_delete_list:
                member_delete(bigip, partition, pool, member)

            member_add = list_diff(marathon_member_list, f5_member_list)
            logger.debug("members to add = %s" % (','.join(member_add)))
            for member in member_add:
                member_create(bigip, partition, pool, member, config[pool]['nodes'][member])

            # since we're only specifying hostname and port for members, 'member_update' will never
            # actually get called.  changing either of these properties will result in a new
            # member being created and the old one being deleted.
            # i'm leaving this here though in case we add other properties to members
            member_update_list = list_intersect(marathon_member_list, f5_member_list)
            logger.debug("members to update = %s" % (','.join(member_update_list)))
            for member in member_update_list:
                member_update(bigip, partition, pool, member, config[pool]['nodes'][member])
        




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
        timeout = ((self.maxConsecutiveFailures - 1) * self.intervalSeconds) + self.timeoutSeconds + 1
        return timeout


def get_protocol(protocol):
    if str(protocol).lower() == 'tcp':
        return 'tcp'
    if str(protocol).lower() == 'http':
        return 'tcp'
    if str(protocol).lower() == 'udp':
        return 'udp'
    else:
        return 'tcp'


def get_health_check(app, portIndex):
    for check in app['healthChecks']:
        if check.get('port'):
            return check
        if check.get('portIndex') == portIndex:
            return check
    return None


def get_apps(marathon):
    apps = marathon.list()
    logger.debug("got apps %s", [app["id"] for app in apps])

    marathon_apps = []
    # This process requires 2 passes: the first is to gather apps belonging
    # to a deployment group.
    processed_apps = []
    deployment_groups = {}
    for app in apps:
        deployment_group = None
        if 'HAPROXY_DEPLOYMENT_GROUP' in app['labels']:
            deployment_group = app['labels']['HAPROXY_DEPLOYMENT_GROUP']
            # mutate the app id to match deployment group
            if deployment_group[0] != '/':
                deployment_group = '/' + deployment_group
            app['id'] = deployment_group
        else:
            processed_apps.append(app)
            continue
        if deployment_group in deployment_groups:
            # merge the groups, with the oldest taking precedence
            prev = deployment_groups[deployment_group]
            cur = app

            # TODO(brenden): do something more intelligent when the label is
            # missing.
            if 'HAPROXY_DEPLOYMENT_STARTED_AT' in prev['labels']:
                prev_date = dateutil.parser.parse(
                    prev['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'])
            else:
                prev_date = ''
            if 'HAPROXY_DEPLOYMENT_STARTED_AT' in cur['labels']:
                cur_date = dateutil.parser.parse(
                    cur['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'])
            else:
                cur_date = ''

            old = new = None
            if prev_date < cur_date:
                old = prev
                new = cur
            else:
                new = prev
                old = cur

            target_instances = \
                int(new['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'])

            # mark N tasks from old app as draining, where N is the
            # number of instances in the new app
            old_tasks = sorted(old['tasks'],
                               key=lambda task: task['host'] +
                               ":" + str(task['ports']))

            healthy_new_instances = 0
            if len(app['healthChecks']) > 0:
                for task in new['tasks']:
                    if 'healthCheckResults' not in task:
                        continue
                    alive = True
                    for result in task['healthCheckResults']:
                        if not result['alive']:
                            alive = False
                    if alive:
                        healthy_new_instances += 1
            else:
                healthy_new_instances = new['instances']

            maximum_drainable = \
                max(0, (healthy_new_instances + old['instances']) -
                    target_instances)

            for i in range(0, min(len(old_tasks),
                                  healthy_new_instances,
                                  maximum_drainable)):
                old_tasks[i]['draining'] = True

            # merge tasks from new app into old app
            merged = old
            old_tasks.extend(new['tasks'])
            merged['tasks'] = old_tasks

            deployment_groups[deployment_group] = merged
        else:
            deployment_groups[deployment_group] = app

    processed_apps.extend(deployment_groups.values())

    for app in processed_apps:
        logger.debug("In processed_apps; working on appid '%s'" % app['id'])
        appId = app['id']
        if appId[1:] == os.environ.get("FRAMEWORK_NAME"):
            continue

        marathon_app = MarathonApp(marathon, appId, app)

        if 'F5_PARTITION' in marathon_app.app['labels']:
            marathon_app.partition = \
                marathon_app.app['labels']['F5_PARTITION']
        marathon_apps.append(marathon_app)

        service_ports = app['ports']
        logger.debug("Application service ports = %s" % (repr(service_ports)))
        for i in range(len(service_ports)):
            servicePort = service_ports[i]
            service = MarathonService(
                        appId, servicePort, get_health_check(app, i))

            for key_unformatted in label_keys:
                key = key_unformatted.format(i)
                logger.debug("App key = %s" % (key))
                if key in marathon_app.app['labels']:
                    print(marathon_app.app['labels'])
                    func = label_keys[key_unformatted]
                    func(service,
                         key_unformatted,
                         marathon_app.app['labels'][key])

            marathon_app.services[servicePort] = service

        for task in app['tasks']:
            # Marathon 0.7.6 bug workaround
            if len(task['host']) == 0:
                logger.warning("Ignoring Marathon task without host " +
                               task['id'])
                continue

            if marathon.health_check() and 'healthChecks' in app and \
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
                    service.partition = marathon_app.partition
                    service.add_backend(task['host'],
                                        task_port,
                                        draining)

    # Convert into a list for easier consumption
    apps_list = []
    for marathon_app in marathon_apps:
        for service in list(marathon_app.services.values()):
            if service.backends:
                apps_list.append(service)

    logger.debug("Final Marathon app list = %s" % repr(apps_list))

    return apps_list



def regenerate_config_f5(apps, config_file, partitions, bind_http_https,
                      ssl_certs):
    logger.info("in regenerate_config_f5()")
    print(apps)
    for app in apps:
        print(app.__hash__())
    f5_go(config(apps, partitions, bind_http_https,
                                ssl_certs), config_file)

class MarathonEventProcessor(object):

    def __init__(self, marathon, config_file, partitions,
                 bind_http_https, ssl_certs):
        self.__marathon = marathon
        # appId -> MarathonApp
        self.__apps = dict()
        self.__config_file = config_file
        self.__partitions = partitions
        self.__bind_http_https = bind_http_https
        self.__ssl_certs = ssl_certs

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

                    self.__apps = get_apps(self.__marathon)
                    regenerate_config_f5(self.__apps,
                                      self.__config_file,
                                      self.__partitions,
                                      self.__bind_http_https,
                                      self.__ssl_certs)

                    logger.debug("updating tasks finished, took %s seconds",
                                 time.time() - start_time)
                except requests.exceptions.ConnectionError as e:
                    logger.error("Connection error({0}): {1}".format(
                        e.errno, e.strerror))
                except:
                    print("Unexpected error:", sys.exc_info()[0])

    def reset_from_tasks(self):
        self.__condition.acquire()
        self.__pending_reset = True
        self.__condition.notify()
        self.__condition.release()

    def handle_event(self, event):
        if event['eventType'] == 'status_update_event' or \
                event['eventType'] == 'health_status_changed_event' or \
                event['eventType'] == 'api_post_event':
            self.reset_from_tasks()


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Marathon HAProxy Load Balancer",
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
                        " list the specified partition. Use '*' to match all"
                        " partitions.  Can use a comma-separated list to specify"
                        " multiple partitions",
                        action="append",
                        default=list())
    parser.add_argument("--command", "-c",
                        help="If set, run this command to reload haproxy.",
                        default=None)
    parser.add_argument("--sse", "-s",
                        help="Use Server Sent Events instead of HTTP "
                        "Callbacks",
                        action="store_true")
    parser.add_argument("--health-check", "-H",
                        help="If set, respect Marathon's health check "
                        "statuses before adding the app instance into "
                        "the backend pool.",
                        action="store_true")
    parser.add_argument("--dont-bind-http-https",
                        help="Don't bind to HTTP and HTTPS frontends.",
                        action="store_true")
    parser.add_argument("--ssl-certs",
                        help="List of SSL certificates separated by comma"
                             "for frontend marathon_https_in"
                             "Ex: /etc/ssl/site1.co.pem,/etc/ssl/site2.co.pem",
                        default="/etc/ssl/mesosphere.com.pem")
    parser = set_logging_args(parser)
    parser = set_marathon_auth_args(parser)
    return parser


def run_server(marathon, listen_addr, callback_url, config_file, partitions,
               bind_http_https, ssl_certs):
    processor = MarathonEventProcessor(marathon,
                                       config_file,
                                       partitions,
                                       bind_http_https,
                                       ssl_certs)
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


def process_sse_events(marathon, config_file, partitions,
                       bind_http_https, ssl_certs):
    processor = MarathonEventProcessor(marathon,
                                       config_file,
                                       partitions,
                                       bind_http_https,
                                       ssl_certs)
    events = marathon.get_event_stream()
    for event in events:
        try:
            # logger.info("received event: {0}".format(event))
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
            print(event.data)
            print("Unexpected error:", sys.exc_info()[0])
            raise


if __name__ == '__main__':
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

    f5_config = {
            "host": args.hostname,
            "username": args.username,
            "password": args.password,
            "partitions": args.partition
            }

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
            run_server(marathon, args.listening, callback_url,
                       f5_config, args.partition,
                       not args.dont_bind_http_https, args.ssl_certs)
        finally:
            clear_callbacks(marathon, callback_url)
    elif args.sse:
        while True:
            try:
                process_sse_events(marathon,
                                   f5_config,
                                   args.partition,
                                   not args.dont_bind_http_https,
                                   args.ssl_certs)
            except:
                logger.exception("Caught exception")
                logger.error("Reconnecting...")
            time.sleep(1)
    else:
        # Generate base config
        regenerate_config_f5(get_apps(marathon), f5_config, args.partition,
                          not args.dont_bind_http_https,
                          args.ssl_certs)
