import logging
import json
import requests
import f5
from operator import attrgetter
from common import *
from f5.bigip import BigIP
import icontrol.session

logger = logging.getLogger('marathon_lb')

# common

def get_protocol(protocol):
    if str(protocol).lower() == 'tcp':
        return 'tcp'
    if str(protocol).lower() == 'http':
        return 'tcp'
    if str(protocol).lower() == 'udp':
        return 'udp'
    else:
        return 'tcp'

def has_partition(partitions, app_partition):
    # App has no partition specified
    if not app_partition:
        return False

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


class MarathonBigIP(BigIP):
    """Generates a configuration for a BigIP based upon the apps/tasks managed
    by the Marathon framework. 

    - Matches Marathon apps by BigIP partition
    - Creates a Virtual Server and pool for each app type that matches a BigIP
      partition
    - For each task, creates a pool member and adds the member to the pool 
    - If the app has a Marathon Health Monitor configured, create a
      corresponding health monitor for the BigIP pool member 
    """

    def __init__(self, hostname, username, password, partitions):
        super(MarathonBigIP, self).__init__(hostname, username, password)
        self._hostname = hostname
        self._username = username
        self._password = password
        self._partitions = partitions

    def regenerate_config_f5(self, apps):
        logger.info("In regenerate_config_f5()")
        logger.debug(apps)
        for app in apps:
            logger.debug(app.__hash__())

        try:
            self._apply_config_f5(self._create_config_f5(apps))

        # Handle F5/BIG-IP exceptions here
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error: {}".format(e))
            # Indicate that we need to retry
            return True
        except f5.sdk_exception.F5SDKError as e:
            logger.error("Resource Error: {}".format(e))
            # Indicate that we need to retry
            return True
        except icontrol.exceptions.BigIPInvalidURL as e:
            logger.error("Invalid URL: {}".format(e))
            # Indicate that we need to retry
            return True
        except icontrol.exceptions.iControlUnexpectedHTTPError as e:
            logger.error("HTTP Error: {}".format(e))
            # Indicate that we need to retry
            return True
        except Exception as e: raise

        return False

    def _create_config_f5(self, apps):
        logger.info("Generating config for BIG-IP")
        f5 = {}
        # partitions this script is responsible for:
        partitions = frozenset(self._partitions)

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
                logger.info("App %s has a partition for which we are not"
                            " responsible: %s", app.appId, app.partition)
                continue

            # No address for this port
            if not app.bindAddr:
                continue

            f5_service['partition'] = app.partition

            logger.info("Configuring app %s, partition %s",
                        app.appId, app.partition)
            backend = app.appId[1:].replace('/', '_') + '_' + str(app.servicePort)

            frontend_name = "%s_%s_%d" % ((app.appId).lstrip('/'), app.bindAddr,
                                          app.servicePort)
            f5_service['name'] = frontend_name
            logger.debug("Frontend at %s:%d with backend %s",
                         app.bindAddr, app.servicePort, backend)

            # Parse the SSL profile into partition and name
            profile = [None, None]
            if app.profile:
                profile = app.profile.split('/')
                if len(profile) != 2:
                    logger.error("Could not parse partition and name from SSL"
                                 " profile: %s", app.profile)
                    profile = [None, None]

            f5_service['virtual'].update({
                'id': (app.appId).lstrip('/'),
                'name': frontend_name,
                'destination': app.bindAddr,
                'port': app.servicePort,
                'protocol': app.mode,
                'balance': app.balance,
                'profile': {'partition': profile[0], 'name': profile[1]}
                })

            if app.healthCheck:
                logger.debug("Healthcheck for app '%s': %s",
                             app.appId, app.healthCheck)
                f5_service['health'] = app.healthCheck
                f5_service['health']['name'] = \
                    "%s_%s" % (frontend_name, app.healthCheck['protocol'])

                # normalize healtcheck protocol name to lowercase
                if 'protocol' in f5_service['health']:
                    f5_service['health']['protocol'] = \
                        (f5_service['health']['protocol']).lower()

            key_func = attrgetter('host', 'port')
            for backendServer in sorted(app.backends, key=key_func):
                logger.debug("Found backend server at %s:%d for app %s",
                             backendServer.host,
                             backendServer.port,
                             app.appId)
            
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

        logger.debug("F5 json config: %s", json.dumps(f5))

        return f5


    def _apply_config_f5(self, config):

        unique_partitions = self.get_partitions(self._partitions)

        for partition in unique_partitions:
            logger.debug("Doing config for partition '%s'" % partition)

            #marathon_virtual_list = [x for x in config.keys() if '*' not in x]
            marathon_virtual_list = \
                [x for x in config.keys() if config[x]['partition'] == partition]
            marathon_pool_list = \
                [x for x in config.keys() if config[x]['partition'] == partition]

            # this is kinda kludgey: health monitor has the same name as the
            # virtual, and there is no more than 1 monitor per virtual.
            marathon_healthcheck_list = []
            for v in marathon_virtual_list:
                if 'protocol' in config[v]['health']:
                    marathon_healthcheck_list.append(v)

            # a throw-away big-ip query.  this is to workaround a bug
            # https://bldr-git.int.lineratesystems.com/talley/f5-marathon-lb/issues/1
            _trash = self.get_pool_list(partition)

            f5_pool_list = self.get_pool_list(partition)
            f5_virtual_list = self.get_virtual_list(partition)

            # get_healthcheck_list() returns a dict with healthcheck names for keys
            # and a subkey of "type" with a value of "tcp", "http", etc.  We need to
            # know the type to correctly reference the resource.  i.e. monitor types
            # are different resources in the f5-sdk
            f5_healthcheck_dict = self.get_healthcheck_list(partition)
            logger.debug("f5_healthcheck_dict:   %s", f5_healthcheck_dict)
            # and then we need just the list to identify differences from the list 
            # returned from marathon
            f5_healthcheck_list = f5_healthcheck_dict.keys()

            logger.debug("f5_pool_list:          %s" % (', '.join(f5_pool_list)))
            logger.debug("f5_virtual_list:       %s" % (', '.join(f5_virtual_list)))
            logger.debug("f5_healthcheck_list:   %s" %
                         (', '.join(f5_healthcheck_list)))
            logger.debug("marathon_pool_list:    %s" %
                         (', '.join(marathon_pool_list)))
            logger.debug("marathon_virtual_list: %s" %
                         (', '.join(marathon_virtual_list)))

            # virtual delete
            virt_delete = list_diff(f5_virtual_list, marathon_virtual_list)
            logger.debug("Virtual Servers to delete: %s", (', '.join(virt_delete)))
            for virt in virt_delete:
                self.virtual_delete(partition, virt)

            # pool delete
            pool_delete_list = list_diff(f5_pool_list, marathon_pool_list)
            logger.debug("Pools to delete: %s", (', '.join(pool_delete_list)))
            for pool in pool_delete_list:
                self.pool_delete(partition, pool)
        
            # healthcheck delete
            health_delete = list_diff(f5_healthcheck_list,
                                      marathon_healthcheck_list)
            logger.debug("Healthchecks to delete: %s", (', '.join(health_delete)))
            for hc in health_delete:
                self.healthcheck_delete(partition, hc,
                                   f5_healthcheck_dict[hc]['type'])

            # healthcheck config needs to happen before pool config because the pool
            # is where we add the healthcheck
            # healthcheck add
            # use the name of the virt for the healthcheck
            healthcheck_add = list_diff(marathon_healthcheck_list,
                                        f5_healthcheck_list)
            logger.debug("Healthchecks to add: %s", (', '.join(healthcheck_add)))
            for hc in healthcheck_add:
                self.healthcheck_create(partition, hc, config[hc]['health'])

            # pool add
            pool_add = list_diff(marathon_pool_list, f5_pool_list)
            logger.debug("Pools to add: %s", (', '.join(pool_add)))
            for pool in pool_add:
                self.pool_create(partition, pool, config[pool])

            # virtual add
            virt_add = list_diff(marathon_virtual_list, f5_virtual_list)
            logger.debug("Virtual Servers to add: %s", (', '.join(virt_add)))
            for virt in virt_add:
                self.virtual_create(partition, virt, config[virt])

            # healthcheck intersection
            healthcheck_intersect = list_intersect(marathon_virtual_list,
                                                   f5_healthcheck_list)
            logger.debug("Healthchecks to update: %s",
                         (', '.join(healthcheck_intersect)))

            for hc in healthcheck_intersect:
                self.healthcheck_update(partition, hc, config[hc]['health'])

            # pool intersection
            pool_intersect = list_intersect(marathon_pool_list, f5_pool_list)
            logger.debug("Pools to update: %s", (', '.join(pool_intersect)))
            for pool in pool_intersect:
                self.pool_update(partition, pool, config[pool])
        
            # virt intersection
            virt_intersect = list_intersect(marathon_virtual_list, f5_virtual_list)
            logger.debug("Virtual Servers to update: %s",
                         (', '.join(virt_intersect)))

            for virt in virt_intersect:
                self.virtual_update(partition, virt, config[virt])

            # add/update/remove pool members
            # need to iterate over pool_add and pool_intersect
            # (note that remove a pool also removes members, so don't have to worry
            # about those)
            for pool in list(set(pool_add + pool_intersect)):
                logger.debug("Pool: %s", pool)

                f5_member_list = self.get_pool_member_list(partition, pool)
                marathon_member_list = (config[pool]['nodes']).keys()

                member_delete_list = list_diff(f5_member_list, marathon_member_list)
                logger.debug("Pool members to delete: %s",
                             (', '.join(member_delete_list)))
                for member in member_delete_list:
                    self.member_delete(partition, pool, member)

                member_add = list_diff(marathon_member_list, f5_member_list)
                logger.debug("Pool members to add:    %s", (', '.join(member_add)))
                for member in member_add:
                    self.member_create(partition, pool, member,
                                  config[pool]['nodes'][member])

                # since we're only specifying hostname and port for members,
                # 'member_update' will never actually get called.  changing either of
                # these properties will result in a new member being created and the
                # old one being deleted.  i'm leaving this here though in case we add
                # other properties to members
                member_update_list = list_intersect(marathon_member_list,
                                                    f5_member_list)
                logger.debug("Pool members to update: %s",
                             (', '.join(member_update_list)))

                for member in member_update_list:
                    self.member_update(partition, pool, member,
                                  config[pool]['nodes'][member])
        
            # Delete any unreferenced nodes
            self.cleanup_nodes(partition)

    def cleanup_nodes(self, partition):
        node_list = self.get_node_list(partition)
        pool_list = self.get_pool_list(partition)

        # Search pool members for nodes still in-use, if the node is still
        # being used, remove it from the node list
        for pool in pool_list:
            member_list = self.get_pool_member_list(partition, pool)
            for member in member_list:
                name, port = member.split(':')
                if name in node_list:
                    node_list.remove(name)

        # What's left in the node list is not referenced, delete
        for node in node_list:
            self.node_delete(node, partition)

    def node_delete(self, node_name, partition):
        node = self.ltm.nodes.node.load(
            name=node_name,
            partition=partition
            )
        node.delete()

    def get_pool(self, partition, pool):
        # return pool object
        p = self.ltm.pools.pool.load(
            name=pool,
            partition=partition
            )
        return p

    def get_pool_list(self, partition):
        pool_list = []
        pools = self.ltm.pools.get_collection()
        for pool in pools:
            logger.debug("Pool list: %s", pool.__dict__)
            if pool.partition == partition:
                pool_list.append(pool.name)
        return pool_list

    def pool_create(self, partition, pool, data):
        # TODO: do we even need 'data' here?
        logger.debug("Creating pool %s", pool)
        p = self.ltm.pools.pool

        p.create(
            name=pool,
            partition=partition
        )
    
        if 'health' in data:
            logger.debug("adding healthcheck '%s' to pool", pool)
            p.monitor = pool
            p.update()

    def pool_delete(self, partition, pool):
        logger.debug("deleting pool %s", pool)
        p = self.get_pool(partition, pool)
        p.delete()

    def pool_update(self, partition, pool, data):
        # getting 'data' here, but not used currently
        # in fact, this update function does nothing currently.
        # if we end up supporting more pool-specific options (not really sure what)
        # then we will need this.  data should be changed or massaged to be
        # a list of k,v pairs for the update call

        #loadBalancingMode options: 
        # var: F5_{n}_BALANCE
        #   round-robin, 
        #   least-connections-member,
        #   ratio-member
        #   observed-member
        #   ratio-node
        #   ...

        virtual = data['virtual']
        pool = self.get_pool(partition, pool)
        if 'health' in data and data['health'] != {}:
            logger.debug("Adding healthcheck %s to pool", (virtual['name']))
            pool.monitor = virtual['name']
        pool.update(
                state=None
                )

    def get_member(self, partition, pool, member):
        p = self.get_pool(partition, pool)
        m = p.members_s.members.load(
                name=member,
                partition=partition
                )
        return m

    def get_pool_member_list(self, partition, pool):
        member_list = []
        p = self.get_pool(partition, pool)
        members = p.members_s.get_collection()
        for member in members:
            member_list.append(member.name)
    
        return member_list

    def member_create(self, partition, pool, member, data):
        # getting 'data' here, but not used currently
        p = self.get_pool(partition, pool)
        member = p.members_s.members.create(
                name=member,
                partition=partition
                )

    def member_delete(self, partition, pool, member):
        member = self.get_member(partition, pool, member)
        member.delete()

    def member_update(self, partition, pool, member, data):
        # getting 'data' here, but not used currently
        # in fact, this update function does nothing currently.
        # if we end up supporting more member-specific options, like ratio
        # then we will need this.  data should be changed or massaged to be
        # a list of k,v pairs for the update call ("ratio": 2)
        member = self.get_member(partition, pool, member)
        #member.update(
        #        state=None
        #        )

    def get_node_list(self, partition):
        node_list = []
        nodes = self.ltm.nodes.get_collection()
        for node in nodes:
            if node.partition == partition:
                node_list.append(node.name)

        return node_list

    def get_virtual(self, partition, virtual):
        # return virtual object
        v = self.ltm.virtuals.virtual.load(
                name=virtual,
                partition=partition
                )
        return v

    def get_virtual_list(self, partition):
        virtual_list = []
        virtuals = self.ltm.virtuals.get_collection()
        for virtual in virtuals:
            if virtual.partition == partition:
                virtual_list.append(virtual.name)

        return virtual_list

    def virtual_create(self, partition, virtual, data):
        logger.debug("Creating Virtual Server %s", virtual)
        hc_data = data['health']
        data = data['virtual']
        v = self.ltm.virtuals.virtual
        destination = "/%s/%s:%d" % (
                partition, 
                data['destination'], 
                data['port']
                )
        pool = "/%s/%s" % (partition, virtual)

        a = v.create(
                name=virtual,
                partition=partition,
                ipProtocol=get_protocol(data['protocol']),
                port=data['port'],
                destination=destination,
                pool=pool,
                sourceAddressTranslation={'type': 'automap'}
                )

        # SSL Profile
        if (data['profile']['name']):
            v.profiles_s.profiles.create(
                name=data['profile']['name'],
                partition=data['profile']['partition']
                )

        # if this is a virt with a http hc, add the default /Common/http profile
        if 'protocol' in hc_data and (hc_data['protocol']).lower() == "http":
                v.profiles_s.profiles.create(
                        name='http',
                        partition='Common'
                        )

        logger.debug("virtual_create %s", a.raw);

    def virtual_delete(self, partition, virtual):
        logger.debug("Deleting Virtual Server %s", virtual)
        v = self.get_virtual(partition, virtual)
        v.delete()

    def virtual_update(self, partition, virtual, data):
        hc_data = data['health']
        data = data['virtual']
        destination = "/%s/%s:%d" % (
                partition, 
                data['destination'], 
                data['port']
                )
        pool = "/%s/%s" % (partition, virtual)
        v = self.get_virtual(partition, virtual)
        v.update(
                name=virtual,
                partition=partition,
                ipProtocol=get_protocol(data['protocol']),
                port=data['port'],
                destination=destination,
                pool=pool,
                sourceAddressTranslation={'type': 'automap'}
                )
    
        try:
            # if this is a virt with a http hc, add the default /Common/http profile
            if 'protocol' in hc_data and (hc_data['protocol']).lower() == "http":
                    v.profiles_s.profiles.load(
                                name='http',
                                partition='Common'
                                )
        except:
            if 'protocol' in hc_data and (hc_data['protocol']).lower() == "http":
                    v.profiles_s.profiles.create(
                                    name='http',
                                    partition='Common'
                                    )

        # SSL Profile
        if (data['profile']['name']):
            if not v.profiles_s.profiles.exists(
                name=data['profile']['name'],
                partition=data['profile']['partition']
                ):
                v.profiles_s.profiles.create(
                    name=data['profile']['name'],
                    partition=data['profile']['partition']
                    )

    def get_healthcheck(self, partition, hc, hc_type):
        # return hc object
        if hc_type.lower() == 'http':
            hc = self.ltm.monitor.https.http.load(
                    name=hc,
                    partition=partition
                    )
        elif hc_type.lower() == 'tcp':
            hc = self.ltm.monitor.tcps.tcp.load(
                    name=hc,
                    partition=partition
                    )

        return hc

    def get_healthcheck_list(self, partition):
        # will need to handle HTTP and TCP

        healthcheck_dict = {}

        # HTTP
        healthchecks = self.ltm.monitor.https.get_collection()
        for hc in healthchecks:
            if hc.partition == partition:
                healthcheck_dict.update(
                        {hc.name: {'type': 'http'}}
                        )
   
        # TCP
        healthchecks = self.ltm.monitor.tcps.get_collection()
        for hc in healthchecks:
            if hc.partition == partition:
                healthcheck_dict.update(
                        {hc.name: {'type': 'tcp'}}
                        )

        return healthcheck_dict

    def healthcheck_delete(self, partition, hc, hc_type):
        logger.debug("Deleting healthcheck %s", hc)
        hc = self.get_healthcheck(partition, hc, hc_type)
        hc.delete()

    def healthcheck_timeout_calculate(self, data):
        # calculate timeout
        # see the f5 monitor docs for explanation of settings: https://goo.gl/JJWUIg
        # formula to match up marathon settings with f5 settings
        # ( ( maxConsecutiveFailures - 1) * intervalSeconds ) + timeoutSeconds + 1
        timeout = (((data['maxConsecutiveFailures'] - 1) * data['intervalSeconds'])
                  + data['timeoutSeconds'] + 1)
        return timeout

    def healthcheck_update(self, partition, hc, data):
        # get healthcheck object
        hc = self.get_healthcheck(partition, hc, data['protocol'])
    
        timeout = self.healthcheck_timeout_calculate(data)
    
        # f5 docs: https://goo.gl/ALrf37
        send_string = 'GET /'
        if 'path' in data:
            # i expected to have to jump through some hoops to get the "\r\n" literal
            # into the f5 config, but this seems to work.
            # when configuring the f5 directly, you have to include the "\r\n"
            # literal at the end of the GET.  from my testing, this is getting
            # added automatically.  I'm not sure what layer is adding it (iControl
            # itself?).  anyway, this works for now, but i could see this being
            # fragile
            send_string = 'GET %s' % data['path']

        if (data['protocol']).lower() == "http":
            hc.update(
                    interval=data['intervalSeconds'],
                    timeout=timeout,
                    send=send_string,
                    )

        if (data['protocol']).lower() == "tcp":
            hc.update(
                    interval=data['intervalSeconds'],
                    timeout=timeout,
                    )

    def healthcheck_create(self, partition, hc, data):

        timeout = self.healthcheck_timeout_calculate(data)

        # NOTE: there is no concept of a grace period in F5, so this setting 
        # (gracePeriodSeconds) will be ignored

        # f5 docs: https://goo.gl/ALrf37
        send_string = 'GET /'
        if 'path' in data:
            # i expected to have to jump through some hoops to get the "\r\n" literal
            # into the f5 config, but this seems to work.
            # when configuring the f5 directly, you have to include the "\r\n"
            # literal at the end of the GET.  from my testing, this is getting
            # added automatically.  I'm not sure what layer is adding it (iControl
            # itself?).  anyway, this works for now, but i could see this being
            # fragile
            send_string = 'GET %s' % data['path']

        if (data['protocol']).lower() == "http":
            h = self.ltm.monitor.https
            http1 = h.http
            logger.debug(http1)
            http1.create(
                    name=hc,
                    partition=partition,
                    interval=data['intervalSeconds'],
                    timeout=timeout,
                    send=send_string,
                    )

        if (data['protocol']).lower() == "tcp":
            h = self.ltm.monitor.tcps
            tcp1 = h.tcp
            logger.debug(tcp1)
            tcp1.create(
                    name=hc,
                    partition=partition,
                    interval=data['intervalSeconds'],
                    timeout=timeout,
                    )

    def get_partitions(self, partitions):
        if ('*' in partitions):
            # Wildcard means all partitions, so we need to query BIG-IP for the
            # actual partition names
            partition_list = []
            for folder in self.sys.folders.get_collection():
                if not folder.name == "Common" and not folder.name == "/" \
                    and not folder.name.endswith(".app"):
                    partition_list.append(folder.name)
            return partition_list
        else:
            # No wildcard, so we just care about those already configured
            return partitions
