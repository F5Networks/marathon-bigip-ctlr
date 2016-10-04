"""BIG-IP Configuration Manager for the Cloud.

The CloudBigIP class (derived from f5.bigip) manages the state of a BIG-IP
based upon changes in the state of apps and tasks in Marathon; or services,
nodes, and pods in Kubernetes.

CloudBigIP manages the following BIG-IP resources:

    * Virtual Servers
    * Virtual Addresses
    * Pools
    * Pool Members
    * Nodes
    * Health Monitors
    * Application Services
"""

import logging
import json
import requests
import f5
from operator import attrgetter
from common import resolve_ip, list_diff, list_intersect
from f5.bigip import BigIP
import icontrol.session
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger('marathon_lb')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# common


def get_protocol(protocol):
    """Return the protocol (tcp or udp)."""
    if str(protocol).lower() == 'tcp':
        return 'tcp'
    if str(protocol).lower() == 'http':
        return 'tcp'
    if str(protocol).lower() == 'udp':
        return 'udp'
    else:
        return 'tcp'


def has_partition(partitions, app_partition):
    """Check if the app_partition is one we're responsible for."""
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


class CloudBigIP(BigIP):
    """CloudBigIP class.

    Generates a configuration for a BigIP based upon the apps/tasks managed
    by Marathon or services/pods/nodes in Kubernetes.

    - Matches apps/sevices by BigIP partition
    - Creates a Virtual Server and pool for each service type that matches a
      BigIP partition
    - For each backend (task, node, or pod), it creates a pool member and adds
      the member to the pool
    - If the app has a Marathon Health Monitor configured, create a
      corresponding health monitor for the BigIP pool member

    Args:
        cloud: cloud environment (marathon or kubernetes)
        hostname: IP address of BIG-IP
        username: BIG-IP username
        password: BIG-IP password
        partitions: List of BIG-IP partitions to manage
    """

    def __init__(self, cloud, hostname, username, password, partitions):
        """Initialize the CloudBigIP object."""
        super(CloudBigIP, self).__init__(hostname, username, password)
        self._cloud = cloud
        self._hostname = hostname
        self._username = username
        self._password = password
        self._partitions = partitions

    def regenerate_config_f5(self, cloud_state):
        """Configure the BIG-IP based on the cloud state.

        Args:
            cloud_state: Marathon or Kubernetes state
        """
        try:
            if self._cloud == 'marathon':
                cfg = self._create_config_marathon(cloud_state)
            else:
                cfg = self._create_config_kubernetes(cloud_state)
            self._apply_config(cfg)

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
        except Exception as e:
            raise

        return False

    def _create_config_kubernetes(self, svcs):
        """Create a BIG-IP configuration from the Kubernetes svc list.

        Args:
            svcs: Kubernetes svc list
        """
        logger.info("Generating config for BIG-IP from Kubernetes state")
        f5 = {}

        # partitions this script is responsible for:
        partitions = frozenset(self._partitions)

        for svc in svcs:
            # FIXME(yacobucci) we need better validation here, a schema exists
            # it just needs to be validated against
            f5_service = {}

            backend = svc['virtualServer']['backend']
            frontend = svc['virtualServer']['frontend']

            # Only handle application if it's partition is one that this script
            # is responsible for
            if not has_partition(partitions, frontend['partition']):
                continue

            # No address for this port
            if (('virtualAddress' not in frontend or
                 'bindAddr' not in frontend['virtualAddress']) and
                    'iapp' not in frontend):
                continue

            virt_addr = ('iapp' if 'iapp' in frontend else
                         frontend['virtualAddress']['bindAddr'])
            port = (backend['servicePort'] if 'virtualAddress' not in frontend
                    else frontend['virtualAddress']['port'])
            frontend_name = "{0}_{1}_{2}".format(
                    backend['serviceName'].strip('/'),
                    virt_addr, port)

            f5_service['name'] = frontend_name

            f5_service['partition'] = frontend['partition']

            if 'iapp' in frontend:
                f5_service['iapp'] = {'template': frontend['iapp'],
                                      'tableName': frontend['iappTableName'],
                                      'variables': frontend['iappVariables'],
                                      'options': frontend['iappOptions']}
            else:
                f5_service['virtual'] = {}
                f5_service['nodes'] = {}
                f5_service['health'] = {}

                # Parse the SSL profile into partition and name
                profile = [None, None]
                if 'sslProfile' in frontend:
                    profile = (frontend['sslProfile']['f5ProfileName'].
                               split('/'))
                    if len(profile) != 2:
                        logger.error("Could not parse partition and name from "
                                     "SSL profile: %s",
                                     frontend['sslProfile']['f5ProfileName'])
                        profile = [None, None]

                f5_service['virtual'].update({
                    'id': backend['serviceName'],
                    'name': frontend_name,
                    'destination': frontend['virtualAddress']['bindAddr'],
                    'port': frontend['virtualAddress']['port'],
                    'protocol': frontend['mode'],
                    'balance': frontend['balance'],
                    'profile': {'partition': profile[0], 'name': profile[1]}
                    })

                nodePort = backend['nodePort']
                for node in backend['nodes']:
                    f5_node_name = node + ':' + str(nodePort)
                    f5_service['nodes'].update({f5_node_name: {
                        'name': f5_node_name,
                        'host': node,
                        'port': nodePort
                    }})

            f5.update({frontend_name: f5_service})

        return f5

    def _create_config_marathon(self, apps):
        """Create a BIG-IP configuration from the Marathon app list.

        Args:
            apps: Marathon app list
        """
        logger.debug(apps)
        for app in apps:
            logger.debug(app.__hash__())

        logger.info("Generating config for BIG-IP")
        f5 = {}
        # partitions this script is responsible for:
        partitions = frozenset(self._partitions)

        for app in sorted(apps, key=attrgetter('appId', 'servicePort')):
            f5_service = {
                'virtual': {},
                'nodes': {},
                'health': {},
                'partition': '',
                'name': ''
                }
            # Only handle application if it's partition is one that this script
            # is responsible for
            if not has_partition(partitions, app.partition):
                continue

            # No address or iApp for this port
            if not app.bindAddr and not app.iapp:
                continue

            f5_service['partition'] = app.partition

            if app.iapp:
                f5_service['iapp'] = {'template': app.iapp,
                                      'tableName': app.iappTableName,
                                      'variables': app.iappVariables,
                                      'options': app.iappOptions}

            logger.info("Configuring app %s, partition %s",
                        app.appId, app.partition)
            backend = app.appId[1:].replace('/', '_') + '_' + \
                str(app.servicePort)

            frontend = 'iapp' if app.iapp else app.bindAddr
            frontend_name = "%s_%s_%d" % ((app.appId).lstrip('/'), frontend,
                                          app.servicePort)
            f5_service['name'] = frontend_name
            if app.bindAddr:
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

                f5_node_name = backendServer.host + ':' + \
                    str(backendServer.port)
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

    def _apply_config(self, config):
        """Apply the configuration to the BIG-IP.

        Args:
            config: BIG-IP config dict
        """
        unique_partitions = self.get_partitions(self._partitions)

        for partition in unique_partitions:
            logger.debug("Doing config for partition '%s'" % partition)

            marathon_virtual_list = \
                [x for x in config.keys()
                 if config[x]['partition'] == partition
                 and 'iapp' not in config[x]]
            marathon_pool_list = \
                [x for x in config.keys()
                 if config[x]['partition'] == partition
                 and 'iapp' not in config[x]]
            marathon_iapp_list = \
                [x for x in config.keys()
                 if config[x]['partition'] == partition
                 and 'iapp' in config[x]]

            # Configure iApps
            f5_iapp_list = self.get_iapp_list(partition)
            logger.debug("f5_iapp_list:       %s" % (', '.join(f5_iapp_list)))
            logger.debug("marathon_iapp_list: %s" %
                         (', '.join(marathon_iapp_list)))

            # iapp delete
            iapp_delete = list_diff(f5_iapp_list, marathon_iapp_list)
            logger.debug("iApps to delete: %s", (', '.join(iapp_delete)))
            for iapp in iapp_delete:
                self.iapp_delete(partition, iapp)

            # iapp add
            iapp_add = list_diff(marathon_iapp_list, f5_iapp_list)
            logger.debug("iApps to add: %s", (', '.join(iapp_add)))
            for iapp in iapp_add:
                self.iapp_create(partition, iapp, config[iapp])

            # iapp update
            iapp_intersect = list_intersect(marathon_iapp_list, f5_iapp_list)
            logger.debug("iApps to update: %s", (', '.join(iapp_intersect)))
            for iapp in iapp_intersect:
                self.iapp_update(partition, iapp, config[iapp])

            # this is kinda kludgey: health monitor has the same name as the
            # virtual, and there is no more than 1 monitor per virtual.
            marathon_healthcheck_list = []
            for v in marathon_virtual_list:
                if 'protocol' in config[v]['health']:
                    marathon_healthcheck_list.append(v)

            f5_pool_list = self.get_pool_list(partition)
            f5_virtual_list = self.get_virtual_list(partition)

            # get_healthcheck_list() returns a dict with healthcheck names for
            # keys and a subkey of "type" with a value of "tcp", "http", etc.
            # We need to know the type to correctly reference the resource.
            # i.e. monitor types are different resources in the f5-sdk
            f5_healthcheck_dict = self.get_healthcheck_list(partition)
            logger.debug("f5_healthcheck_dict:   %s", f5_healthcheck_dict)
            # and then we need just the list to identify differences from the
            # list returned from marathon
            f5_healthcheck_list = f5_healthcheck_dict.keys()

            # The virtual servers, pools, and health monitors for iApps are
            # managed by the iApps themselves, so remove them from the lists we
            # manage
            for iapp in marathon_iapp_list:
                f5_virtual_list = \
                    [x for x in f5_virtual_list if not x.startswith(iapp)]
                f5_pool_list = \
                    [x for x in f5_pool_list if not x.startswith(iapp)]
                f5_healthcheck_list = \
                    [x for x in f5_healthcheck_list if not x.startswith(iapp)]

            logger.debug("f5_pool_list:          %s" %
                         (', '.join(f5_pool_list)))
            logger.debug("f5_virtual_list:       %s" %
                         (', '.join(f5_virtual_list)))
            logger.debug("f5_healthcheck_list:   %s" %
                         (', '.join(f5_healthcheck_list)))
            logger.debug("marathon_pool_list:    %s" %
                         (', '.join(marathon_pool_list)))
            logger.debug("marathon_virtual_list: %s" %
                         (', '.join(marathon_virtual_list)))

            # virtual delete
            virt_delete = list_diff(f5_virtual_list, marathon_virtual_list)
            logger.debug("Virtual Servers to delete: %s",
                         (', '.join(virt_delete)))
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
            logger.debug("Healthchecks to delete: %s",
                         (', '.join(health_delete)))
            for hc in health_delete:
                self.healthcheck_delete(partition, hc,
                                        f5_healthcheck_dict[hc]['type'])

            # healthcheck config needs to happen before pool config because
            # the pool is where we add the healthcheck
            # healthcheck add: use the name of the virt for the healthcheck
            healthcheck_add = list_diff(marathon_healthcheck_list,
                                        f5_healthcheck_list)
            logger.debug("Healthchecks to add: %s",
                         (', '.join(healthcheck_add)))
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
            virt_intersect = list_intersect(marathon_virtual_list,
                                            f5_virtual_list)
            logger.debug("Virtual Servers to update: %s",
                         (', '.join(virt_intersect)))

            for virt in virt_intersect:
                self.virtual_update(partition, virt, config[virt])

            # add/update/remove pool members
            # need to iterate over pool_add and pool_intersect (note that
            # removing a pool also removes members, so don't have to
            # worry about those)
            for pool in list(set(pool_add + pool_intersect)):
                logger.debug("Pool: %s", pool)

                f5_member_list = self.get_pool_member_list(partition, pool)
                marathon_member_list = (config[pool]['nodes']).keys()

                member_delete_list = list_diff(f5_member_list,
                                               marathon_member_list)
                logger.debug("Pool members to delete: %s",
                             (', '.join(member_delete_list)))
                for member in member_delete_list:
                    self.member_delete(partition, pool, member)

                member_add = list_diff(marathon_member_list, f5_member_list)
                logger.debug("Pool members to add:    %s",
                             (', '.join(member_add)))
                for member in member_add:
                    self.member_create(partition, pool, member,
                                       config[pool]['nodes'][member])

                # Since we're only specifying hostname and port for members,
                # 'member_update' will never actually get called. Changing
                # either of these properties will result in a new member being
                # created and the old one being deleted. I'm leaving this here
                # though in case we add other properties to members
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
        """Delete any unused nodes in a partition from the BIG-IP.

        Args:
            partition: Partition name
        """
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
        """Delete a node from the BIG-IP partition.

        Args:
            node_name: Node name
            partition: Partition name
        """
        node = self.ltm.nodes.node.load(
            name=node_name,
            partition=partition
            )
        node.delete()

    def get_pool(self, partition, name):
        """Get a pool object.

        Args:
            partition: Partition name
            name: Pool name
        """
        # return pool object

        # TODO: This is the efficient way to lookup a pool object:
        #
        #       p = self.ltm.pools.pool.load(
        #           name=name,
        #           partition=partition
        #       )
        #       return p
        #
        # However, this doesn't work if the path to the pool contains a
        # subpath. This is a known problem in the F5 SDK:
        #     https://github.com/F5Networks/f5-common-python/issues/468
        #
        # The alternative (below) is to get the collection of pool objects
        # and then search the list for the matching pool name.

        pools = self.ltm.pools.get_collection()
        for pool in pools:
            if pool.name == name:
                return pool

        return None

    def get_pool_list(self, partition):
        """Get a list of pool names for a partition.

        Args:
            partition: Partition name
        """
        pool_list = []
        pools = self.ltm.pools.get_collection()
        for pool in pools:
            if pool.partition == partition:
                pool_list.append(pool.name)
        return pool_list

    def pool_create(self, partition, pool, data):
        """Create a pool.

        Args:
            partition: Partition name
            pool: Name of pool to create
            data: BIG-IP config dict
        """
        logger.debug("Creating pool %s", pool)
        p = self.ltm.pools.pool

        p.create(
            name=pool,
            partition=partition
        )

        if 'health' in data and data['health']:
            logger.debug("adding healthcheck '%s' to pool", pool)
            p.monitor = pool
            p.update()

    def pool_delete(self, partition, pool):
        """Delete a pool.

        Args:
            partition: Partition name
            pool: Name of pool to delete
        """
        logger.debug("deleting pool %s", pool)
        p = self.get_pool(partition, pool)
        p.delete()

    def pool_update(self, partition, pool, data):
        """Update a pool.

        Args:
            partition: Partition name
            pool: Name of pool to update
            data: BIG-IP config dict
        """
        # Getting 'data' here, but not used currently
        # In fact, this update function does nothing currently.
        # If we end up supporting more pool-specific options (not really sure
        # what), then we will need this. Data should be changed or massaged to
        # be a list of k,v pairs for the update call

        # loadBalancingMode options:
        #  var: F5_{n}_BALANCE
        #    round-robin,
        #    least-connections-member,
        #    ratio-member
        #    observed-member
        #    ratio-node
        #    ...

        virtual = data['virtual']
        pool = self.get_pool(partition, pool)
        if 'health' in data and data['health'] != {}:
            logger.debug("Adding healthcheck %s to pool", (virtual['name']))
            pool.monitor = virtual['name']
        pool.update(
                state=None
                )

    def get_member(self, partition, pool, member):
        """Get a pool-member object.

        Args:
            partition: Partition name
            pool: Name of pool
            member: Name of pool member
        """
        p = self.get_pool(partition, pool)
        m = p.members_s.members.load(
                name=member,
                partition=partition
                )
        return m

    def get_pool_member_list(self, partition, pool):
        """Get a list of pool-member names.

        Args:
            partition: Partition name
            pool: Name of pool
        """
        member_list = []
        p = self.get_pool(partition, pool)
        members = p.members_s.get_collection()
        for member in members:
            member_list.append(member.name)

        return member_list

    def member_create(self, partition, pool, member, data):
        """Create a pool member.

        Args:
            partition: Partition name
            pool: Name of pool
            member: Name of pool member
            data: BIG-IP config dict
        """
        # getting 'data' here, but not used currently
        p = self.get_pool(partition, pool)
        member = p.members_s.members.create(
                name=member,
                partition=partition
                )

    def member_delete(self, partition, pool, member):
        """Delete a pool member.

        Args:
            partition: Partition name
            pool: Name of pool
            member: Name of pool member
        """
        member = self.get_member(partition, pool, member)
        member.delete()

    def member_update(self, partition, pool, member, data):
        """Update a pool member.

        Args:
            partition: Partition name
            pool: Name of pool
            member: Name of pool member
            data: BIG-IP config dict
        """
        # Getting 'data' here, but not used currently
        # In fact, this update function does nothing currently.
        # If we end up supporting more member-specific options, like ratio
        # then we will need this. Data should be changed or massaged to be
        # a list of k,v pairs for the update call ("ratio": 2)
        member = self.get_member(partition, pool, member)
        # member.update(
        #        state=None
        #        )

    def get_node_list(self, partition):
        """Get a list of node names for a partition.

        Args:
            partition: Partition name
        """
        node_list = []
        nodes = self.ltm.nodes.get_collection()
        for node in nodes:
            if node.partition == partition:
                node_list.append(node.name)

        return node_list

    def get_virtual(self, partition, virtual):
        """Get Virtual Server object.

        Args:
            partition: Partition name
            virtual: Name of the Virtual Server
        """
        # return virtual object
        v = self.ltm.virtuals.virtual.load(
                name=virtual,
                partition=partition
                )
        return v

    def get_virtual_list(self, partition):
        """Get a list of virtual-server names for a partition.

        Args:
            partition: Partition name
        """
        virtual_list = []
        virtuals = self.ltm.virtuals.get_collection()
        for virtual in virtuals:
            if virtual.partition == partition:
                virtual_list.append(virtual.name)

        return virtual_list

    def virtual_create(self, partition, virtual, data):
        """Create a Virtual Server.

        Args:
            partition: Partition name
            virtual: Name of the virtual server
            data: BIG-IP config dict
        """
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

        v.create(
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

        # If this is a virt with a http hc, add the default
        # /Common/http profile
        if 'protocol' in hc_data and (hc_data['protocol']).lower() == "http":
                v.profiles_s.profiles.create(
                        name='http',
                        partition='Common'
                        )

    def virtual_delete(self, partition, virtual):
        """Delete a Virtual Server.

        Args:
            partition: Partition name
            virtual: Name of the Virtual Server
        """
        logger.debug("Deleting Virtual Server %s", virtual)
        v = self.get_virtual(partition, virtual)
        v.delete()

    def virtual_update(self, partition, virtual, data):
        """Update a Virtual Server.

        Args:
            partition: Partition name
            virtual: Name of the Virtual Server
            data: BIG-IP config dict
        """
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
            # If this is a virt with a http hc, add the default
            # /Common/http profile
            if ('protocol' in hc_data and
               (hc_data['protocol']).lower() == "http"):
                    v.profiles_s.profiles.load(
                            name='http',
                            partition='Common'
                            )
        except:
            if ('protocol' in hc_data and
               (hc_data['protocol']).lower() == "http"):
                    v.profiles_s.profiles.create(
                                    name='http',
                                    partition='Common'
                                    )

        # SSL Profile
        if (data['profile']['name']):
            if not v.profiles_s.profiles.exists(
                   name=data['profile']['name'],
                   partition=data['profile']['partition']):
                v.profiles_s.profiles.create(
                    name=data['profile']['name'],
                    partition=data['profile']['partition']
                    )

    def get_healthcheck(self, partition, hc, hc_type):
        """Get a Health Monitor object.

        Args:
            partition: Partition name
            hc: Name of the Health Monitor
            hc_type: Health Monitor type
        """
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
        """Get a dict of Health Monitors for a partition.

        Args:
            partition: Partition name
        """
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
        """Delete a Health Monitor.

        Args:
            partition: Partition name
            hc: Name of the Health Monitor
            hc_type: Health Monitor type
        """
        logger.debug("Deleting healthcheck %s", hc)
        hc = self.get_healthcheck(partition, hc, hc_type)
        hc.delete()

    def healthcheck_timeout_calculate(self, data):
        """Calculate a BIG-IP Health Monitor timeout.

        Args:
            data: BIG-IP config dict
        """
        # Calculate timeout
        # See the f5 monitor docs for explanation of settings:
        # https://goo.gl/JJWUIg
        # Formula to match up marathon settings with f5 settings:
        # (( maxConsecutiveFailures - 1) * intervalSeconds )
        # + timeoutSeconds + 1
        timeout = (((data['maxConsecutiveFailures'] - 1) *
                   data['intervalSeconds']) + data['timeoutSeconds'] + 1)
        return timeout

    def healthcheck_update(self, partition, hc, data):
        """Update a Health Monitor.

        Args:
            partition: Partition name
            hc: Name of the Health Monitor
            data: BIG-IP config dict
        """
        logger.debug("Deleting healthcheck %s", hc)
        # get healthcheck object
        hc = self.get_healthcheck(partition, hc, data['protocol'])

        timeout = self.healthcheck_timeout_calculate(data)

        # f5 docs: https://goo.gl/ALrf37
        send_string = 'GET /'
        if 'path' in data:
            # I expected to have to jump through some hoops to get the "\r\n"
            # literal into the f5 config, but this seems to work.
            # When configuring the f5 directly, you have to include the "\r\n"
            # literal at the end of the GET. From my testing, this is getting
            # added automatically. I'm not sure what layer is adding it
            # (iControl itself?). Anyway, this works for now, but i could see
            # this being fragile
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
        """Create a Health Monitor.

        Args:
            partition: Partition name
            hc: Name of the Health Monitor
            data: BIG-IP config dict
        """
        timeout = self.healthcheck_timeout_calculate(data)

        # NOTE: There is no concept of a grace period in F5, so this setting
        # (gracePeriodSeconds) will be ignored

        # f5 docs: https://goo.gl/ALrf37
        send_string = 'GET /'
        if 'path' in data:
            # I expected to have to jump through some hoops to get the "\r\n"
            # literal into the f5 config, but this seems to work.
            # When configuring the f5 directly, you have to include the "\r\n"
            # literal at the end of the GET.  from my testing, this is getting
            # added automatically. I'm not sure what layer is adding it
            # (iControl itself?). Anyway, this works for now, but i could see
            # this being fragile
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
        """Get a list of BIG-IP partition names.

        Args:
            partitions: The list of partition names we're configured to manage
                        (Could be wildcard: '*')
        """
        if ('*' in partitions):
            # Wildcard means all partitions, so we need to query BIG-IP for the
            # actual partition names
            partition_list = []
            for folder in self.sys.folders.get_collection():
                if (not folder.name == "Common" and not folder.name == "/"
                        and not folder.name.endswith(".app")):

                    partition_list.append(folder.name)
            return partition_list
        else:
            # No wildcard, so we just care about those already configured
            return partitions

    def iapp_build_definition(self, config):
        """Create a dict that defines the 'variables' and 'tables' for an iApp.

        Args:
            config: BIG-IP config dict
        """
        # Build variable list
        variables = []
        for key in config['iapp']['variables']:
            var = {'name': key, 'value': config['iapp']['variables'][key]}
            variables.append(var)

        # Build table
        tables = [{'columnNames': ['addr', 'port', 'connection_limit'],
                   'name': config['iapp']['tableName'],
                   'rows': []
                   }]
        for node in config['nodes']:
            tables[0]['rows'].append({'row': [config['nodes'][node]['host'],
                                     config['nodes'][node]['port'], '0']})

        return {'variables': variables, 'tables': tables}

    def iapp_create(self, partition, name, config):
        """Create an iApp Application Service.

        Args:
            partition: Partition name
            name: Application Service name
            config: BIG-IP config dict
        """
        logger.debug("Creating iApp %s from template %s",
                     name, config['iapp']['template'])
        a = self.sys.application.services.service

        iapp_def = self.iapp_build_definition(config)

        a.create(
            name=name,
            template=config['iapp']['template'],
            partition=partition,
            variables=iapp_def['variables'],
            tables=iapp_def['tables'],
            **config['iapp']['options']
            )

    def iapp_delete(self, partition, name):
        """Delete an iApp Application Service.

        Args:
            partition: Partition name
            name: Application Service name
        """
        logger.debug("Deleting iApp %s", name)
        a = self.get_iapp(partition, name)
        a.delete()

    def iapp_update(self, partition, name, config):
        """Update an iApp Application Service.

        Args:
            partition: Partition name
            name: Application Service name
            config: BIG-IP config dict
        """
        a = self.get_iapp(partition, name)

        iapp_def = self.iapp_build_definition(config)

        a.update(
            executeAction='definition',
            name=name,
            partition=partition,
            variables=iapp_def['variables'],
            tables=iapp_def['tables'],
            **config['iapp']['options']
            )

    def get_iapp(self, partition, name):
        """Get an iApp Application Service object.

        Args:
            partition: Partition name
            name: Application Service name
        """
        a = self.sys.application.services.service.load(
                name=name,
                partition=partition
                )
        return a

    def get_iapp_list(self, partition):
        """Get a list of iApp Application Service names.

        Args:
            partition: Partition name
        """
        iapp_list = []
        iapps = self.sys.application.services.get_collection()
        for iapp in iapps:
            if iapp.partition == partition:
                iapp_list.append(iapp.name)

        return iapp_list
