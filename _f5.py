#!/usr/bin/env python

# pool functions


def get_pool(bigip, partition, pool):
    # return pool object
    p = bigip.ltm.pools.pool.load(
            name=pool,
            partition=partition
            )
    return p

def get_pool_list(bigip, partition):
    pool_list = []
    pools = bigip.ltm.pools.get_collection()
    print pools
    for pool in pools:
        print pool.__dict__
        if pool.partition == partition:
            print "pool is in mesos partition"
            pool_list.append(pool.name)
    print "-----------"
    print pool_list
    print "-----------"
    return pool_list

def pool_create(bigip, partition, pool, data):
    # TODO: do we even need 'data' here?
    print("creating pool %s" % pool)
    p = bigip.ltm.pools.pool

    p.create(
        name=pool,
        partition=partition
        )
    
    if 'health' in data:
        print "adding healthcheck '%s' to pool" % (pool)
        p.monitor = pool
        p.update()

def pool_delete(bigip, partition, pool):
    print("deleting pool %s" % pool)
    p = get_pool(bigip, partition, pool)
    p.delete()

def pool_update(bigip, partition, pool, data):
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
    pool = get_pool(bigip, partition, pool)
    if 'health' in data:
        print "adding healthcheck '%s' to pool" % (virtual['name'])
        pool.monitor = virtual['name']
    pool.update(
            state=None
            )


# pool member functions

def get_member(bigip, partition, pool, member):
    p = get_pool(bigip, partition, pool)
    m = p.members_s.members.load(
            name=member,
            partition=partition
            )
    return m

def get_pool_member_list(bigip, partition, pool):
    member_list = []
    p = get_pool(bigip, partition, pool)
    members = p.members_s.get_collection()
    for member in members:
        member_list.append(member.name)
    
    return member_list

def member_create(bigip, partition, pool, member, data):
    # getting 'data' here, but not used currently
    p = get_pool(bigip, partition, pool)
    member = p.members_s.members.create(
            name=member,
            partition=partition
            )

def member_delete(bigip, partition, pool, member):
    member = get_member(bigip, partition, pool, member)
    member.delete()


def member_update(bigip, partition, pool, member, data):
    # getting 'data' here, but not used currently
    # in fact, this update function does nothing currently.
    # if we end up supporting more member-specific options, like ratio
    # then we will need this.  data should be changed or massaged to be
    # a list of k,v pairs for the update call ("ratio": 2)
    member = get_member(bigip, partition, pool, member)
    #member.update(
    #        state=None
    #        )

# virtual server functions

def get_virtual(bigip, partition, virtual):
    # return virtual object
    v = bigip.ltm.virtuals.virtual.load(
            name=virtual,
            partition=partition
            )
    return v

def get_virtual_list(bigip, partition):
    virtual_list = []
    virtuals = bigip.ltm.virtuals.get_collection()
    for virtual in virtuals:
        if virtual.partition == partition:
            virtual_list.append(virtual.name)

    return virtual_list


def virtual_create(bigip, partition, virtual, data):
    print("creating virt %s" % virtual)
    data = data['virtual']
    v = bigip.ltm.virtuals.virtual
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

    # if this is an http virt, add the default /Common/http profile
    v.profiles_s.profiles.create(
            name='http',
            partition='Common'
            )

    print a.raw

def virtual_delete(bigip, partition, virtual):
    print("deleting virtual %s" % virtual)
    v = get_virtual(bigip, partition, virtual)
    v.delete()

def virtual_update(bigip, partition, virtual, data):
    data = data['virtual']
    destination = "/%s/%s:%d" % (
            partition, 
            data['destination'], 
            data['port']
            )
    pool = "/%s/%s" % (partition, virtual)
    v = get_virtual(bigip, partition, virtual)
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
        v.profiles_s.profiles.load(
                    name='http',
                    partition='Common'
                    )
    except:
        v.profiles_s.profiles.create(
                        name='http',
                        partition='Common'
                        )

# healthcheck functions

def get_healthcheck(bigip, partition, hc, hc_type):
    # return hc object
    if hc_type.lower() == 'http':
        hc = bigip.ltm.monitor.https.http.load(
                name=hc,
                partition=partition
                )
    elif hc_type.lower() == 'tcp':
        hc = bigip.ltm.monitor.tcps.tcp.load(
                name=hc,
                partition=partition
                )

    return hc

def get_healthcheck_list(bigip, partition):
    # will need to handle HTTP and TCP

    healthcheck_dict = {}

    # HTTP
    healthchecks = bigip.ltm.monitor.https.get_collection()
    for hc in healthchecks:
        if hc.partition == partition:
            healthcheck_dict.update(
                    {hc.name: {'type': 'http'}}
                    )
   
    # TCP
    healthchecks = bigip.ltm.monitor.tcps.get_collection()
    for hc in healthchecks:
        if hc.partition == partition:
            healthcheck_dict.update(
                    {hc.name: {'type': 'tcp'}}
                    )

    return healthcheck_dict

def healthcheck_delete(bigip, partition, hc, hc_type):
    print("deleting healthcheck %s" % hc)
    hc = get_healthcheck(bigip, partition, hc, hc_type)
    hc.delete()

def healthcheck_timeout_calculate(data):
    # calculate timeout
    # see the f5 monitor docs for explanation of settings: https://goo.gl/JJWUIg
    # formula to match up marathon settings with f5 settings
    # ( ( maxConsecutiveFailures - 1) * intervalSeconds ) + timeoutSeconds + 1
    timeout = ((data['maxConsecutiveFailures'] - 1) * data['intervalSeconds']) + data['timeoutSeconds'] + 1
    return timeout

def healthcheck_update(bigip, partition, hc, data):

    # get healthcheck object
    hc = get_healthcheck(bigip, partition, hc, data['protocol'])
    
    timeout = healthcheck_timeout_calculate(data)
    
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
                sendString=send_string,
                )

    if (data['protocol']).lower() == "tcp":
        hc.update(
                interval=data['intervalSeconds'],
                timeout=timeout,
                )

def healthcheck_create(bigip, partition, hc, data):

    timeout = healthcheck_timeout_calculate(data)

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
        h = bigip.ltm.monitor.https
        http1 = h.http
        print http1
        http1.create(
                name=hc,
                partition=partition,
                interval=data['intervalSeconds'],
                timeout=timeout,
                sendString=send_string,
                )

    if (data['protocol']).lower() == "tcp":
        h = bigip.ltm.monitor.tcps
        tcp1 = h.tcp
        print tcp1
        tcp1.create(
                name=hc,
                partition=partition,
                interval=data['intervalSeconds'],
                timeout=timeout,
                )


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
