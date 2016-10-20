"""f5-marathon-lb Unit Tests.

Units tests for testing command-line args, Marathon state parsing, and
BIG-IP resource management.

"""
import unittest
import json
import sys
import f5
import icontrol
import requests
import os
from mock import Mock
from mock import patch
from f5_marathon_lb import get_apps, parse_args
from f5.bigip import BigIP
from _f5 import CloudBigIP
from StringIO import StringIO

args_env = ['F5_CSI_SYSLOG_SOCKET',
            'F5_CSI_LOG_FORMAT',
            'F5_CSI_MARATHON_AUTH',
            'MARATHON_URL',
            'F5_CSI_LISTENING_ADDR',
            'F5_CSI_CALLBACK_URL',
            'F5_CSI_BIGIP_HOSTNAME',
            'F5_CSI_BIGIP_USERNAME',
            'F5_CSI_BIGIP_PASSWORD',
            'F5_CSI_PARTITIONS',
            'F5_CSI_USE_SSE',
            'F5_CSI_USE_HEALTHCHECK',
            'F5_CSI_SSE_TIMEOUT']


class ArgTest(unittest.TestCase):
    """Test f5-marathon-lb arg parsing."""

    _args_app_name = ['f5-marathon-lb']
    _args_mandatory = ['--marathon', 'http://10.0.0.10:8080',
                       '--partition', 'mesos',
                       '--hostname', '10.10.1.145',
                       '--username', 'admin',
                       '--password', 'default']
    _args_without_partition = ['--marathon', 'http://10.0.0.10:8080',
                               '--hostname', '10.10.1.145',
                               '--username', 'admin',
                               '--password', 'default']

    def setUp(self):
        """Test suite set up."""
        self.out = StringIO()
        sys.stderr = self.out

    def tearDown(self):
        """Test suite tear down."""
        # Clear env vars
        for arg in args_env:
            os.environ.pop(arg, None)

    def test_no_args(self):
        """Test: No command-line args."""
        sys.argv[0:] = self._args_app_name
        self.assertRaises(SystemExit, parse_args)

        expected = \
            "usage: f5-marathon-lb [-h] [--longhelp]" \
            """ [--marathon MARATHON [MARATHON ...]]
                      [--listening LISTENING] [--callback-url CALLBACK_URL]
                      [--hostname HOSTNAME] [--username USERNAME]
                      [--password PASSWORD] [--partition PARTITION] [--sse]
                      [--health-check] [--sse-timeout SSE_TIMEOUT]
                      [--verify-interval VERIFY_INTERVAL]
                      [--syslog-socket SYSLOG_SOCKET]
                      [--log-format LOG_FORMAT]
                      [--marathon-auth-credential-file""" \
            " MARATHON_AUTH_CREDENTIAL_FILE]\n" \
            "f5-marathon-lb: error: argument --marathon/-m is required\n"

        output = self.out.getvalue()
        self.assertEqual(output, expected)

    def test_all_mandatory_args(self):
        """Test: All mandatory command-line args."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.marathon, ['http://10.0.0.10:8080'])
        self.assertEqual(args.partition, ['mesos'])
        self.assertEqual(args.hostname, '10.10.1.145')
        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.password, 'default')
        # default arg values
        self.assertEqual(args.sse, False)
        self.assertEqual(args.health_check, False)
        if sys.platform == "darwin":
            self.assertEqual(args.syslog_socket, '/var/run/syslog')
        else:
            self.assertEqual(args.syslog_socket, '/dev/log')
        self.assertEqual(args.log_format,
                         '%(asctime)s %(name)s: %(levelname) -8s: %(message)s')
        self.assertEqual(args.listening, None)
        self.assertEqual(args.callback_url, None)
        self.assertEqual(args.marathon_auth_credential_file, None)

    def test_all_mandatory_args_from_env(self):
        """Test: All mandatory command-line args."""
        sys.argv[0:] = self._args_app_name
        os.environ['MARATHON_URL'] = 'http://10.0.0.10:8080'
        os.environ['F5_CSI_PARTITIONS'] = '[mesos, mesos2]'
        os.environ['F5_CSI_BIGIP_HOSTNAME'] = '10.10.1.145'
        os.environ['F5_CSI_BIGIP_USERNAME'] = 'admin'
        os.environ['F5_CSI_BIGIP_PASSWORD'] = 'default'
        args = parse_args()
        self.assertEqual(args.marathon, ['http://10.0.0.10:8080'])
        self.assertEqual(args.partition, ['mesos', 'mesos2'])
        self.assertEqual(args.hostname, '10.10.1.145')
        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.password, 'default')

    def test_partition_arg(self):
        """Test: Wildcard partition arg."""
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = parse_args()
        self.assertEqual(args.partition, ['*'])

        # test via env var
        partitions_env = '*'
        sys.argv[0:] = self._args_app_name + self._args_without_partition
        os.environ['F5_CSI_PARTITIONS'] = partitions_env
        args = parse_args()
        self.assertEqual(args.partition, ['*'])

    def test_multiple_partition_arg(self):
        """Test: Multiple partition args."""
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'mesos-1',
                '--partition', 'mesos-2',
                '--partition', 'mesos-3',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = parse_args()
        self.assertEqual(args.partition, ['mesos-1', 'mesos-2', 'mesos-3'])

        # test via env var
        partitions_env = '[mesos7, mesos8]'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CSI_PARTITIONS'] = partitions_env
        args = parse_args()
        # command-line overrides env var
        self.assertEqual(args.partition, ['mesos'])

        sys.argv[0:] = self._args_app_name + self._args_without_partition
        args = parse_args()
        self.assertEqual(args.partition, ['mesos7', 'mesos8'])

    def test_conflicting_args(self):
        """Test: Mutually-exclusive args."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--listening', '-sse']
        self.assertRaises(SystemExit, parse_args)

        # test via env var
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        listen_addr_env = '192.168.10.50'
        os.environ['F5_CSI_LISTENING_ADDR'] = listen_addr_env
        os.environ['F5_CSI_USE_SSE'] = 'True'
        self.assertRaises(SystemExit, parse_args)

    def test_callback_arg(self):
        """Test: 'Callback URL' arg."""
        url = 'http://marathon:8080'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--callback-url', url]
        args = parse_args()
        self.assertEqual(args.callback_url, url)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-u', url]
        args = parse_args()
        self.assertEqual(args.callback_url, url)

        # test via env var
        url_env = 'http://marathon:8081'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CSI_CALLBACK_URL'] = url_env
        args = parse_args()
        self.assertEqual(args.callback_url, url_env)

    def test_listening_arg(self):
        """Test: 'Listening' arg."""
        listen_addr = '192.168.10.50'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--listening', listen_addr]
        args = parse_args()
        self.assertEqual(args.listening, listen_addr)

        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['-l', listen_addr]
        args = parse_args()
        self.assertEqual(args.listening, listen_addr)

        # test via env var
        listen_addr_env = '192.168.10.90'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CSI_LISTENING_ADDR'] = listen_addr_env
        args = parse_args()
        self.assertEqual(args.listening, listen_addr_env)

    def test_sse_arg(self):
        """Test: 'SSE' arg."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.sse, False)
        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['--sse']
        args = parse_args()
        self.assertEqual(args.sse, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-s']
        args = parse_args()
        self.assertEqual(args.sse, True)

        # test via env var
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.sse, False)
        os.environ['F5_CSI_USE_SSE'] = 'True'
        args = parse_args()
        self.assertEqual(args.sse, True)

    def test_health_check_arg(self):
        """Test: 'Health Check' arg."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.health_check, False)
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--health-check']
        args = parse_args()
        self.assertEqual(args.health_check, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-H']
        args = parse_args()
        self.assertEqual(args.health_check, True)

        # test via env var
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.health_check, False)
        os.environ['F5_CSI_USE_HEALTHCHECK'] = 'True'
        args = parse_args()
        self.assertEqual(args.health_check, True)

    def test_syslog_socket_arg(self):
        """Test: 'Syslog socket' arg."""
        log_file = '/var/run/mylog'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--syslog-socket', log_file]
        args = parse_args()
        self.assertEqual(args.syslog_socket, log_file)

        # test via env var
        env_log_file = '/var_run/mylog_from_env'
        os.environ['F5_CSI_SYSLOG_SOCKET'] = env_log_file
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.syslog_socket, env_log_file)

    def test_log_format_arg(self):
        """Test: 'Log format' arg."""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-format', log_format]
        args = parse_args()
        self.assertEqual(args.log_format, log_format)

        # test via env var
        env_log_format = '%(asctime)s - %(message)s'
        os.environ['F5_CSI_LOG_FORMAT'] = env_log_format
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.log_format, env_log_format)

    def test_marathon_cred_arg(self):
        """Test: 'Marathon credentials' arg."""
        auth_file = '/tmp/auth'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-auth-credential-file', auth_file]
        args = parse_args()
        self.assertEqual(args.marathon_auth_credential_file, auth_file)

        # test via env var
        env_auth_file = '/tmp/auth_from_env'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CSI_MARATHON_AUTH'] = env_auth_file
        args = parse_args()
        self.assertEqual(args.marathon_auth_credential_file, env_auth_file)

    def test_timeout_arg(self):
        """Test: 'SSE timeout' arg."""
        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--sse-timeout', str(timeout)]
        args = parse_args()
        self.assertEqual(args.sse_timeout, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.sse_timeout, 30)

        # test via env var
        os.environ['F5_CSI_SSE_TIMEOUT'] = str(timeout)
        args = parse_args()
        self.assertEqual(args.sse_timeout, timeout)

    def test_verify_interval_arg(self):
        """Test: 'Verify Interval' arg."""
        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--verify-interval', str(timeout)]
        args = parse_args()
        self.assertEqual(args.verify_interval, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.verify_interval, 30)

        # test via env var
        os.environ['F5_CSI_VERIFY_INTERVAL'] = str(timeout)
        args = parse_args()
        self.assertEqual(args.verify_interval, timeout)


class Pool():
    """A mock BIG-IP Pool."""

    def __init__(self, name, **kwargs):
        """Initialize the object."""
        self.name = name
        self.monitor = kwargs.get('monitor', None)
        self.loadBalancingMode = kwargs.get('balance', None)

    def modify(self, **kwargs):
        """Placeholder: This will be mocked."""
        pass


class Member():
    """A mock BIG-IP Pool Member."""

    def __init__(self, name, **kwargs):
        """Initialize the object."""
        self.name = name
        self.session = kwargs.get('session', None)
        if kwargs.get('state', None) == 'user-up':
            self.state = 'up'
        else:
            self.state = 'user-down'

    def modify(self, **kwargs):
        """Placeholder: This will be mocked."""
        pass


class Profiles():
    """A container of Virtual Server Profiles."""

    def __init__(self, **kwargs):
        """Initialize the object."""
        self.profiles = kwargs.get('profiles', [])

    def exists(self, name, partition):
        """Check for the existance of a profile."""
        for p in self.profiles:
            if p['name'] == name and p['partition'] == partition:
                return True

        return False

    def create(self, name, partition):
        """Placeholder: This will be mocked."""
        pass


class ProfileSet():
    """A set of Virtual Server Profiles."""

    def __init__(self, **kwargs):
        """Initialize the object."""
        self.profiles = Profiles(**kwargs)


class Virtual():
    """A mock BIG-IP Virtual Server."""

    def __init__(self, name, **kwargs):
        """Initialize the object."""
        self.profiles_s = ProfileSet(**kwargs)
        self.name = name
        self.enabled = kwargs.get('enabled', None)
        self.disabled = kwargs.get('disabled', None)
        self.ipProtocol = kwargs.get('ipProtocol', None)
        self.destination = kwargs.get('destination', None)
        self.pool = kwargs.get('pool', None)
        self.sourceAddressTranslation = kwargs.get('sourceAddressTranslation',
                                                   None)
        self.profiles = kwargs.get('profiles', [])

    def modify(self, **kwargs):
        """Placeholder: This will be mocked."""
        pass


class HealthCheck():
    """A mock BIG-IP Health Monitor."""

    def __init__(self, name, **kwargs):
        """Initialize the object."""
        self.interval = kwargs.get('interval', None)
        self.timeout = kwargs.get('timeout', None)
        self.send = kwargs.get('send', None)

    def modify(self, **kwargs):
        """Placeholder: This will be mocked."""
        pass


class BigIPTest(unittest.TestCase):
    """BIG-IP configuration tests.

    Test BIG-IP configuration given various cloud states and existing
    BIG-IP states
    """

    virtuals = {}
    pools = {}
    virtuals = {}
    members = {}
    healthchecks = {}

    def mock_get_pool_member_list(self, partition, pool):
        """Mock: Get a mocked list of pool members."""
        try:
            return self.bigip_data[pool]
        except KeyError:
            return []

    def mock_get_node_list(self, partition):
        """Mock: Get a mocked list of nodes."""
        return ['10.141.141.10']

    def mock_get_healthcheck_list(self, partition):
        """Mock: Get a mocked list of health monitors."""
        return self.hm_data

    def mock_get_iapp_empty_list(self, partition):
        """Mock: Get a mocked list of iapps."""
        return []

    def mock_get_iapp_list(self, partition):
        """Mock: Get a mocked list of iapps."""
        return ['server-app2_iapp_10000_vs']

    def mock_get_partition_list(self, partitions):
        """Mock: Get a mocked list of partitions."""
        if '*' in partitions:
            return ['mesos', 'mesos2']
        else:
            return partitions

    def create_mock_pool(self, name, **kwargs):
        """Create a mock pool server object."""
        pool = Pool(name, **kwargs)
        self.pools[name] = pool
        pool.modify = Mock()
        return pool

    def create_mock_virtual(self, name, **kwargs):
        """Create a mock virtual server object."""
        virtual = Virtual(name, **kwargs)
        self.virtuals[name] = virtual
        virtual.modify = Mock()
        virtual.profiles_s.profiles.create = Mock()
        return virtual

    def create_mock_pool_member(self, name, **kwargs):
        """Create a mock pool member object."""
        member = Member(name, **kwargs)
        self.members[name] = member
        member.modify = Mock()
        return member

    def create_mock_healthcheck(self, name, **kwargs):
        """Create a mock healthcheck object."""
        healthcheck = HealthCheck(name, **kwargs)
        self.healthchecks[name] = healthcheck
        healthcheck.modify = Mock()
        return healthcheck

    def mock_get_pool(self, partition, name):
        """Lookup a mock pool object by name."""
        return self.pools.get(name, None)

    def mock_get_virtual(self, partition, name):
        """Lookup a mock virtual server object by name."""
        return self.virtuals.get(name, None)

    def mock_get_virtual_address(self, partition, name):
        """Lookup a mock virtual Address object by name."""
        return name

    def mock_get_member(self, partition, pool, name):
        """Lookup a mock pool member object by name."""
        return self.members.get(name, None)

    def mock_get_healthcheck(self, partition, hc, hc_type):
        """Lookup a mock healthcheck object by name."""
        return self.healthchecks.get(hc, None)

    def read_test_vectors(self, cloud_state, bigip_state, hm_state):
        """Read test vectors for cloud, BIG-IP, and Health Monitor state."""
        # Read the Marathon state
        with open(cloud_state) as json_data:
            self.cloud_data = json.load(json_data)

        # Read the BIG-IP state
        with open(bigip_state) as json_data:
            self.bigip_data = json.load(json_data)

        with open(hm_state) as json_data:
            self.hm_data = json.load(json_data)

        self.bigip.get_pool_list = Mock(return_value=self.bigip_data.keys())
        self.bigip.get_virtual_list = Mock(return_value=self.bigip_data.keys())

    def raiseTypeError(self, cfg):
        """Raise a TypeError exception."""
        raise TypeError

    def raiseSDKError(self, cfg):
        """Raise an F5SDKError exception."""
        raise f5.sdk_exception.F5SDKError

    def raiseConnectionError(self, cfg):
        """Raise a ConnectionError exception."""
        raise requests.exceptions.ConnectionError

    def raiseBigIPInvalidURL(self, cfg):
        """Raise a BigIPInvalidURL exception."""
        raise icontrol.exceptions.BigIPInvalidURL

    def raiseBigiControlUnexpectedHTTPError(self, cfg):
        """Raise an iControlUnexpectedHTTPError exception."""
        raise icontrol.exceptions.iControlUnexpectedHTTPError

    def setUp(self, cloud, partition):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        with patch.object(BigIP, '_get_tmos_version'):
            self.bigip = CloudBigIP(cloud, '1.2.3.4', 'admin', 'default',
                                    [partition])

        self.bigip.get_pool_member_list = \
            Mock(side_effect=self.mock_get_pool_member_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)
        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_empty_list)

        # Save the original update functions (to be restored when needed)
        self.bigip.pool_update_orig = self.bigip.pool_update
        self.bigip.virtual_update_orig = self.bigip.virtual_update
        self.bigip.member_update_orig = self.bigip.member_update
        self.bigip.healthcheck_update_orig = self.bigip.healthcheck_update

        self.bigip.get_node = Mock()
        self.bigip.pool_create = Mock()
        self.bigip.pool_delete = Mock()
        self.bigip.pool_update = Mock()

        self.bigip.healthcheck_create = Mock()
        self.bigip.healthcheck_delete = Mock()
        self.bigip.healthcheck_update = Mock()

        self.bigip.virtual_create = Mock()
        self.bigip.virtual_delete = Mock()
        self.bigip.virtual_update = Mock()

        self.bigip.virtual_address_create = Mock()
        self.bigip.virtual_address_update = Mock()

        self.bigip.member_create = Mock()
        self.bigip.member_delete = Mock()
        self.bigip.member_update = Mock()

        self.bigip.iapp_create = Mock()
        self.bigip.iapp_delete = Mock()
        self.bigip.iapp_update = Mock()

        self.bigip.node_delete = Mock()

        self.bigip.get_partitions = \
            Mock(side_effect=self.mock_get_partition_list)
        self.bigip.get_node_list = Mock(side_effect=self.mock_get_node_list)

    def tearDown(self):
        """Test suite tear down."""
        pass


class MarathonTest(BigIPTest):
    """Marathon/Big-IP configuration tests.

    Test BIG-IP configuration given various Marathon states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        super(MarathonTest, self).setUp('marathon', 'mesos')

    def check_labels(self, apps, services):
        """Validate label parsing."""
        for app, service in zip(apps, services):
            labels = app['labels']
            if labels.get('F5_0_BIND_ADDR') is not None:
                self.assertNotEqual(labels.get('F5_PARTITION'), None)
                self.assertNotEqual(labels.get('F5_0_MODE'), None)
                self.assertEqual(labels.get('F5_PARTITION'), service.partition)
                self.assertEqual(labels.get('F5_0_BIND_ADDR'),
                                 service.bindAddr)
                self.assertEqual(labels.get('F5_0_MODE'), service.mode)

                # Verify that F5_0_PORT label overrides the Marathon service
                # port
                if labels.get('F5_0_PORT') is not None:
                    self.assertEqual(int(labels.get('F5_0_PORT')),
                                     service.servicePort)
                else:
                    self.assertEqual(app['ports'][0], service.servicePort)

    def test_exceptions(self, cloud_state='tests/marathon_two_apps.json',
                        bigip_state='tests/bigip_test_no_change.json',
                        hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Exception handling."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)
        apps = get_apps(self.cloud_data, True)

        # Successful configuration (no retry)
        self.assertFalse(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = Mock(side_effect=self.raiseSDKError)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = \
            Mock(side_effect=self.raiseConnectionError)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = \
            Mock(side_effect=self.raiseBigIPInvalidURL)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = \
            Mock(side_effect=self.raiseBigiControlUnexpectedHTTPError)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # Other exception types are raised
        self.bigip._apply_config = Mock(side_effect=self.raiseTypeError)
        self.assertRaises(TypeError, self.bigip.regenerate_config_f5, apps)

    def test_no_change(self, cloud_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_no_change.json',
                       hm_state='tests/bigip_test_two_monitors.json'):
        """Test: No Marathon state change."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)

    def test_app_destroyed(self, cloud_state='tests/marathon_one_app.json',
                           bigip_state='tests/bigip_test_app_destroyed.json',
                           hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app destroyed."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.virtual_delete.called)
        self.assertTrue(self.bigip.pool_delete.called)
        self.assertTrue(self.bigip.healthcheck_delete.called)
        self.assertEqual(self.bigip.virtual_delete.call_count, 1)
        self.assertEqual(self.bigip.pool_delete.call_count, 1)
        self.assertEqual(self.bigip.healthcheck_delete.call_count, 1)

    def test_app_scaled_up(self,
                           cloud_state='tests/marathon_app_scaled.json',
                           bigip_state='tests/bigip_test_app_scaled_up.json',
                           hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app destroyed."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

    def test_app_scaled_down(
            self,
            cloud_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_scaled_down.json',
            hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app scaled down."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_delete.called)
        self.assertEqual(self.bigip.member_delete.call_count, 2)

    def test_start_app_with_health_monitor_tcp(
            self,
            cloud_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_started_with_tcp.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Start Marathon app with a TCP health monitor."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 1)
        self.assertEquals(self.bigip.pool_create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 4)
        self.assertEquals(self.bigip.healthcheck_create.call_count, 1)

    def test_start_app_with_health_monitor_http(
            self,
            cloud_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_started_with_http.json',
            hm_state='tests/bigip_test_one_tcp_monitor.json'):
        """Test: Start Marathon app with an HTTP health monitor."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 1)
        self.assertEquals(self.bigip.pool_create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 2)
        self.assertEquals(self.bigip.healthcheck_create.call_count, 1)

    def test_start_app_with_health_monitor_none(
            self,
            cloud_state='tests/marathon_app_no_hm.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Start Marathon app with no health monitor configured."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 1)
        self.assertEquals(self.bigip.pool_create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 2)

    def test_bigip_new(self, cloud_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_blank.json',
                       hm_state='tests/bigip_test_blank.json'):
        """Test: BIG-IP with no resources previously configured."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 2)
        self.assertEquals(self.bigip.pool_create.call_count, 2)
        self.assertEquals(self.bigip.member_create.call_count, 6)
        self.assertEquals(self.bigip.healthcheck_create.call_count, 2)

    def test_no_port_override(
            self,
            cloud_state='tests/marathon_one_app_no_port_label.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app using default Marathon service port."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 1)
        self.assertEquals(self.bigip.pool_create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 4)
        self.assertEquals(self.bigip.healthcheck_create.call_count, 1)

        # No override of service port from Marathon
        expected_name = 'server-app_10.128.10.240_10001'
        self.assertEquals(self.bigip.virtual_create.call_args[0][1],
                          expected_name)
        self.assertEquals(self.bigip.pool_create.call_args[0][1],
                          expected_name)
        self.assertEquals(self.bigip.member_create.call_args[0][1],
                          expected_name)

    def test_start_app_with_two_service_ports_and_two_hm(
            self,
            cloud_state='tests/marathon_one_app_two_service_ports.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app with two service ports."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 2)
        self.assertEquals(self.bigip.pool_create.call_count, 2)
        self.assertEquals(self.bigip.member_create.call_count, 6)
        self.assertEquals(self.bigip.healthcheck_create.call_count, 2)

        expected_name1 = 'server-app4_10.128.10.240_8080'
        expected_name2 = 'server-app4_10.128.10.240_8090'
        self.assertEquals(self.bigip.virtual_create.call_args_list[0][0][1],
                          expected_name1)
        self.assertEquals(self.bigip.virtual_create.call_args_list[1][0][1],
                          expected_name2)
        self.assertEquals(self.bigip.pool_create.call_args_list[0][0][1],
                          expected_name1)
        self.assertEquals(self.bigip.pool_create.call_args_list[1][0][1],
                          expected_name2)
        self.assertEquals(
            self.bigip.healthcheck_create.call_args_list[0][0][1]['name'],
            expected_name1)
        self.assertEquals(
            self.bigip.healthcheck_create.call_args_list[1][0][1]['name'],
            expected_name2)

    def start_two_apps_with_two_partitions(
            self, partitions, expected_name1, expected_name2,
            cloud_state='tests/marathon_two_apps_two_partitions.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start two Marathon apps on two partitions."""
        # Setup two partitions
        self.bigip._partitions = partitions

        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        create_call_count = 0

        if expected_name1:
            create_call_count += 1
            self.assertEquals(
                self.bigip.virtual_create.call_args_list[0][0][1],
                expected_name1)
            self.assertEquals(self.bigip.pool_create.call_args_list[0][0][1],
                              expected_name1)
            self.assertEquals(
                self.bigip.healthcheck_create.call_args_list[0][0][1]['name'],
                expected_name1)

        if expected_name2:
            create_call_count += 1
            self.assertEquals(self.bigip.virtual_create.call_args_list[
                create_call_count - 1][0][1], expected_name2)
            self.assertEquals(self.bigip.pool_create.call_args_list[
                create_call_count - 1][0][1], expected_name2)
            self.assertEquals(self.bigip.healthcheck_create.call_args_list[
                create_call_count - 1][0][1]['name'], expected_name2)

        if create_call_count > 0:
            self.assertTrue(self.bigip.virtual_create.called)
            self.assertTrue(self.bigip.pool_create.called)
            self.assertTrue(self.bigip.member_create.called)
            self.assertTrue(self.bigip.healthcheck_create.called)
        else:
            self.assertFalse(self.bigip.virtual_create.called)
            self.assertFalse(self.bigip.pool_create.called)
            self.assertFalse(self.bigip.member_create.called)
            self.assertFalse(self.bigip.healthcheck_create.called)

        self.assertEquals(self.bigip.virtual_create.call_count,
                          create_call_count)
        self.assertEquals(self.bigip.pool_create.call_count,
                          create_call_count)
        self.assertEquals(self.bigip.member_create.call_count,
                          3*create_call_count)
        self.assertEquals(self.bigip.healthcheck_create.call_count,
                          create_call_count)

    def test_start_two_apps_with_two_matching_partitions(self):
        """Test: Start two Marathon apps on two partitions."""
        self.start_two_apps_with_two_partitions(
            ['mesos', 'mesos2'],
            'server-app_10.128.10.240_80',
            'server-app1_10.128.10.242_80')

    def test_start_two_apps_with_wildcard_partitions(self):
        """Test: Start two Marathon apps, all partitions managed."""
        self.start_two_apps_with_two_partitions(
            ['*'],
            'server-app_10.128.10.240_80',
            'server-app1_10.128.10.242_80')

    def test_start_two_apps_with_three_partitions(self):
        """Test: Start two Marathon apps, three partitions managed."""
        self.start_two_apps_with_two_partitions(
            ['mesos', 'mesos2', 'mesos3'],
            'server-app_10.128.10.240_80',
            'server-app1_10.128.10.242_80')

    def test_start_two_apps_with_one_matching_partition(self):
        """Test: Start two Marathon apps, one managed partition matches."""
        self.start_two_apps_with_two_partitions(
            ['mesos', 'mesos1', 'mesos3'],
            None,
            'server-app_10.128.10.240_80')

    def test_start_two_apps_with_no_matching_partitions(self):
        """Test: Start two Marathon apps, no managed partitions match."""
        self.start_two_apps_with_two_partitions(
            ['mesos0', 'mesos1', 'mesos3'],
            None,
            None)

    def test_start_two_apps_with_no_partitions_configured(self):
        """Test: Start two Marathon apps, no partitions managed."""
        self.start_two_apps_with_two_partitions(
            [],
            None,
            None)

    def test_start_app_with_one_unconfigured_service_ports(
            self,
            cloud_state='tests/'
            'marathon_app_with_one_unconfig_service_port.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon apps with one uncofigured service port."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertEquals(self.bigip.virtual_create.call_count, 2)
        self.assertEquals(self.bigip.pool_create.call_count, 2)
        self.assertEquals(self.bigip.member_create.call_count, 4)
        self.assertEquals(self.bigip.healthcheck_create.call_count, 2)

        expected_name1 = 'server-app4_10.128.10.240_8080'
        expected_name2 = 'server-app4_10.128.10.242_8090'
        self.assertEquals(self.bigip.virtual_create.call_args_list[0][0][1],
                          expected_name1)
        self.assertEquals(self.bigip.virtual_create.call_args_list[1][0][1],
                          expected_name2)
        self.assertEquals(self.bigip.pool_create.call_args_list[0][0][1],
                          expected_name1)
        self.assertEquals(self.bigip.pool_create.call_args_list[1][0][1],
                          expected_name2)
        self.assertEquals(
            self.bigip.healthcheck_create.call_args_list[0][0][1]['name'],
            expected_name1)
        self.assertEquals(
            self.bigip.healthcheck_create.call_args_list[1][0][1]['name'],
            expected_name2)

    def test_destroy_all_apps(
            self,
            cloud_state='tests/marathon_no_apps.json',
            bigip_state='tests/bigip_test_no_change.json',
            hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Destroy all Marathon apps."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.virtual_delete.called)
        self.assertTrue(self.bigip.pool_delete.called)
        self.assertTrue(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertEquals(self.bigip.virtual_delete.call_count, 2)
        self.assertEquals(self.bigip.pool_delete.call_count, 2)
        self.assertEquals(self.bigip.member_delete.call_count, 0)
        self.assertEquals(self.bigip.healthcheck_delete.call_count, 2)

        expected_name1 = 'server-app2_10.128.10.240_8080'
        expected_name2 = 'server-app_10.128.10.240_80'
        self.assertEquals(self.bigip.virtual_delete.call_args_list[0][0][1],
                          expected_name1)
        self.assertEquals(self.bigip.virtual_delete.call_args_list[1][0][1],
                          expected_name2)
        self.assertEquals(self.bigip.pool_delete.call_args_list[0][0][1],
                          expected_name1)
        self.assertEquals(self.bigip.pool_delete.call_args_list[1][0][1],
                          expected_name2)
        self.assertEquals(
            self.bigip.healthcheck_delete.call_args_list[0][0][1],
            expected_name1)
        self.assertEquals(
            self.bigip.healthcheck_delete.call_args_list[1][0][1],
            expected_name2)

    def test_app_suspended(
            self,
            cloud_state='tests/marathon_one_app_zero_instances.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Suspend Marathon app."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertTrue(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertEquals(self.bigip.member_delete.call_count, 4)

        expected_name = 'server-app_10.128.10.240_80'
        self.assertEquals(self.bigip.member_delete.call_args_list[0][0][1],
                          expected_name)

    def test_new_iapp(self, cloud_state='tests/marathon_one_iapp.json',
                      bigip_state='tests/bigip_test_blank.json',
                      hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertTrue(self.bigip.iapp_create.called)

        self.assertEquals(self.bigip.iapp_create.call_count, 1)

        expected_name = 'server-app2_iapp_10000'
        self.assertEquals(self.bigip.iapp_create.call_args_list[0][0][1],
                          expected_name)

    def test_delete_iapp(self, cloud_state='tests/marathon_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Marathon app associated with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_list)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.iapp_delete.called)
        self.assertEquals(self.bigip.iapp_delete.call_count, 1)

        expected_name = 'server-app2_iapp_10000_vs'
        self.assertEquals(self.bigip.iapp_delete.call_args_list[0][0][1],
                          expected_name)

    def test_https_app(
            self,
            cloud_state='tests/marathon_one_app_https.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app that uses HTTPS."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)
        self.bigip.regenerate_config_f5(apps)

        https_app_count = 0
        for service, app in zip(self.cloud_data, apps):
            labels = service['labels']
            if labels.get('F5_0_BIND_ADDR') is not None:
                self.assertEqual(labels.get('F5_PARTITION'), 'mesos')
                self.assertEqual(labels.get('F5_0_BIND_ADDR'), '10.128.10.240')
                self.assertEqual(labels.get('F5_0_MODE'), 'http')
                self.assertEqual(labels.get('F5_0_SSL_PROFILE'),
                                 'Common/clientssl')
                self.assertEqual(labels.get('F5_PARTITION'), app.partition)
                self.assertEqual(labels.get('F5_0_BIND_ADDR'), app.bindAddr)
                self.assertEqual(labels.get('F5_0_MODE'), app.mode)
                self.assertEqual(labels.get('F5_0_SSL_PROFILE'), app.profile)
                https_app_count += 1

        self.assertEqual(https_app_count, 1)

    def test_updates(self,
                     cloud_state='tests/marathon_one_app_https.json',
                     bigip_state='tests/bigip_test_one_app.json',
                     hm_state='tests/bigip_test_one_monitor.json'):
        """Test: Verify BIG-IP updates.

        Verify that resources are only updated when the state
        of the resource changes.
        """
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.cloud_data, True)

        # Restore the mocked 'update' functions to their original state
        self.bigip.pool_update = self.bigip.pool_update_orig
        self.bigip.virtual_update = self.bigip.virtual_update_orig
        self.bigip.member_update = self.bigip.member_update_orig
        self.bigip.healthcheck_update = self.bigip.healthcheck_update_orig

        # Mock the 'get' resource functions. We will use these to supply
        # mocked resources
        self.bigip.get_pool = Mock(side_effect=self.mock_get_pool)
        self.bigip.get_virtual = Mock(side_effect=self.mock_get_virtual)
        self.bigip.get_member = Mock(side_effect=self.mock_get_member)
        self.bigip.get_healthcheck = Mock(
            side_effect=self.mock_get_healthcheck)
        self.bigip.get_virtual_address = Mock(
            side_effect=self.mock_get_virtual_address)

        # Create a mock Pool
        pool_data_unchanged = {'monitor': '/mesos/server-app_10.128.10.240_80',
                               'balance': 'round-robin'}
        pool = self.create_mock_pool('server-app_10.128.10.240_80',
                                     **pool_data_unchanged)

        # Create a mock Virtual
        virtual_data_unchanged = {'enabled': True,
                                  'disabled': False,
                                  'ipProtocol': 'tcp',
                                  'destination': '/mesos/10.128.10.240:80',
                                  'pool': '/mesos/server-app_10.128.10.240_80',
                                  'sourceAddressTranslation':
                                  {'type': 'automap'},
                                  'profiles': [{'partition': 'Common',
                                                'name': u'clientssl'},
                                               {'partition': 'Common',
                                                'name': 'http'}]}
        virtual = self.create_mock_virtual('server-app_10.128.10.240_80',
                                           **virtual_data_unchanged)

        # Create mock Pool Members
        member_data_unchanged = {'state': 'user-up', 'session': 'user-enabled'}
        member = self.create_mock_pool_member('10.141.141.10:31132',
                                              **member_data_unchanged)
        member = self.create_mock_pool_member('10.141.141.10:31615',
                                              **member_data_unchanged)
        member = self.create_mock_pool_member('10.141.141.10:31982',
                                              **member_data_unchanged)
        member = self.create_mock_pool_member('10.141.141.10:31972',
                                              **member_data_unchanged)

        # Create a mock Healthcheck
        health_data_unchanged = {
            'interval': 20,
            'timeout': 61,
            'send': 'GET /'
        }
        healthcheck = self.create_mock_healthcheck(
            'server-app_10.128.10.240_80', **health_data_unchanged)

        # Pool, Virtual, Member, and Healthcheck are not modified
        self.bigip.regenerate_config_f5(apps)
        self.assertFalse(pool.modify.called)
        self.assertFalse(virtual.modify.called)
        self.assertFalse(virtual.profiles_s.profiles.create.called)
        self.assertFalse(member.modify.called)
        self.assertFalse(healthcheck.modify.called)

        # Pool is modified
        pool_data_changed = {
            'balance': 'least-connections',
            'monitor': 'server-app_10.128.10.240_8080'
        }
        for key in pool_data_changed:
            data = pool_data_unchanged
            # Change one thing
            data[key] = pool_data_changed[key]
            pool = self.create_mock_pool('server-app_10.128.10.240_80', **data)
            self.bigip.regenerate_config_f5(apps)
            self.assertTrue(pool.modify.called)

        # Virtual is modified
        virtual_data_changed = {
            'enabled': False,
            'disabled': True,
            'ipProtocol': 'udp',
            'destination': '/Common/10.128.10.240:80',
            'pool': '/Common/server-app_10.128.10.240_80',
            'sourceAddressTranslation': {'type': 'snat'}
        }
        for key in virtual_data_changed:
            data = virtual_data_unchanged
            # Change one thing
            data[key] = virtual_data_changed[key]
            virtual = self.create_mock_virtual('server-app_10.128.10.240_80',
                                               **data)
            self.bigip.regenerate_config_f5(apps)
            self.assertTrue(virtual.modify.called)

        # Member is modified
        member_data_changed = {
            'state': 'user-down',
            'session': 'user-disabled'
        }
        for key in member_data_changed:
            data = member_data_unchanged
            # Change one thing
            data[key] = member_data_changed[key]
            member = self.create_mock_pool_member('10.141.141.10:31132',
                                                  **data)
            self.bigip.regenerate_config_f5(apps)
            self.assertTrue(member.modify.called)

        # Healthcheck is modified
        health_data_changed = {
            'interval': 10,
            'timeout': 30,
            'send': 'GET /mypath'
        }
        for key in health_data_changed:
            data = health_data_unchanged
            # Change one thing
            data[key] = health_data_changed[key]
            healthcheck = self.create_mock_healthcheck(
                'server-app_10.128.10.240_80', **data)
            self.bigip.regenerate_config_f5(apps)
            self.assertTrue(healthcheck.modify.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)


class KubernetesTest(BigIPTest):
    """Kubernetes/Big-IP configuration tests.

    Test BIG-IP configuration given various Kubernetes states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        super(KubernetesTest, self).setUp('kubernetes', 'velcro')

    def test_svc_create(self,
                        cloud_state='tests/kubernetes_one_svc_two_nodes.json',
                        bigip_state='tests/bigip_test_blank.json',
                        hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service created."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data['services'])

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

    def test_svc_scaled_down(
            self,
            cloud_state='tests/kubernetes_one_svc_one_node.json',
            bigip_state='tests/bigip_test_one_svc_two_nodes.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service scaled down."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data['services'])

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_delete.called)
        self.assertEqual(self.bigip.member_delete.call_count, 1)

    def test_svc_scaled_up(
            self,
            cloud_state='tests/kubernetes_one_svc_four_nodes.json',
            bigip_state='tests/bigip_test_one_svc_two_nodes.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service scaled up."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data['services'])

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

    def test_new_iapp(self, cloud_state='tests/kubernetes_one_iapp.json',
                      bigip_state='tests/bigip_test_blank.json',
                      hm_state='tests/bigip_test_blank.json'):
        """Test: Start Kubernetes app with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data['services'])

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertTrue(self.bigip.iapp_create.called)

        self.assertEquals(self.bigip.iapp_create.call_count, 1)

        expected_name = 'server-app2_iapp_10000'
        self.assertEquals(self.bigip.iapp_create.call_args_list[0][0][1],
                          expected_name)

    def test_delete_iapp(self, cloud_state='tests/kubernetes_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Kubernetes app associated with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_list)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data['services'])

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)
        self.assertFalse(self.bigip.member_delete.called)

        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.iapp_delete.called)
        self.assertEquals(self.bigip.iapp_delete.call_count, 1)

        expected_name = 'server-app2_iapp_10000_vs'
        self.assertEquals(self.bigip.iapp_delete.call_args_list[0][0][1],
                          expected_name)


if __name__ == '__main__':
    unittest.main()
