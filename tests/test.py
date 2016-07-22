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
from mock import Mock
from mock import patch
from f5_marathon_lb import get_apps, parse_args
from f5.bigip import BigIP
from _f5 import MarathonBigIP
from StringIO import StringIO


class ArgTest(unittest.TestCase):
    """Test f5-marathon-lb arg parsing."""

    _args_app_name = ['f5-marathon-lb']
    _args_mandatory = ['--marathon', 'http://10.0.0.10:8080',
                       '--partition', 'mesos',
                       '--hostname', '10.10.1.145',
                       '--username', 'admin',
                       '--password', 'default']

    def setUp(self):
        """Test suite set up."""
        self.out = StringIO()
        sys.stderr = self.out

    def tearDown(self):
        """Test suite tear down."""
        pass

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

    def test_conflicting_args(self):
        """Test: Mutually-exclusive command-line args."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--listening', '-sse']
        self.assertRaises(SystemExit, parse_args)

    def test_callback_arg(self):
        """Test: 'Callback URL' command-line arg."""
        url = 'http://marathon:8080'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--callback-url', url]
        args = parse_args()
        self.assertEqual(args.callback_url, url)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-u', url]
        args = parse_args()
        self.assertEqual(args.callback_url, url)

    def test_listening_arg(self):
        """Test: 'Listening' command-line arg."""
        listen_addr = '192.168.10.50'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--listening', listen_addr]
        args = parse_args()
        self.assertEqual(args.listening, listen_addr)

        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['-l', listen_addr]
        args = parse_args()
        self.assertEqual(args.listening, listen_addr)

    def test_sse_arg(self):
        """Test: 'SSE' command-line arg."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['--sse']
        args = parse_args()
        self.assertEqual(args.sse, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-s']
        args = parse_args()
        self.assertEqual(args.sse, True)

    def test_health_check_arg(self):
        """Test: 'Health Check' command-line arg."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--health-check']
        args = parse_args()
        self.assertEqual(args.health_check, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-H']
        args = parse_args()
        self.assertEqual(args.health_check, True)

    def test_syslog_socket_arg(self):
        """Test: 'Syslog socket' command-line arg."""
        log_file = '/var/run/mylog'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--syslog-socket', log_file]
        args = parse_args()
        self.assertEqual(args.syslog_socket, log_file)

    def test_log_format_arg(self):
        """Test: 'Log format' command-line arg."""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-format', log_format]
        args = parse_args()
        self.assertEqual(args.log_format, log_format)

    def test_marathon_cred_arg(self):
        """Test: 'Marathon credentials' command-line arg."""
        auth_file = '/tmp/auth'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-auth-credential-file', auth_file]
        args = parse_args()
        self.assertEqual(args.marathon_auth_credential_file, auth_file)

    def test_timeout_arg(self):
        """Test: 'SSE timeout' command-line arg."""
        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--sse-timeout', str(timeout)]
        args = parse_args()
        self.assertEqual(args.sse_timeout, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = parse_args()
        self.assertEqual(args.sse_timeout, 30)


class BigIPTest(unittest.TestCase):
    """BIG-IP configuration tests.

    Test BIG-IP configuration given various Marathon states and existing
    BIG-IP states
    """

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

    def read_test_vectors(self, marathon_state, bigip_state, hm_state):
        """Read test vectors for Marathon, BIG-IP, and Health Monitor state."""
        # Read the Marathon state
        with open(marathon_state) as json_data:
            self.marathon_data = json.load(json_data)

        # Read the BIG-IP state
        with open(bigip_state) as json_data:
            self.bigip_data = json.load(json_data)

        with open(hm_state) as json_data:
            self.hm_data = json.load(json_data)

        self.bigip.get_pool_list = Mock(return_value=self.bigip_data.keys())
        self.bigip.get_virtual_list = Mock(return_value=self.bigip_data.keys())

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

    def setUp(self):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        with patch.object(BigIP, '_get_tmos_version'):
            self.bigip = MarathonBigIP('1.2.3.4', 'admin', 'default',
                                       ['mesos'])

        self.bigip.get_pool_member_list = \
            Mock(side_effect=self.mock_get_pool_member_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)
        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_empty_list)

        self.bigip.pool_create = Mock()
        self.bigip.pool_delete = Mock()
        self.bigip.pool_update = Mock()

        self.bigip.healthcheck_create = Mock()
        self.bigip.healthcheck_delete = Mock()
        self.bigip.healthcheck_update = Mock()

        self.bigip.virtual_create = Mock()
        self.bigip.virtual_delete = Mock()
        self.bigip.virtual_update = Mock()

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

    def test_exceptions(self, marathon_state='tests/marathon_two_apps.json',
                        bigip_state='tests/bigip_test_no_change.json',
                        hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Exception handling."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)
        apps = get_apps(self.marathon_data, True)

        # Successful configuration (no retry)
        self.assertFalse(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config_f5 = Mock(side_effect=self.raiseSDKError)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config_f5 = \
            Mock(side_effect=self.raiseConnectionError)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config_f5 = \
            Mock(side_effect=self.raiseBigIPInvalidURL)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # BIG-IP related exception (retry)
        self.bigip._apply_config_f5 = \
            Mock(side_effect=self.raiseBigiControlUnexpectedHTTPError)
        self.assertTrue(self.bigip.regenerate_config_f5(apps))

        # Other exception types are raised
        self.bigip._apply_config_f5 = Mock(side_effect=self.raiseTypeError)
        self.assertRaises(TypeError, self.bigip.regenerate_config_f5, apps)

    def test_no_change(self, marathon_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_no_change.json',
                       hm_state='tests/bigip_test_two_monitors.json'):
        """Test: No Marathon state change."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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

    def test_app_destroyed(self, marathon_state='tests/marathon_one_app.json',
                           bigip_state='tests/bigip_test_app_destroyed.json',
                           hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app destroyed."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
                           marathon_state='tests/marathon_app_scaled.json',
                           bigip_state='tests/bigip_test_app_scaled_up.json',
                           hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app destroyed."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_scaled_down.json',
            hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app scaled down."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_started_with_tcp.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Start Marathon app with a TCP health monitor."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_started_with_http.json',
            hm_state='tests/bigip_test_one_tcp_monitor.json'):
        """Test: Start Marathon app with an HTTP health monitor."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_app_no_hm.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Start Marathon app with no health monitor configured."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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

    def test_bigip_new(self, marathon_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_blank.json',
                       hm_state='tests/bigip_test_blank.json'):
        """Test: BIG-IP with no resources previously configured."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_one_app_no_port_label.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app using default Marathon service port."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_one_app_two_service_ports.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app with two service ports."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            self.bigip.healthcheck_create.call_args_list[0][0][1],
            expected_name1)
        self.assertEquals(
            self.bigip.healthcheck_create.call_args_list[1][0][1],
            expected_name2)

    def start_two_apps_with_two_partitions(
            self, partitions, expected_name1, expected_name2,
            marathon_state='tests/marathon_two_apps_two_partitions.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start two Marathon apps on two partitions."""
        # Setup two partitions
        self.bigip._partitions = partitions

        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            self.assertEquals(
                self.bigip.pool_create.call_args_list[0][0][1],
                expected_name1)
            self.assertEquals(
                self.bigip.healthcheck_create.call_args_list[0][0][1],
                expected_name1)

        if expected_name2:
            create_call_count += 1
            self.assertEquals(
                self.bigip.virtual_create.call_args_list[
                    create_call_count-1][0][1], expected_name2)
            self.assertEquals(
                self.bigip.pool_create.call_args_list[
                    create_call_count-1][0][1], expected_name2)
            self.assertEquals(
                self.bigip.healthcheck_create.call_args_list[
                    create_call_count-1][0][1], expected_name2)

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
            marathon_state='tests/'
            'marathon_app_with_one_unconfig_service_port.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon apps with one uncofigured service port."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            self.bigip.healthcheck_create.call_args_list[0][0][1],
            expected_name1)
        self.assertEquals(
            self.bigip.healthcheck_create.call_args_list[1][0][1],
            expected_name2)

    def test_destroy_all_apps(
            self,
            marathon_state='tests/marathon_no_apps.json',
            bigip_state='tests/bigip_test_no_change.json',
            hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Destroy all Marathon apps."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_one_app_zero_instances.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Suspend Marathon app."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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

    def test_new_iapp(self, marathon_state='tests/marathon_one_iapp.json',
                      bigip_state='tests/bigip_test_blank.json',
                      hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app with iApp."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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

    def test_delete_iapp(self, marathon_state='tests/marathon_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Marathon app associated with iApp."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_list)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.marathon_data, apps)

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
            marathon_state='tests/marathon_one_app_https.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app that uses HTTPS."""
        # Get the test data
        self.read_test_vectors(marathon_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = get_apps(self.marathon_data, True)
        self.bigip.regenerate_config_f5(apps)

        https_app_count = 0
        for service, app in zip(self.marathon_data, apps):
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

if __name__ == '__main__':
    unittest.main()
