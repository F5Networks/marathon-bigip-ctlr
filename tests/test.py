import unittest
import json
from mock import Mock
from f5_marathon_lb import *
from _f5 import MarathonBigIP
from StringIO import StringIO

class ArgTest(unittest.TestCase):
    """
    Test f5-marathon-lb arg parsing
    """

    _args_app_name = ['f5-marathon-lb']
    _args_mandatory = ['--marathon', 'http://10.0.0.10:8080',
                       '--partition', 'mesos',
                       '--hostname', '10.10.1.145',
                       '--username', 'admin',
                       '--password', 'default']

    def setUp(self):
        self.out = StringIO()
        #sys.stdout = self.out
        sys.stderr = self.out

    def tearDown(self):
        pass

    def test_no_args(self):
        sys.argv[0:] = self._args_app_name
        self.assertRaises(SystemExit, parse_args)

        expected = '''usage: f5-marathon-lb [-h] [--longhelp] [--marathon MARATHON [MARATHON ...]]
                      [--listening LISTENING] [--callback-url CALLBACK_URL]
                      [--hostname HOSTNAME] [--username USERNAME]
                      [--password PASSWORD] [--partition PARTITION] [--sse]
                      [--health-check] [--syslog-socket SYSLOG_SOCKET]
                      [--log-format LOG_FORMAT]
                      [--marathon-auth-credential-file MARATHON_AUTH_CREDENTIAL_FILE]
f5-marathon-lb: error: argument --marathon/-m is required
'''
        output = self.out.getvalue()
        self.assertEqual(output, expected)

    def test_all_mandatory_args(self):
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
        self.assertEqual(args.syslog_socket, '/var/run/syslog')
        self.assertEqual(args.log_format,
                         '%(asctime)s %(name)s: %(levelname) -8s: %(message)s')
        self.assertEqual(args.listening, None)
        self.assertEqual(args.callback_url, None)
        self.assertEqual(args.marathon_auth_credential_file, None)

    def test_conflicting_args(self):
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            +['--listening', '-sse']
        self.assertRaises(SystemExit, parse_args)

    def test_callback_arg(self):
        url = 'http://marathon:8080'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--callback-url', url]
        args = parse_args()
        self.assertEqual(args.callback_url, url)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-u', url]
        args = parse_args()
        self.assertEqual(args.callback_url, url)

    def test_listening_arg(self):
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
        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['--sse']
        args = parse_args()
        self.assertEqual(args.sse, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-s']
        args = parse_args()
        self.assertEqual(args.sse, True)

    def test_health_check_arg(self):
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--health-check']
        args = parse_args()
        self.assertEqual(args.health_check, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-H']
        args = parse_args()
        self.assertEqual(args.health_check, True)

    def test_syslog_socket_arg(self):
        log_file = '/var/run/mylog'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--syslog-socket', log_file]
        args = parse_args()
        self.assertEqual(args.syslog_socket, log_file)

    def test_log_format_arg(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-format', log_format]
        args = parse_args()
        self.assertEqual(args.log_format, log_format)

    def test_marathon_cred_arg(self):
        auth_file = '/tmp/auth'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-auth-credential-file', auth_file]
        args = parse_args()
        self.assertEqual(args.marathon_auth_credential_file, auth_file)



class BigIPTest(unittest.TestCase):
    """
    Test BIG-IP configuration given various Marathon states and existing
    BIG-IP states
    """

    def mock_get_pool_member_list(self, partition, pool):
        try:
            return self.bigip_data[pool]
        except KeyError:
            return []

    def mock_get_healthcheck_list(self, partition):
	return self.hm_data

    def read_test_vectors(self, marathon_state, bigip_state, hm_state):
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

        for app, service in zip(apps, services):
            labels = app['labels']
            if labels.get('F5_0_BIND_ADDR') != None:
	        self.assertEqual(labels.get('F5_PARTITION'), service.partition)
	        self.assertEqual(labels.get('F5_0_BIND_ADDR'), service.bindAddr)
	        self.assertEqual(labels.get('F5_0_MODE'), service.mode)
	        self.assertEqual(int(labels.get('F5_0_PORT')), service.servicePort)

    def setUp(self):
        self.bigip = MarathonBigIP('1.2.3.4', 'admin', 'default', ['mesos'])

	self.bigip.get_pool_member_list = \
            Mock(side_effect=self.mock_get_pool_member_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)

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

    def tearDown(self):
        pass

    def test_no_change(self, marathon_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_no_change.json',
                       hm_state='tests/bigip_test_two_monitors.json'):

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

	self.assertFalse(self.bigip.virtual_create.called)
	self.assertFalse(self.bigip.pool_create.called)
	self.assertFalse(self.bigip.healthcheck_create.called)
	self.assertFalse(self.bigip.member_create.called)
	self.assertFalse(self.bigip.member_delete.called)

	self.assertTrue(self.bigip.virtual_delete.called)
	self.assertTrue(self.bigip.pool_delete.called)
	self.assertTrue(self.bigip.healthcheck_delete.called)
        self.assertEqual(self.bigip.virtual_delete.call_count, 1)
        self.assertEqual(self.bigip.pool_delete.call_count, 1)
        self.assertEqual(self.bigip.healthcheck_delete.call_count, 1)

    def test_app_scaled_up(self, marathon_state='tests/marathon_app_scaled.json',
                           bigip_state='tests/bigip_test_app_scaled_up.json',
                           hm_state='tests/bigip_test_two_monitors.json'):

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

	self.assertFalse(self.bigip.virtual_create.called)
	self.assertFalse(self.bigip.virtual_delete.called)
	self.assertFalse(self.bigip.pool_create.called)
	self.assertFalse(self.bigip.pool_delete.called)
	self.assertFalse(self.bigip.healthcheck_delete.called)
	self.assertFalse(self.bigip.healthcheck_create.called)
	self.assertFalse(self.bigip.member_delete.called)

	self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

    def test_app_scaled_down(self, marathon_state='tests/marathon_two_apps.json',
                             bigip_state='tests/bigip_test_app_scaled_down.json',
                             hm_state='tests/bigip_test_two_monitors.json'):

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

	self.assertFalse(self.bigip.virtual_create.called)
	self.assertFalse(self.bigip.virtual_delete.called)
	self.assertFalse(self.bigip.pool_create.called)
	self.assertFalse(self.bigip.pool_delete.called)
	self.assertFalse(self.bigip.healthcheck_delete.called)
	self.assertFalse(self.bigip.healthcheck_create.called)
	self.assertFalse(self.bigip.member_create.called)

	self.assertTrue(self.bigip.member_delete.called)
        self.assertEqual(self.bigip.member_delete.call_count, 2)

    def test_start_app_with_health_monitor_tcp(self,
                       marathon_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_app_started_with_tcp.json',
                       hm_state='tests/bigip_test_one_http_monitor.json'):

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

	self.assertFalse(self.bigip.virtual_delete.called)
	self.assertFalse(self.bigip.pool_delete.called)
	self.assertFalse(self.bigip.healthcheck_delete.called)
	self.assertFalse(self.bigip.member_delete.called)

	self.assertTrue(self.bigip.virtual_create.called)
	self.assertTrue(self.bigip.pool_create.called)
	self.assertTrue(self.bigip.healthcheck_create.called)
	self.assertTrue(self.bigip.member_create.called)
	self.assertEquals(self.bigip.virtual_create.call_count, 1)
	self.assertEquals(self.bigip.pool_create.call_count, 1)
	self.assertEquals(self.bigip.member_create.call_count, 4)
	self.assertEquals(self.bigip.healthcheck_create.call_count, 1)

    def test_start_app_with_health_monitor_http(self,
                      marathon_state='tests/marathon_two_apps.json',
                      bigip_state='tests/bigip_test_app_started_with_http.json',
                      hm_state='tests/bigip_test_one_tcp_monitor.json'):

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

	self.assertFalse(self.bigip.virtual_delete.called)
	self.assertFalse(self.bigip.pool_delete.called)
	self.assertFalse(self.bigip.healthcheck_delete.called)
	self.assertFalse(self.bigip.member_delete.called)

	self.assertTrue(self.bigip.virtual_create.called)
	self.assertTrue(self.bigip.pool_create.called)
	self.assertTrue(self.bigip.healthcheck_create.called)
	self.assertTrue(self.bigip.member_create.called)
	self.assertEquals(self.bigip.virtual_create.call_count, 1)
	self.assertEquals(self.bigip.pool_create.call_count, 1)
	self.assertEquals(self.bigip.member_create.call_count, 2)
	self.assertEquals(self.bigip.healthcheck_create.call_count, 1)

    def test_start_app_with_health_monitor_none(self,
                             marathon_state='tests/marathon_app_no_hm.json',
                             bigip_state='tests/bigip_test_one_app.json',
                             hm_state='tests/bigip_test_one_http_monitor.json'):

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

	self.assertFalse(self.bigip.virtual_delete.called)
	self.assertFalse(self.bigip.pool_delete.called)
	self.assertFalse(self.bigip.healthcheck_delete.called)
	self.assertFalse(self.bigip.member_delete.called)
	self.assertFalse(self.bigip.healthcheck_create.called)

	self.assertTrue(self.bigip.virtual_create.called)
	self.assertTrue(self.bigip.pool_create.called)
	self.assertTrue(self.bigip.member_create.called)
	self.assertEquals(self.bigip.virtual_create.call_count, 1)
	self.assertEquals(self.bigip.pool_create.call_count, 1)
	self.assertEquals(self.bigip.member_create.call_count, 2)

    def test_bigip_new(self, marathon_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_blank.json',
                       hm_state='tests/bigip_test_blank.json'):

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

	self.assertFalse(self.bigip.virtual_delete.called)
	self.assertFalse(self.bigip.pool_delete.called)
	self.assertFalse(self.bigip.healthcheck_delete.called)
	self.assertFalse(self.bigip.member_delete.called)

	self.assertTrue(self.bigip.virtual_create.called)
	self.assertTrue(self.bigip.pool_create.called)
	self.assertTrue(self.bigip.member_create.called)
	self.assertTrue(self.bigip.healthcheck_create.called)
	self.assertEquals(self.bigip.virtual_create.call_count, 2)
	self.assertEquals(self.bigip.pool_create.call_count, 2)
	self.assertEquals(self.bigip.member_create.call_count, 6)
	self.assertEquals(self.bigip.healthcheck_create.call_count, 2)

if __name__ == '__main__':
    unittest.main()
