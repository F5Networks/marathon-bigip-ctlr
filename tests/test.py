# Copyright (c) 2017,2018, F5 Networks, Inc.
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

"""Controller Unit Tests.

Units tests for testing command-line args, Marathon state parsing, and
BIG-IP resource management.

"""
import unittest
import logging
import json
import sys
import requests
import os
import copy
import time
from sseclient import Event
from mock import Mock, mock_open, patch
from common import DCOSAuth, get_marathon_auth_params, setup_logging
from f5_cccl.utils.mgmt import ManagementRoot
from f5_cccl.utils.mgmt import mgmt_root
from f5_cccl.api import F5CloudServiceManager
from f5_cccl.exceptions import F5CcclValidationError
from f5_cccl.exceptions import F5CcclSchemaError
from StringIO import StringIO
ctlr = __import__('marathon-bigip-ctlr')

# Marathon app data
marathon_test_data = [
    'tests/marathon_one_app_in_subdir.json',
    'tests/marathon_invalid_apps.json',
    'tests/marathon_two_apps.json',
    'tests/marathon_app_no_hm.json',
    'tests/marathon_one_app_missing_data.json',
    'tests/marathon_one_app_no_port_label.json',
    'tests/marathon_one_app_two_service_ports.json',
    'tests/marathon_app_with_one_unconfig_service_port.json',
    'tests/marathon_no_apps.json',
    'tests/marathon_one_app_zero_instances.json',
    'tests/marathon_one_app_https.json',
    'tests/marathon_one_app_two_health_checks.json',
    'tests/marathon_one_app_pool_only.json',
    'tests/marathon_two_apps_v152.json'
]

args_env = ['F5_CC_SYSLOG_SOCKET',
            'F5_CC_LOG_FORMAT',
            'F5_CC_MARATHON_AUTH',
            'MARATHON_URL',
            'F5_CC_LISTENING_ADDR',
            'F5_CC_CALLBACK_URL',
            'F5_CC_BIGIP_HOSTNAME',
            'F5_CC_BIGIP_USERNAME',
            'F5_CC_BIGIP_PASSWORD',
            'F5_CC_PARTITIONS',
            'F5_CC_USE_HEALTHCHECK',
            'F5_CC_SSE_TIMEOUT',
            'F5_CC_MARATHON_CA_CERT',
            'F5_CC_DCOS_AUTH_CREDENTIALS',
            'F5_CC_DCOS_AUTH_TOKEN']


version_data = {'version': '1.1.0', 'build': 'abcdef'}


class ArgTest(unittest.TestCase):
    """Test marathon-bigip-ctlr arg parsing."""

    _args_app_name = ['marathon-bigip-ctlr.py']
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
        sys.stdout = self.out

    def tearDown(self):
        """Test suite tear down."""
        # Clear env vars
        for arg in args_env:
            os.environ.pop(arg, None)

    def test_no_args(self):
        """Test: No command-line args."""
        sys.argv[0:] = self._args_app_name
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        expected = \
            "usage: marathon-bigip-ctlr.py [-h] [--longhelp]\n" \
            """                              [--marathon MARATHON [MARATHON ...]]
                              [--hostname HOSTNAME] [--username USERNAME]
                              [--password PASSWORD] [--partition PARTITION]
                              [--health-check]
                              [--marathon-ca-cert MARATHON_CA_CERT]
                              [--sse-timeout SSE_TIMEOUT]
                              [--verify-interval VERIFY_INTERVAL] [--version]
                              [--log-format LOG_FORMAT]
                              [--log-level LOG_LEVEL]
                              [--marathon-auth-credential-file""" \
        """ MARATHON_AUTH_CREDENTIAL_FILE]\n \
                             [--dcos-auth-credentials DCOS_AUTH_CREDENTIALS]
                              [--dcos-auth-token DCOS_AUTH_TOKEN]\n""" \
        "marathon-bigip-ctlr.py: error: argument --marathon/-m is required\n"

        output = self.out.getvalue()
        self.assertEqual(output, expected)

    def test_all_mandatory_args(self):
        """Test: All mandatory command-line args."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.marathon, ['http://10.0.0.10:8080'])
        self.assertEqual(args.partition, ['mesos'])
        self.assertEqual(args.hostname, 'https://10.10.1.145')
        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.password, 'default')
        # default arg values
        self.assertEqual(args.health_check, False)
        self.assertEqual(args.log_format,
                         '%(asctime)s %(name)s: %(levelname) -8s: %(message)s')
        self.assertEqual(args.marathon_auth_credential_file, None)

    def test_all_mandatory_args_from_env(self):
        """Test: All mandatory command-line args."""
        sys.argv[0:] = self._args_app_name
        os.environ['MARATHON_URL'] = 'http://10.0.0.10:8080'
        os.environ['F5_CC_PARTITIONS'] = '[mesos, mesos2]'
        os.environ['F5_CC_BIGIP_HOSTNAME'] = '10.10.1.145'
        os.environ['F5_CC_BIGIP_USERNAME'] = 'admin'
        os.environ['F5_CC_BIGIP_PASSWORD'] = 'default'
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.marathon, ['http://10.0.0.10:8080'])
        self.assertEqual(args.partition, ['mesos', 'mesos2'])
        self.assertEqual(args.hostname, 'https://10.10.1.145')
        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.password, 'default')

    def test_long_help(self):
        """Test: Long help."""
        args = ['--longhelp']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        expected = "marathon-bigip-ctlr.\n\nmarathon-bigip-ctlr is a service" \
            " discovery and load balancing tool\nfor Marathon to configure" \
            " an F5 BIG-IP. It reads the Marathon task information\nand" \
            " dynamically generates BIG-IP configuration details.\n\nTo" \
            " gather the task information, marathon-bigip-ctlr needs to know" \
            " where\nto find Marathon. The service configuration details are" \
            " stored in labels.\n\nEvery service port in Marathon can be" \
            " configured independently.\n\n### Configuration\nService" \
            " configuration lives in Marathon via labels.\nmarathon-bigip-" \
            "ctlr just needs to know where to find Marathon.\n\n"
        output = self.out.getvalue()
        self.assertEqual(output, expected)

    def test_no_username(self):
        """Test: No username arg."""
        # Invalid scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', 'scheme://10.10.1.145',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

    def test_no_password(self):
        """Test: No password arg."""
        # Invalid scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--username', 'admin',
                '--hostname', 'scheme://10.10.1.145']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

    def test_hostname_arg(self):
        """Test: Hostname arg."""
        # No hostname
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        # Invalid scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', 'scheme://10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        # No scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.host, '10.10.1.145')
        self.assertEqual(args.port, 443)

        # No port
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', 'https://10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.host, '10.10.1.145')
        self.assertEqual(args.port, 443)

        # Given port
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', 'https://10.10.1.145:555',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.host, '10.10.1.145')
        self.assertEqual(args.port, 555)

        # Invalid path
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', 'https://10.10.1.145/path/not/allowed',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

    def test_partition_arg(self):
        """Test: Wildcard partition arg."""
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', 'test',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.partition, ['test'])

        # No partition specified
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        # test via env var
        partitions_env = 'test'
        sys.argv[0:] = self._args_app_name + self._args_without_partition
        os.environ['F5_CC_PARTITIONS'] = partitions_env
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.partition, ['test'])

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
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.partition, ['mesos-1', 'mesos-2', 'mesos-3'])

        # test via env var
        partitions_env = '[mesos7, mesos8]'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_PARTITIONS'] = partitions_env
        args = ctlr.parse_args(version_data)
        # command-line overrides env var
        self.assertEqual(args.partition, ['mesos'])

        sys.argv[0:] = self._args_app_name + self._args_without_partition
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.partition, ['mesos7', 'mesos8'])

    def test_health_check_arg(self):
        """Test: 'Health Check' arg."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.health_check, False)
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--health-check']
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.health_check, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-H']
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.health_check, True)

        # test via env var
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.health_check, False)
        os.environ['F5_CC_USE_HEALTHCHECK'] = 'True'
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.health_check, True)

    def test_log_format_arg(self):
        """Test: 'Log format' arg."""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-format', log_format]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.log_format, log_format)

        # test via env var
        env_log_format = '%(asctime)s - %(message)s'
        os.environ['F5_CC_LOG_FORMAT'] = env_log_format
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.log_format, env_log_format)

    def test_log_level_arg(self):
        """Test: 'Log level' arg."""
        # Test all valid levels
        levels = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
        for level in levels:
            sys.argv[0:] = self._args_app_name + self._args_mandatory + \
                ['--log-level', level]
            args = ctlr.parse_args(version_data)
            self.assertEqual(args.log_level, getattr(logging, level))

        # Test default
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.log_level, getattr(logging, 'INFO'))

        # Test invalid
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-level', 'INCONCEIVABLE']
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        # Test invalid (via env)
        os.environ['F5_CC_LOG_LEVEL'] = 'INCONCEIVABLE'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        # Test all valid levels (via env)
        for level in levels:
            os.environ['F5_CC_LOG_LEVEL'] = level
            sys.argv[0:] = self._args_app_name + self._args_mandatory
            args = ctlr.parse_args(version_data)
            self.assertEqual(args.log_level, getattr(logging, level))

    def test_marathon_cred_arg(self):
        """Test: 'Marathon credentials' arg."""
        auth_file = '/tmp/auth'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-auth-credential-file', auth_file]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.marathon_auth_credential_file, auth_file)

        # test via env var
        env_auth_file = '/tmp/auth_from_env'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_MARATHON_AUTH'] = env_auth_file
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.marathon_auth_credential_file, env_auth_file)

        # Test auth file
        # Correct user:password
        with patch('__builtin__.open',
                   mock_open(read_data="samiam:greeneggs")):
            self.assertEqual(get_marathon_auth_params(args),
                             ('samiam', 'greeneggs'))

        # No password
        with patch('__builtin__.open', mock_open(read_data="samiam")):
            self.assertRaises(SystemExit, get_marathon_auth_params, args)

        # Empty file
        with patch('__builtin__.open', mock_open(read_data='\r\n')):
            self.assertEqual(get_marathon_auth_params(args), None)

    def test_timeout_arg(self):
        """Test: 'SSE timeout' arg."""
        # Invalid timeout
        timeout = 0
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--sse-timeout', str(timeout)]
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--sse-timeout', str(timeout)]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.sse_timeout, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.sse_timeout, 30)

        # test via env var
        os.environ['F5_CC_SSE_TIMEOUT'] = str(timeout)
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.sse_timeout, timeout)

    def test_verify_interval_arg(self):
        """Test: 'Verify Interval' arg."""
        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--verify-interval', str(timeout)]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.verify_interval, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.verify_interval, 30)

        # test via env var
        os.environ['F5_CC_VERIFY_INTERVAL'] = str(timeout)
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.verify_interval, timeout)

        # Invalid interval
        timeout = 0
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--verify-interval', str(timeout)]
        self.assertRaises(SystemExit, ctlr.parse_args, version_data)

    def test_marathon_ca_cert_arg(self):
        """Test: 'Marathon CA Cert' arg."""
        cert = "/this/is/a/path/to/a/cert.crt"

        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-ca-cert', cert]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.marathon_ca_cert, cert)

        # test via env var
        env_cert = 'It will now be a different value'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_MARATHON_CA_CERT'] = env_cert
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.marathon_ca_cert, env_cert)

    def test_auth_credentials_arg(self):
        """Test: 'dcos-auth-credentials' arg."""
        creds = "{ \"scheme\": \"RS256\", \"uid\": \"mlb-principal\", " \
            "\"private_key\": " \
            "\"-----BEGIN PRIVATE KEY-----\\n" \
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCul4DUy56pkSq/"\
            "QbawK0IEuH2MBiDm1nVDV95WWRs+LSNWYWhZIa5B2V0Zwa+OKXsZFU/L5GlLo+mX"\
            "FitRju70t2SwJxOQi1L3oyhWfrOr45lviTF1YWt52ca8VWgEIHcdPGXl5PtlI0VB"\
            "JQOPESUI0kr/FJ/28ZIrNa5NdiVWPHQdB5Kec7q2iy418oPVzNeWsoIiHl9A7Dt+"\
            "BMQQqVAsZD4f26wSjMSX6AiryQ8hOLfDMdaiR06KY3cg7PkswfIjsKJ8hR7HO6hl"\
            "GqXtpo1V05N6nlcOJuWEe7ejBlqWyeZ+Y+oInibhbxNeN1KVPTB9WLWlqa/vnEp0"\
            "gHX2RkBXAgMBAAECggEAOiyXK9BxHJUXRkUSJ18yjzod8yMzoVcCGZ9UoTbtoekO"\
            "ZkDssQ5M7voLUIK+CUN/FduJDCoef6qtMb+cTX+v1XCqJxvOJBKYYZVG4pMzMOoU"\
            "fRqclT0Rv7c1xhk7IGzk46P1XAXRUmDPOaaoqeoPigHwJVBtAK57gtRPMNZWGIZd"\
            "C+5EJ8w0GoZ04wZ2geVVHfyEExP2VVm0pfe7MTJzHLkuU21BvlUcaCqiqKwswg8m"\
            "cy5O1RwKpKXH5zW1Dks578kIayQiFxaYUMskDw0wD52H8JgCB305xBjl2/eH+5xD"\
            "dji9ZidT+07ylcHW9ELvOTBnDMH7mmadENScMmyt4QKBgQDhFmP9kojgk7DFGTr7"\
            "KJ4EB56C2Y4Y050MSRfcPnsqov+Fis6yOn/Z58VTZ/bx0r7CV1FxNzzao2DJEhM3"\
            "qRvNgK7oHPCBC62Af8yAvUmZaOLJf1uGqL9/3YJZ8TRPcTWRGY+vchPT8oJF537D"\
            "fYNIXGKIvurjfmT/5sy+Jb6gZwKBgQDGkco7j/ysLC2kAQXHuENjhy5TrAXgrW9U"\
            "WYhXhU22sQy21w6sf7q6cZd5MQfHQV70QcUCtCX4VOAjCE1I/+BtoxnUHZKD1Vye"\
            "2MGM5uoKXbkG3tUx0m1Hdg6Y5gH3+khdwjC9wqtzwzi/MzaxRsLVi8a6jRjyKb+p"\
            "eKOiKU+qkQKBgGFOeLOqoZnUv1q16ZWinY1IbfJLcu6wrPgesT35lO19wdFNjMXo"\
            "HFVrqRbBnzQz01vYu9Ch/KDYeIL0WXJ6nRZeRz75I8/l6H/gv9v3+NVlToWllT/F"\
            "u+PfMvcHG4IsgufTkRZbzs6VzFPEHD0PCa5CoiZTwt/OSIOIl4KsdpiJAoGATO6J"\
            "CqCThWUsXaEjyyghu7rRAQvhzxWCz4xMnZQA8uoPgfs6LSzjfH6r8AFGATXbgwjE"\
            "OnLvTxIbMJdz0feIzRFm3V6DuF3+n3BdNKj2PgPnvriworfjLM+ZgjWCx7+JMAIf"\
            "fjWg1Z3qK3G9G9vNeozH9tjZtGDmZ9NcmmQlAHECgYEAyZjthPRiAYhHcmA4I+ND"\
            "1uZ3/9gvpQBJtrtRbwBU3mqyDkhhKkLrJmdB9Z8gqKAKAvhJ713zs5YAwOhoTPx0"\
            "6/IC/KSKy+ZOtb3U5vpnwO0tkqXuc9a455+XBHfZw3WhXc1WOdUafUNyI5tro1Md"\
            "0h5SITv/2nj9tyM443CpprM=\\n" \
            "-----END PRIVATE KEY-----\"," \
            "\"login_endpoint\": " \
            "\"http://35.161.197.99/acs/api/v1/auth/login\" }"

        url = 'http://dcos.com/acs/api/v1/auth/login'
        dummy_token = 'abcdefghijklmo'
        cert = "/this/is/a/path/to/a/cert.crt"

        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--dcos-auth-credentials', creds] + ['--marathon-ca-cert', cert]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.dcos_auth_credentials, creds)

        auth = get_marathon_auth_params(args)
        self.assertEqual(auth.login_endpoint,
                         'http://35.161.197.99/acs/api/v1/auth/login')

        # Mock 'requests.post()' and verify that the auth_request gets the
        # expected auth token
        req = requests.Request('POST', url)
        auth_request = req.prepare()
        auth_request.prepare_headers({'Authorization': ''})
        requests.post = Mock(return_value=self.request_response(dummy_token))

        auth = DCOSAuth(args.dcos_auth_credentials, args.marathon_ca_cert,
                        args.dcos_auth_token)
        auth(auth_request)
        self.assertEqual(auth_request.headers['Authorization'],
                         'token=' + dummy_token)

        # test via env var
        env_creds = 'It will now be a different value'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_DCOS_AUTH_CREDENTIALS'] = env_creds
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.dcos_auth_credentials, env_creds)

    def test_auth_token_arg(self):
        """Test: 'dcos-auth-token' arg."""
        token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCIsInR5cCI6IkpXVCJ9.eyJ \
        hdWQiOiIzeUY1VE9TemRsSTQ1UTF4c3B4emVvR0JlOWZOeG05bSIsImVtYWlsIjoiZHNz \
        dHN0YXBsZXRvbnJvYm90aWNzQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlL \
        CJleHAiOjEuNDgwODgyMzM5ZSswOSwiaWF0IjoxLjQ4MDQ1MDMzOWUrMDksImlzcyI6Im \
        h0dHBzOi8vZGNvcy5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMDYyMDA \
        4NzM2MDg4NzgwNDU5MzEiLCJ1aWQiOiJkc3N0c3RhcGxldG9ucm9ib3RpY3NAZ21haWwu \
        Y29tIn0.iq2rKcCH5_rPEd5td-fM2rxlHjIyGAJOmxTd5lceHAU"

        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--dcos-auth-token', token]
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.dcos_auth_token, token)

        url = 'http://dcos.com/acs/api/v1/auth/login'
        req = requests.Request('POST', url)
        auth_request = req.prepare()
        auth_request.prepare_headers({'Authorization': ''})

        auth = DCOSAuth(args.dcos_auth_credentials, args.marathon_ca_cert,
                        args.dcos_auth_token)

        auth(auth_request)
        self.assertEqual(auth_request.headers['Authorization'],
                         'token=' + token)

        # test via env var
        env_token = 'It will now be a different value'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_DCOS_AUTH_TOKEN'] = env_token
        args = ctlr.parse_args(version_data)
        self.assertEqual(args.dcos_auth_token, env_token)

    def request_response(self, token):
        """Mock a response and set a cookie."""
        r = requests.Response()
        r.cookies['dcos-acs-auth-cookie'] = token
        r.status_code = 200
        return r

    def request_response_failed(self):
        """Mock a failed response."""
        r = requests.Response()
        r.status_code = 404
        r.reason = 'not found'
        return r

    def request_response_ok(self):
        """Mock an OK response."""
        r = requests.Response()
        r.status_code = 200
        return r

    def test_marathon_client(self):
        """Test the Marathon client."""
        args = ['--marathon', 'http://10.0.0.10:8080', 'http://10.0.0.10:8081',
                '--partition', 'mesos',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default',
                '--marathon-ca-cert', '/this/is/a/path/to/a/cert.crt']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args(version_data)

        marathon = ctlr.Marathon(args.marathon,
                                 args.health_check,
                                 get_marathon_auth_params(args),
                                 args.marathon_ca_cert)

        # Cycle through multiple marathon hosts
        self.assertEqual(marathon.host, 'http://10.0.0.10:8080')
        self.assertEqual(marathon.host, 'http://10.0.0.10:8081')
        self.assertEqual(marathon.host, 'http://10.0.0.10:8080')
        self.assertEqual(marathon.host, 'http://10.0.0.10:8081')

        requests.Response.json = \
            Mock(return_value={"apps": [], "message": "this will go wrong"})
        self.assertFalse(marathon.health_check())

        # HTTPError raise
        requests.request = Mock(return_value=self.request_response_failed())
        self.assertRaises(requests.HTTPError, marathon.list)

        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args(version_data)
        marathon = ctlr.Marathon(args.marathon,
                                 args.health_check,
                                 get_marathon_auth_params(args),
                                 args.marathon_ca_cert)
        requests.Response.json = Mock(return_value={"apps": ['app1', 'app2'],
                                      "message": "this is ok"})
        # Valid response and data
        requests.request = Mock(return_value=self.request_response_ok())
        self.assertTrue(marathon.list() == ['app1', 'app2'])

        # 'apps' key error
        requests.Response.json = \
            Mock(return_value={"no apps": ['app1', 'app2']})
        requests.request = Mock(return_value=self.request_response_ok())
        self.assertRaises(KeyError, marathon.list)

    def test_setup_logging(self):
        """Test logging set up."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--log-level', 'DEBUG']
        args = ctlr.parse_args(version_data)
        logger = logging.getLogger('tests')
        setup_logging(logger, args.log_format, args.log_level)
        self.assertEqual(args.log_level, getattr(logging, 'DEBUG'))


class MarathonTest(unittest.TestCase):
    """Marathon/Big-IP configuration tests.

    Test BIG-IP configuration given various Marathon states
    """

    def setUp(self):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        with patch.object(ManagementRoot, '_get_tmos_version'):
            bigip = mgmt_root(
                '1.2.3.4',
                'admin',
                'admin',
                443,
                'tmos')
            self.cccl = F5CloudServiceManager(
                bigip,
                'mesos',
                prefix='')

        self.cccl._service_manager._service_deployer._bigip.refresh_ltm = \
            Mock()
        self.cccl._service_manager._service_deployer.deploy_ltm = \
            Mock(return_value=0)
        self.cccl._bigip_proxy.get_default_route_domain = \
            Mock(return_value=0)

    def raiseSystemExit(self):
        """Raise a SystemExit exception."""
        raise SystemExit

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

    def read_test_vectors(self, cloud_state):
        """Read test vectors for the various states."""
        # Read the Marathon state
        if cloud_state:
            with open(cloud_state) as json_data:
                self.cloud_data = json.load(json_data)

    def verify_marathon_config(self, cloud_state, expected_state):
        """Test: Verify expected config is created from the Marathon state."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        with open(expected_state) as json_data:
                exp = json.load(json_data)
        self.assertEqual(cfg, exp)

    def test_marathon_objects(
            self,
            cloud_state='tests/marathon_one_app_in_subdir.json'):
        """Test: Verify magic methods of app, service and backend objects."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        app_data = self.cloud_data
        for app in app_data:
            marathon_app = ctlr.MarathonApp(app['id'], app)
            marathon_app_copy = copy.deepcopy(marathon_app)
            marathon_app_copy.appId = 'copy_id'
            self.assertFalse(marathon_app == marathon_app_copy)
            self.assertNotEqual(hash(marathon_app), hash(marathon_app_copy))

        apps = ctlr.get_apps(self.cloud_data, True)
        expectedService = ctlr.MarathonService("app1", 80, [])
        self.assertEquals(expectedService, apps[1])
        self.assertEquals(repr(apps[1].backends.pop()),
                          "MarathonBackend(u'10.141.141.10', 31982)")

    def test_marathon_configs(self):
        """Test: Verify expected BIG-IP config created from Marathon state."""
        # Verify configuration
        for data_file in marathon_test_data:
            expected_file = data_file.replace('.json', '_expected.json')
            self.verify_marathon_config(data_file, expected_file)

    def start_two_apps_with_multiple_partitions(
            self, partitions, expected_name1, expected_partition1,
            expected_name1_count, expected_name2, expected_partition2,
            expected_name2_count,
            cloud_state='tests/marathon_two_apps_two_partitions.json'):
        """Test: Start two Marathon apps on two partitions."""
        # Get the test data
        self.read_test_vectors(cloud_state)
        apps = ctlr.get_apps(self.cloud_data, True)
        self.check_labels(self.cloud_data, apps)

        name1_count = 0
        name2_count = 0

        # Create CCCL instance for each partition and count the number of
        # times the virtual-server name is found
        for partition in partitions:
            with patch.object(ManagementRoot, '_get_tmos_version'):
                bigip = mgmt_root(
                    '1.2.3.4',
                    'admin',
                    'default',
                    443,
                    'tmos')
                cccl = F5CloudServiceManager(
                    bigip,
                    partition,
                    prefix='')

                cfg = ctlr.create_config_marathon(cccl, apps)
                if len(cfg['virtualServers']) > 0:
                    if expected_name1 == cfg['virtualServers'][0]['name'] and \
                            expected_partition1 == cccl.get_partition():
                        name1_count += 1
                    if expected_name2 == cfg['virtualServers'][0]['name'] and \
                            expected_partition2 == cccl.get_partition():
                        name2_count += 1

        # Verify BIG-IP configuration
        self.assertEqual(expected_name1_count, name1_count)
        self.assertEqual(expected_name2_count, name2_count)

    def test_start_two_apps_with_two_matching_partitions(self):
        """Test: Start two Marathon apps on two partitions."""
        self.start_two_apps_with_multiple_partitions(
            ['mesos', 'mesos2'],
            'server-app_80', 'mesos', 1,
            'server-app1_80', 'mesos2', 1)

    def test_start_two_apps_with_three_partitions(self):
        """Test: Start two Marathon apps, three partitions managed."""
        self.start_two_apps_with_multiple_partitions(
            ['mesos', 'mesos2', 'mesos3'],
            'server-app_80', 'mesos', 1,
            'server-app1_80', 'mesos2', 1)

    def test_start_two_apps_with_one_matching_partition(self):
        """Test: Start two Marathon apps, one managed partition matches."""
        self.start_two_apps_with_multiple_partitions(
            ['mesos', 'mesos1', 'mesos3'],
            'server-app_80', 'mesos', 1,
            'server-app1_80', 'mesos2', 0)

    def test_start_two_apps_with_no_matching_partitions(self):
        """Test: Start two Marathon apps, no managed partitions match."""
        self.start_two_apps_with_multiple_partitions(
            ['mesos0', 'mesos1', 'mesos3'],
            'server-app_80', 'mesos', 0,
            'server-app1_80', 'mesos2', 0)

    def test_new_iapp(self, cloud_state='tests/marathon_one_iapp.json'):
        """Test: Start Marathon app with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        expected_name = 'server-app2_10000'

        # Verfiy the iapp variables and tables
        expected_table = {
            "name": "pool__members",
            "columns": [{"kind": "IPAddress", "name": "addr"},
                        {"kind": "Port", "name": "port"},
                        {"name": "connection_limit", "value": "0"}],
            "members": [{"address": "10.141.141.10", "port": 31256},
                        {"address": "10.141.141.10", "port": 31269},
                        {"address": "10.141.141.10", "port": 31698},
                        {"address": "10.141.141.10", "port": 31748}]}

        expected_variables = {
            'monitor__monitor': '/#create_new#',
            'net__client_mode': 'wan',
            'pool__pool_to_use': '/#create_new#',
            'net__server_mode': 'lan',
            'pool__addr': '10.128.10.240',
            'monitor__response': 'none',
            'monitor__uri': '/',
            'pool__port': '8080'}

        # Verify the iapp variables and tables
        self.assertEquals(expected_name, cfg['iapps'][0]['name'])
        self.assertEquals(expected_table, cfg['iapps'][0]['poolMemberTable'])
        self.assertEquals(expected_variables, cfg['iapps'][0]['variables'])

    def check_expected_iapp_poolmember_table(self, pool_member_table_input,
                                             expected_table):
        """Check that the controller properly interprets POOL_MEMBER_TABLE.

        pool_member_table_description - Converted to a JSON string and assigned
            to F5_0_IAPP_POOL_MEMBER_TABLE.
        expected_tables - These tables must match the iApp definition's
            "tables" property that the controller would attempt to set on the
            BIG-IP (compared with assertEquals).
        """
        cloud_state = 'tests/marathon_one_iapp_column_names.json'

        # Get the test data
        self.read_test_vectors(cloud_state)

        # Overload the pool member table label - this tells the controller how
        # to fill in the pool member table.  Properly interpreting this is
        # what's under test.
        self.cloud_data[0]['labels']['F5_0_IAPP_POOL_MEMBER_TABLE'] = \
            json.dumps(pool_member_table_input)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        expected_name = 'server-app2_10000'

        # Verify the iapp variables and tables
        self.assertEquals(expected_name, cfg['iapps'][0]['name'])
        self.assertEquals(expected_table, cfg['iapps'][0]['poolMemberTable'])

    def test_new_iapp_nondefault_column_names(self):
        """Test: Marathon app with iApp, override pool-member column names."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
                {"name": "ConnectionLimit", "value": "0"}
            ]
        }
        expected_table = {
            "name": "pool__members",
            "columns": [{"kind": "IPAddress", "name": "IPAddress"},
                        {"kind": "Port", "name": "Port"},
                        {"name": "ConnectionLimit", "value": "0"}],
            "members": [{"address": "10.141.141.10", "port": 31256},
                        {"address": "10.141.141.10", "port": 31269},
                        {"address": "10.141.141.10", "port": 31698},
                        {"address": "10.141.141.10", "port": 31748}]}
        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_table)

    def test_new_iapp_nondefault_column_names_short(self):
        """Test: Marathon app with iApp, override only IPAddress and Port."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        expected_table = {
            'name': 'pool__members',
            'columns': [{'kind': 'IPAddress', 'name': 'IPAddress'},
                        {'kind': 'Port', 'name': 'Port'}],
            'members': [{'port': 31256, 'address': '10.141.141.10'},
                        {'port': 31269, 'address': '10.141.141.10'},
                        {'port': 31698, 'address': '10.141.141.10'},
                        {'port': 31748, 'address': '10.141.141.10'}]}

        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_table)

    def test_new_iapp_nondefault_column_names_reorder(self):
        """Test: Marathon app with iApp, override pool-member column order."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "ConnectionLimit", "value": "0"},
                {"name": "Port", "kind": "Port"},
                {"name": "IPAddress", "kind": "IPAddress"},
            ]
        }
        expected_table = {
            "name": "pool__members",
            "columns": [{"name": "ConnectionLimit", "value": "0"},
                        {"kind": "Port", "name": "Port"},
                        {"kind": "IPAddress", "name": "IPAddress"}],
            "members": [{"address": "10.141.141.10", "port": 31256},
                        {"address": "10.141.141.10", "port": 31269},
                        {"address": "10.141.141.10", "port": 31698},
                        {"address": "10.141.141.10", "port": 31748}]}

        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_table)

    def test_new_iapp_nondefault_column_names_appsvcs(self):
        """Test: Marathon app with iApp, override the AppSvcs iApp fields."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "Index", "value": "0"},
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
                {"name": "ConnectionLimit", "value": "1000"},
                {"name": "Ratio", "value": "1"},
                {"name": "PriorityGroup", "value": "0"},
                {"name": "State", "value": "enabled"},
                {"name": "AdvOptions", "value": ""}
            ]
        }
        expected_table = {
            "name": "pool__members",
            "columns": [{"name": "Index", "value": "0"},
                        {"name": "IPAddress", "kind": "IPAddress"},
                        {"name": "Port", "kind": "Port"},
                        {"name": "ConnectionLimit", "value": "1000"},
                        {"name": "Ratio", "value": "1"},
                        {"name": "PriorityGroup", "value": "0"},
                        {"name": "State", "value": "enabled"},
                        {"name": "AdvOptions", "value": ""}],
            "members": [{"address": "10.141.141.10", "port": 31256},
                        {"address": "10.141.141.10", "port": 31269},
                        {"address": "10.141.141.10", "port": 31698},
                        {"address": "10.141.141.10", "port": 31748}]}

        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_table)

    def check_failed_iapp_pool_member_table(self, pool_member_table_input,
                                            do_json=True):
        """Check that invalid pool member table formats fail cleanly."""
        cloud_state = 'tests/marathon_one_iapp_column_names.json'

        # Get the test data
        self.read_test_vectors(cloud_state)

        # Overload the pool member table label - this tells the controller how
        # to fill in the pool member table.  Properly interpreting this is
        # what's under test.
        pool_member_table_string = pool_member_table_input
        if do_json:
            pool_member_table_string = json.dumps(pool_member_table_input)
        self.cloud_data[0]['labels']['F5_0_IAPP_POOL_MEMBER_TABLE'] = \
            pool_member_table_string

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        # Should be empty because parsing the table should have failed.
        self.assertEquals(cfg['iapps'], [])

    def test_iapp_pool_member_table_not_json(self):
        """The pool member isn't JSON - should get an error."""
        pool_member_table_input = "{ This isn't JSON }"
        self.check_failed_iapp_pool_member_table(pool_member_table_input,
                                                 False)

    def test_iapp_pool_member_table_no_name(self):
        """The pool member doesn't have a "name" entry."""
        pool_member_table_input = {
            # Missing "name" entry here
            "columns": [
                {"name": "Index", "value": "0"},
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_pool_member_table_name_not_string(self):
        """The pool member table name is not a string."""
        pool_member_table_input = {
            "name": 2,
            "columns": [
                {"name": "Index", "value": "0"},
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_pool_member_table_name_not_in_column(self):
        """The pool member table name is not a string."""
        pool_member_table_input = {
            "name": "pool_Members",
            "columns": [
                {"nombre": "Index", "value": "0"},
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_pool_member_table_column_not_list(self):
        """The pool member table name is not a string."""
        pool_member_table_input = {
            "name": "pool_Members",
            "columns":
                {"name": "Index", "value": "0"}
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_pool_member_table_badcolumns(self):
        """The pool member has a columns array that is non-conformant."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": ["name", "Index", "value", "0"]
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_pool_member_table_badkind(self):
        """The pool member has a bad "kind"."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "Index", "value": "0"},
                {"name": "IPAddress", "kind": "ThisIsABadKind"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_pool_member_table_column_neither(self):
        """The pool member has a column that is neither "kind" nor "value"."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "Index"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        self.check_failed_iapp_pool_member_table(pool_member_table_input)

    def test_iapp_both_table_definitions(self):
        """Check that specifying both table types fails."""
        cloud_state = 'tests/marathon_one_iapp_column_names.json'

        # Get the test data
        self.read_test_vectors(cloud_state)

        # Overload the pool member table label - this tells the controller how
        # to fill in the pool member table.  Properly interpreting this is
        # what's under test.
        pool_member_table = {
            "name": "pool__members",
            "columns": [
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
                {"name": "ConnectionLimit", "value": "0"}
            ]
        }
        self.cloud_data[0]['labels']['F5_0_IAPP_POOL_MEMBER_TABLE'] = \
            json.dumps(pool_member_table)
        self.cloud_data[0]['labels']['F5_0_IAPP_POOL_MEMBER_TABLE_NAME'] = \
            "pool__members"

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        # Should be empty because parsing the table should have failed.
        self.assertEquals(cfg['iapps'], [])

    def test_new_iapp_with_tables(
            self,
            cloud_state='tests/marathon_one_iapp_with_tables.json'):
        """Test: Marathon app with iApp with iApp tables."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        expected_name = 'server-app2_10000'

        # Verify the iapp variables and tables
        expected_table = {
            "name": "pool__members",
            "columns": [{"kind": "IPAddress", "name": "addr"},
                        {"kind": "Port", "name": "port"},
                        {"name": "connection_limit", "value": "0"}],
            "members": [{"address": "10.141.141.10", "port": 31256},
                        {"address": "10.141.141.10", "port": 31269},
                        {"address": "10.141.141.10", "port": 31698},
                        {"address": "10.141.141.10", "port": 31748}]}
        expected_tables = {
            "l7policy__rulesMatch": {
                "rows": [["0", "http-uri/request/path", "no", "starts-with",
                          "/env", "no", "no"],
                         ["default", "", "no", "", "", "no", "no"]],
                "columns": ["Group", "Operand", "Negate", "Condition",
                            "Value", "CaseSensitive", "Missing"]},
            "l7policy__rulesAction": {
                "rows": [["0", "forward/request/reset", "none"],
                         ["default", "forward/request/select/pool", "pool:0"]],
                "columns": ["Group", "Target", "Parameter"]}}

        # Verify the iapp tables
        self.assertEquals(expected_name, cfg['iapps'][0]['name'])
        self.assertEquals(expected_table, cfg['iapps'][0]['poolMemberTable'])
        self.assertEquals(expected_tables, cfg['iapps'][0]['tables'])

    def test_event_processor(self):
        """Test Marathon event processing."""
        args_app_name = ['marathon-bigip-ctlr.py']
        args_mandatory = ['--marathon', 'http://10.0.0.10:8080',
                          '--partition', 'mesos',
                          '--hostname', '10.10.1.145',
                          '--username', 'admin',
                          '--password', 'default']
        sys.argv[0:] = args_app_name + args_mandatory
        args = ctlr.parse_args(version_data)
        marathon = ctlr.Marathon(args.marathon,
                                 args.health_check,
                                 get_marathon_auth_params(args))

        ctlr.Marathon.list = Mock(return_value=[])
        ctlr.Marathon.health_check = Mock(return_value=True)
        ctlr.MarathonEventProcessor.start_checkpoint_timer = Mock()
        ctlr.MarathonEventProcessor.retry_backoff = Mock()
        ep = ctlr.MarathonEventProcessor(marathon, 100, [self.cccl])

        event_empty = Event(data='')
        event_app = Event(data='{"eventType": "app_terminated_event"}')
        event_unknown = Event(data='{"eventType": "unknown_event"}')
        event_detached = Event(data='{"eventType": "event_stream_detached"}')
        event_invalid = Event(data='{"eventType": }')
        events = [event_empty, event_app, event_unknown, event_detached]

        with patch.object(self.cccl, 'apply_ltm_config',
                          return_value=1):
            ctlr.process_sse_events(ep, events)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid])
            time.sleep(1)

        with patch.object(self.cccl, 'apply_ltm_config',
                          side_effect=requests.exceptions.ConnectionError):
            ctlr.process_sse_events(ep, events)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid])
            time.sleep(1)

        with patch.object(self.cccl, 'apply_ltm_config',
                          side_effect=F5CcclValidationError):
            ctlr.process_sse_events(ep, events)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid])
            time.sleep(1)

            self.assertGreaterEqual(
                ctlr.MarathonEventProcessor.start_checkpoint_timer.call_count,
                1)
            self.assertGreaterEqual(ep.retry_backoff.call_count, 1)

    def test_backoff_timer(self):
        """Test tight loop backoff."""
        cb = Mock()
        ep = ctlr.MarathonEventProcessor({}, 1, {})
        # Set our times for fast unit testing
        ep._max_backoff_time = 0.1
        ep._backoff_timer = 0.025

        self.assertEqual(ep._max_backoff_time, 0.1)
        self.assertEqual(ep._backoff_timer, 0.025)
        # First call doubles the _backoff_timer
        ctlr.MarathonEventProcessor.retry_backoff(ep, cb)
        self.assertEqual(ep._backoff_timer, 0.05)
        # Second call doubles the _backoff_timer
        ctlr.MarathonEventProcessor.retry_backoff(ep, cb)
        self.assertEqual(ep._backoff_timer, 0.1)
        # No change to backoff_timer as we hit _max_backoff_time
        ctlr.MarathonEventProcessor.retry_backoff(ep, cb)
        self.assertEqual(ep._backoff_timer, 0.1)
        self.assertEqual(cb.call_count, 3)

    def test_pool_only_to_virtual_server(
            self,
            cloud_state='tests/marathon_one_app_pool_only.json'):
        """Test: Marathon app without a virtual server gets virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)
        self.assertEqual(len(cfg['virtualServers']), 0)

        # Reconfigure BIG-IP by adding virtual server to existing pool
        self.cloud_data[1]['labels'].update({unicode('F5_0_MODE'):
                                             unicode('http'),
                                             unicode('F5_0_BIND_ADDR'):
                                             unicode('10.128.10.240')})
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)
        self.check_labels(self.cloud_data, apps)
        self.assertEqual(len(cfg['virtualServers']), 1)

        # Verify BIG-IP reconfiguration

    def test_virtual_server_to_pool_only(
            self,
            cloud_state='tests/marathon_one_app.json'):
        """Test: Marathon app with virtual server removes virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)
        self.assertEqual(len(cfg['virtualServers']), 1)

        # Reconfigure BIG-IP by adding virtual server to existing pool
        self.cloud_data[1]['labels'].pop(unicode('F5_0_MODE'))
        self.cloud_data[1]['labels'].pop(unicode('F5_0_BIND_ADDR'))
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.cccl, apps)
        self.cccl.apply_ltm_config(cfg)

        self.check_labels(self.cloud_data, apps)

        self.assertEqual(len(cfg['virtualServers']), 0)

    def test_cccl_exceptions(self, cloud_state='tests/marathon_one_app.json'):
        """Test: CCCL exceptions."""
        with patch.object(ManagementRoot, '_get_tmos_version'):
            bigip = mgmt_root(
                '1.2.3.4',
                'admin',
                'default',
                443,
                'tmos')
            self.assertRaises(F5CcclSchemaError, F5CloudServiceManager,
                              bigip,
                              'test',
                              prefix="",
                              schema_path='not/a/valid/path.json')

        cfg = 'not valid json'
        self.assertRaises(F5CcclValidationError,
                          self.cccl.apply_ltm_config,
                          cfg)

        cfg = '{}'
        self.assertRaises(F5CcclValidationError,
                          self.cccl.apply_ltm_config,
                          cfg)

        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.cccl, apps)

        # Corrupt the config
        del cfg['virtualServers'][0]['name']
        self.assertRaises(F5CcclValidationError,
                          self.cccl.apply_ltm_config,
                          cfg)


class GetProtocolTest(unittest.TestCase):
    """Test marathon-bigip-ctlr get_protocol function."""

    def test_get_protocol_valid_input(self):
        """Test get_protocol with valid input."""
        valid = ['tcp', 'http', 'udp', 'TCP', 'HTTP', 'UDP', 'tCp', 'Http',
                 'udP']
        exp_res = ['tcp', 'tcp', 'udp', 'tcp', 'tcp', 'udp', 'tcp', 'tcp',
                   'udp']
        for i in range(0, len(valid)):
            res = ctlr.get_protocol(valid[i])
            self.assertEqual(res, exp_res[i])

    def test_get_protocol_invalid_input(self):
        """Test get_protocol with invalid input."""
        invalid = ['abc', 'ABC', 'aBc', '', ' ', True, 1, [], {}]
        for i in range(0, len(invalid)):
            res = ctlr.get_protocol(invalid[i])
            self.assertEqual(res, None)


class IsLabelDataValidTest(unittest.TestCase):
    """Test marathon-bigip-ctlr is_label_data_valid method."""

    class MockAppLabelData():
        """Mock marathon label data."""

        def __init__(self, proto, port, addr, balance):
            """Initialize a MockAppLabelData object."""
            self.appId = 'mockApp'
            self.mode = proto
            self.servicePort = port
            self.bindAddr = addr
            self.balance = balance

    def test_is_label_data_valid_valid_input(self):
        """Test is_label_data_valid with valid input."""
        proto = ['tcp', 'http', 'udp']
        port = [1, 10000, 65535]
        addr = [unicode('192.168.0.1'), unicode('2001:db8::'),
                unicode('192.168.0.1%24'), unicode('2001:db8::%0')]
        balance = ['dynamic-ratio-member',
                   'least-connections-member',
                   'observed-node',
                   'ratio-least-connections-node',
                   'round-robin',
                   'dynamic-ratio-node',
                   'least-connections-node',
                   'predictive-member',
                   'ratio-member',
                   'weighted-least-connections-member',
                   'fastest-app-response',
                   'least-sessions',
                   'predictive-node',
                   'ratio-node',
                   'weighted-least-connections-node',
                   'fastest-node',
                   'observed-member',
                   'ratio-least-connections-member',
                   'ratio-session']
        for i in range(0, len(proto)):
            app = self.MockAppLabelData(proto[i], port[0], addr[0], balance[0])
            res = ctlr.is_label_data_valid(app)
            self.assertTrue(res)
        for i in range(0, len(port)):
            app = self.MockAppLabelData(proto[0], port[i], addr[0], balance[0])
            res = ctlr.is_label_data_valid(app)
            self.assertTrue(res)
        for i in range(0, len(addr)):
            app = self.MockAppLabelData(proto[0], port[0], addr[i], balance[0])
            res = ctlr.is_label_data_valid(app)
            self.assertTrue(res)
        for i in range(0, len(balance)):
            app = self.MockAppLabelData(proto[0], port[0], addr[0], balance[i])
            res = ctlr.is_label_data_valid(app)
            self.assertTrue(res)

    def test_is_label_data_valid_invalid_input(self):
        """Test is_label_data_valid with invalid input."""
        valid_proto = 'tcp'
        proto = ['abc', 'ABC', 'abc', '', ' ', 1, False, [], {}]
        valid_port = 8000
        port = [0, -10000, 65536, '123', '', False, [], {}]
        valid_addr = unicode('192.168.0.1')
        addr = [unicode('258.0.0.1'), unicode('2001:dg8::1'),
                unicode('string'), unicode(''), unicode(' '), 'string', True,
                [], {}, unicode('1.1.1.1%cow'), unicode('1.1.1.1%')]
        valid_balance = 'round-robin'
        for i in range(0, len(proto)):
            app = self.MockAppLabelData(proto[i], valid_port,
                                        valid_addr, valid_balance)
            res = ctlr.is_label_data_valid(app)
            self.assertFalse(res)
        for i in range(0, len(port)):
            app = self.MockAppLabelData(valid_proto, port[i],
                                        valid_addr, valid_balance)
            res = ctlr.is_label_data_valid(app)
            self.assertFalse(res)
        for i in range(0, len(addr)):
            app = self.MockAppLabelData(valid_proto, valid_port,
                                        addr[i], valid_balance)
            res = ctlr.is_label_data_valid(app)
            self.assertFalse(res)


if __name__ == '__main__':
    unittest.main()
