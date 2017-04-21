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
from f5.bigip import BigIP
from _f5 import CloudBigIP, get_protocol
from StringIO import StringIO
from testcommon import BigIPTest, HealthCheck, Pool
ctlr = __import__('marathon-bigip-ctlr')

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
        self.assertRaises(SystemExit, ctlr.parse_args)

        expected = \
            "usage: marathon-bigip-ctlr.py [-h] [--longhelp]\n" \
            """                              [--marathon MARATHON [MARATHON ...]]
                              [--hostname HOSTNAME] [--username USERNAME]
                              [--password PASSWORD] [--partition PARTITION]
                              [--health-check]
                              [--marathon-ca-cert MARATHON_CA_CERT]
                              [--sse-timeout SSE_TIMEOUT]
                              [--verify-interval VERIFY_INTERVAL]
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
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
        self.assertEqual(args.marathon, ['http://10.0.0.10:8080'])
        self.assertEqual(args.partition, ['mesos', 'mesos2'])
        self.assertEqual(args.hostname, 'https://10.10.1.145')
        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.password, 'default')

    def test_long_help(self):
        """Test: Long help."""
        args = ['--longhelp']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

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
                '--partition', '*',
                '--hostname', 'scheme://10.10.1.145',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

    def test_no_password(self):
        """Test: No password arg."""
        # Invalid scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--username', 'admin',
                '--hostname', 'scheme://10.10.1.145']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

    def test_hostname_arg(self):
        """Test: Hostname arg."""
        # No hostname
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

        # Invalid scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', 'scheme://10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

        # No scheme
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args()
        self.assertEqual(args.host, '10.10.1.145')
        self.assertEqual(args.port, 443)

        # No port
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', 'https://10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args()
        self.assertEqual(args.host, '10.10.1.145')
        self.assertEqual(args.port, 443)

        # Given port
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', 'https://10.10.1.145:555',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args()
        self.assertEqual(args.host, '10.10.1.145')
        self.assertEqual(args.port, 555)

        # Invalid path
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', 'https://10.10.1.145/path/not/allowed',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

    def test_partition_arg(self):
        """Test: Wildcard partition arg."""
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--partition', '*',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        args = ctlr.parse_args()
        self.assertEqual(args.partition, ['*'])

        # No partition specified
        args = ['--marathon', 'http://10.0.0.10:8080',
                '--hostname', '10.10.1.145',
                '--username', 'admin',
                '--password', 'default']
        sys.argv[0:] = self._args_app_name + args
        self.assertRaises(SystemExit, ctlr.parse_args)

        # test via env var
        partitions_env = '*'
        sys.argv[0:] = self._args_app_name + self._args_without_partition
        os.environ['F5_CC_PARTITIONS'] = partitions_env
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
        self.assertEqual(args.partition, ['mesos-1', 'mesos-2', 'mesos-3'])

        # test via env var
        partitions_env = '[mesos7, mesos8]'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_PARTITIONS'] = partitions_env
        args = ctlr.parse_args()
        # command-line overrides env var
        self.assertEqual(args.partition, ['mesos'])

        sys.argv[0:] = self._args_app_name + self._args_without_partition
        args = ctlr.parse_args()
        self.assertEqual(args.partition, ['mesos7', 'mesos8'])

    def test_health_check_arg(self):
        """Test: 'Health Check' arg."""
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args()
        self.assertEqual(args.health_check, False)
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--health-check']
        args = ctlr.parse_args()
        self.assertEqual(args.health_check, True)

        sys.argv[0:] = self._args_app_name + self._args_mandatory + ['-H']
        args = ctlr.parse_args()
        self.assertEqual(args.health_check, True)

        # test via env var
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args()
        self.assertEqual(args.health_check, False)
        os.environ['F5_CC_USE_HEALTHCHECK'] = 'True'
        args = ctlr.parse_args()
        self.assertEqual(args.health_check, True)

    def test_log_format_arg(self):
        """Test: 'Log format' arg."""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-format', log_format]
        args = ctlr.parse_args()
        self.assertEqual(args.log_format, log_format)

        # test via env var
        env_log_format = '%(asctime)s - %(message)s'
        os.environ['F5_CC_LOG_FORMAT'] = env_log_format
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args()
        self.assertEqual(args.log_format, env_log_format)

    def test_log_level_arg(self):
        """Test: 'Log level' arg."""
        # Test all valid levels
        levels = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
        for level in levels:
            sys.argv[0:] = self._args_app_name + self._args_mandatory + \
                ['--log-level', level]
            args = ctlr.parse_args()
            self.assertEqual(args.log_level, getattr(logging, level))

        # Test default
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args()
        self.assertEqual(args.log_level, getattr(logging, 'INFO'))

        # Test invalid
        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--log-level', 'INCONCEIVABLE']
        self.assertRaises(SystemExit, ctlr.parse_args)

        # Test invalid (via env)
        os.environ['F5_CC_LOG_LEVEL'] = 'INCONCEIVABLE'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        self.assertRaises(SystemExit, ctlr.parse_args)

        # Test all valid levels (via env)
        for level in levels:
            os.environ['F5_CC_LOG_LEVEL'] = level
            sys.argv[0:] = self._args_app_name + self._args_mandatory
            args = ctlr.parse_args()
            self.assertEqual(args.log_level, getattr(logging, level))

    def test_marathon_cred_arg(self):
        """Test: 'Marathon credentials' arg."""
        auth_file = '/tmp/auth'
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-auth-credential-file', auth_file]
        args = ctlr.parse_args()
        self.assertEqual(args.marathon_auth_credential_file, auth_file)

        # test via env var
        env_auth_file = '/tmp/auth_from_env'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_MARATHON_AUTH'] = env_auth_file
        args = ctlr.parse_args()
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
        self.assertRaises(SystemExit, ctlr.parse_args)

        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--sse-timeout', str(timeout)]
        args = ctlr.parse_args()
        self.assertEqual(args.sse_timeout, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args()
        self.assertEqual(args.sse_timeout, 30)

        # test via env var
        os.environ['F5_CC_SSE_TIMEOUT'] = str(timeout)
        args = ctlr.parse_args()
        self.assertEqual(args.sse_timeout, timeout)

    def test_verify_interval_arg(self):
        """Test: 'Verify Interval' arg."""
        timeout = 45
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--verify-interval', str(timeout)]
        args = ctlr.parse_args()
        self.assertEqual(args.verify_interval, timeout)

        # test default value
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        args = ctlr.parse_args()
        self.assertEqual(args.verify_interval, 30)

        # test via env var
        os.environ['F5_CC_VERIFY_INTERVAL'] = str(timeout)
        args = ctlr.parse_args()
        self.assertEqual(args.verify_interval, timeout)

        # Invalid interval
        timeout = 0
        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--verify-interval', str(timeout)]
        self.assertRaises(SystemExit, ctlr.parse_args)

    def test_marathon_ca_cert_arg(self):
        """Test: 'Marathon CA Cert' arg."""
        cert = "/this/is/a/path/to/a/cert.crt"

        sys.argv[0:] = self._args_app_name + self._args_mandatory \
            + ['--marathon-ca-cert', cert]
        args = ctlr.parse_args()
        self.assertEqual(args.marathon_ca_cert, cert)

        # test via env var
        env_cert = 'It will now be a different value'
        sys.argv[0:] = self._args_app_name + self._args_mandatory
        os.environ['F5_CC_MARATHON_CA_CERT'] = env_cert
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()

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
        args = ctlr.parse_args()
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
        args = ctlr.parse_args()
        logger = logging.getLogger('tests')
        setup_logging(logger, args.log_format, args.log_level)
        self.assertEqual(args.log_level, getattr(logging, 'DEBUG'))


class MarathonTest(BigIPTest):
    """Marathon/Big-IP configuration tests.

    Test BIG-IP configuration given various Marathon states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        partition = 'mesos'
        with patch.object(BigIP, '_get_tmos_version'):
            bigip = CloudBigIP('1.2.3.4', '443', 'admin',
                               'default', [partition])
        super(MarathonTest, self).setUp(partition, bigip)

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

    def test_exceptions(self, cloud_state='tests/marathon_two_apps.json',
                        bigip_state='tests/bigip_test_no_change.json',
                        hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Exception handling."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)

        # Successful configuration (no retry)
        self.assertFalse(self.bigip.regenerate_config_f5(cfg))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = Mock(side_effect=self.raiseSDKError)
        self.assertTrue(self.bigip.regenerate_config_f5(cfg))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = \
            Mock(side_effect=self.raiseConnectionError)
        self.assertTrue(self.bigip.regenerate_config_f5(cfg))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = \
            Mock(side_effect=self.raiseBigIPInvalidURL)
        self.assertTrue(self.bigip.regenerate_config_f5(cfg))

        # BIG-IP related exception (retry)
        self.bigip._apply_config = \
            Mock(side_effect=self.raiseBigiControlUnexpectedHTTPError)
        self.assertTrue(self.bigip.regenerate_config_f5(cfg))

        # Other exception types (retry)
        self.bigip._apply_config = Mock(side_effect=self.raiseTypeError)
        self.assertTrue(self.bigip.regenerate_config_f5(cfg))

    def test_marathon_objects(
            self,
            cloud_state='tests/marathon_one_app_in_subdir.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Verify magic methods of app, service and backend objects."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

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

    def test_app_frontend_name(
            self,
            cloud_state='tests/marathon_one_app_in_subdir.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Verify frontend name when the app is in a subdirectory."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)

        expected_name = 'my_services_test-2_server-app_80'
        self.assertEquals(1, len(self.test_virtual))
        self.assertEquals(1, len(self.test_pool))
        self.assertEquals(expected_name, self.test_virtual[0]['name'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[0]['partition'])
        self.assertEquals(expected_name, self.test_pool[0]['name'])
        self.assertEquals(self.test_partition, self.test_pool[0]['partition'])
        self.assertEquals(self.bigip.member_create.call_args[0][1],
                          expected_name)

    def test_invalid_app(self,
                         cloud_state='tests/marathon_invalid_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Invalid marathon applications are not configured."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.member_create.call_count, 3)

        self.assertEquals(1, len(self.test_virtual))
        self.assertEquals(1, len(self.test_pool))
        self.assertEquals(1, len(self.test_monitor))

        expected_name = 'server-app_80'

        self.assertEquals(expected_name, self.test_virtual[0]['name'])
        self.assertEquals(expected_name, self.test_pool[0]['name'])
        self.assertEquals(expected_name, self.test_monitor[0]['name'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[0]['partition'])
        self.assertEquals(self.test_partition, self.test_pool[0]['partition'])
        self.assertEquals(self.test_partition,
                          self.test_monitor[0]['partition'])

    def test_no_change(self, cloud_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_no_change.json',
                       hm_state='tests/bigip_test_two_monitors.json'):
        """Test: No Marathon state change."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)

    def test_app_destroyed(self, cloud_state='tests/marathon_one_app.json',
                           bigip_state='tests/bigip_test_app_destroyed.json',
                           hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app destroyed."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertTrue(self.bigip.ltm.pools.get_collection.called)
        self.assertTrue(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.load.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.get_collection.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.tcps.tcp.load.call_count, 1)

    def test_app_scaled_up(self,
                           cloud_state='tests/marathon_app_scaled.json',
                           bigip_state='tests/bigip_test_app_scaled_up.json',
                           hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Marathon app destroyed."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
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
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
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
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.ltm.virtuals.virtual.create.call_count,
                          1)
        self.assertEquals(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 4)
        self.assertEquals(self.bigip.ltm.monitor.tcps.tcp.create.call_count, 1)

    def test_start_app_with_health_monitor_http(
            self,
            cloud_state='tests/marathon_two_apps.json',
            bigip_state='tests/bigip_test_app_started_with_http.json',
            hm_state='tests/bigip_test_one_tcp_monitor.json'):
        """Test: Start Marathon app with an HTTP health monitor."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.ltm.virtuals.virtual.create.call_count,
                          1)
        self.assertEquals(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 2)
        self.assertEquals(self.bigip.ltm.monitor.https.http.create.call_count,
                          1)

    def test_start_app_with_health_monitor_none(
            self,
            cloud_state='tests/marathon_app_no_hm.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Start Marathon app with no health monitor configured."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.ltm.virtuals.virtual.create.call_count,
                          1)
        self.assertEquals(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 2)

    def test_bigip_new(self, cloud_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_blank.json',
                       hm_state='tests/bigip_test_blank.json'):
        """Test: BIG-IP with no resources previously configured."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertEquals(self.bigip.ltm.virtuals.virtual.create.call_count,
                          2)
        self.assertEquals(self.bigip.ltm.pools.pool.create.call_count, 2)
        self.assertEquals(self.bigip.member_create.call_count, 6)
        self.assertEquals(self.bigip.ltm.monitor.tcps.tcp.create.call_count, 1)
        self.assertEquals(self.bigip.ltm.monitor.https.http.create.call_count,
                          1)

    def test_missing_task_data(
            self,
            cloud_state='tests/marathon_one_app_missing_data.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Tasks missing health-check results, hosts, and not 'alive'."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertEquals(self.bigip.ltm.virtuals.virtual.create.call_count,
                          1)
        self.assertEquals(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEquals(self.bigip.member_create.call_count, 1)

    def test_no_port_override(
            self,
            cloud_state='tests/marathon_one_app_no_port_label.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app using default Marathon service port."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertEquals(self.bigip.member_create.call_count, 4)
        self.assertEquals(self.bigip.ltm.monitor.https.http.create.call_count,
                          1)

        # No override of service port from Marathon
        expected_name = 'server-app_10001'
        self.assertEquals(1, len(self.test_virtual))
        self.assertEquals(1, len(self.test_pool))
        self.assertEquals(expected_name, self.test_virtual[0]['name'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[0]['partition'])
        self.assertEquals(expected_name, self.test_pool[0]['name'])
        self.assertEquals(self.test_partition, self.test_pool[0]['partition'])
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
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.member_create.call_count, 6)

        expected_name1 = 'server-app4_8080'
        expected_name2 = 'server-app4_8090'
        self.assertEquals(2, len(self.test_virtual))
        self.assertEquals(2, len(self.test_pool))
        self.assertEquals(2, len(self.test_monitor))
        self.assertEquals(expected_name1, self.test_virtual[0]['name'])
        self.assertEquals(expected_name2, self.test_virtual[1]['name'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[0]['partition'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[1]['partition'])
        self.assertEquals(expected_name1, self.test_pool[0]['name'])
        self.assertEquals(expected_name2, self.test_pool[1]['name'])
        self.assertEquals(self.test_partition, self.test_pool[0]['partition'])
        self.assertEquals(self.test_partition, self.test_pool[1]['partition'])
        self.assertEquals(expected_name1, self.test_monitor[0]['name'])
        self.assertEquals(expected_name2, self.test_monitor[1]['name'])
        self.assertEquals(self.test_partition,
                          self.test_monitor[0]['partition'])
        self.assertEquals(self.test_partition,
                          self.test_monitor[1]['partition'])

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
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        create_call_count = 0

        if expected_name1:
            create_call_count += 1
            self.assertEquals(expected_name1,
                              self.test_virtual[create_call_count - 1]['name'])
            self.assertEquals(expected_name1,
                              self.test_pool[create_call_count - 1]['name'])
            self.assertEquals(expected_name1,
                              self.test_monitor[create_call_count - 1]['name'])

        if expected_name2:
            create_call_count += 1
            self.assertEquals(expected_name2,
                              self.test_virtual[create_call_count - 1]['name'])
            self.assertEquals(expected_name2,
                              self.test_pool[create_call_count - 1]['name'])
            self.assertEquals(expected_name2,
                              self.test_monitor[create_call_count - 1]['name'])

        if create_call_count > 0:
            self.assertTrue(self.bigip.member_create.called)
        else:
            self.assertFalse(self.bigip.member_create.called)

        self.assertEquals(create_call_count, len(self.test_virtual))
        self.assertEquals(create_call_count, len(self.test_pool))
        self.assertEquals(self.bigip.member_create.call_count,
                          3*create_call_count)
        self.assertEquals(create_call_count, len(self.test_monitor))

    def test_start_two_apps_with_two_matching_partitions(self):
        """Test: Start two Marathon apps on two partitions."""
        self.start_two_apps_with_two_partitions(
            ['mesos', 'mesos2'],
            'server-app_80',
            'server-app1_80')

    def test_start_two_apps_with_wildcard_partitions(self):
        """Test: Start two Marathon apps, all partitions managed."""
        self.start_two_apps_with_two_partitions(
            ['*'],
            'server-app_80',
            'server-app1_80')

    def test_start_two_apps_with_three_partitions(self):
        """Test: Start two Marathon apps, three partitions managed."""
        self.start_two_apps_with_two_partitions(
            ['mesos', 'mesos2', 'mesos3'],
            'server-app_80',
            'server-app1_80')

    def test_start_two_apps_with_one_matching_partition(self):
        """Test: Start two Marathon apps, one managed partition matches."""
        self.start_two_apps_with_two_partitions(
            ['mesos', 'mesos1', 'mesos3'],
            None,
            'server-app_80')

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
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEquals(self.bigip.member_create.call_count, 6)

        expected_name1 = 'server-app4_8080'
        expected_name2 = 'server-app4_8090'
        expected_name3 = 'server-app4_10003'
        self.assertEquals(2, len(self.test_virtual))
        self.assertEquals(3, len(self.test_pool))
        self.assertEquals(expected_name1, self.test_virtual[0]['name'])
        self.assertEquals(expected_name2, self.test_virtual[1]['name'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[0]['partition'])
        self.assertEquals(self.test_partition,
                          self.test_virtual[1]['partition'])
        self.assertEquals(expected_name1, self.test_pool[0]['name'])
        self.assertEquals(expected_name2, self.test_pool[1]['name'])
        self.assertEquals(expected_name3, self.test_pool[2]['name'])
        self.assertEquals(self.test_partition, self.test_pool[0]['partition'])
        self.assertEquals(self.test_partition, self.test_pool[1]['partition'])
        self.assertEquals(self.test_partition, self.test_pool[2]['partition'])
        self.assertEquals(expected_name1, self.test_monitor[0]['name'])
        self.assertEquals(expected_name2, self.test_monitor[1]['name'])
        self.assertEquals(expected_name3, self.test_monitor[2]['name'])
        self.assertEquals(self.test_partition,
                          self.test_monitor[0]['partition'])
        self.assertEquals(self.test_partition,
                          self.test_monitor[1]['partition'])
        self.assertEquals(self.test_partition,
                          self.test_monitor[2]['partition'])

    def test_destroy_all_apps(
            self,
            cloud_state='tests/marathon_no_apps.json',
            bigip_state='tests/bigip_test_no_change.json',
            hm_state='tests/bigip_test_two_monitors.json'):
        """Test: Destroy all Marathon apps."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertEquals(self.bigip.member_delete.call_count, 0)

        expected_name1 = 'server-app2_8080'
        expected_name2 = 'server-app_80'
        self.assertEquals(2, len(self.test_virtual))
        self.assertEquals(2, len(self.test_pool))
        self.assertEquals(2, len(self.test_monitor))
        self.assertEquals(expected_name1, self.test_virtual[1].name)
        self.assertEquals(expected_name2, self.test_virtual[0].name)
        self.assertEquals(expected_name1, self.test_pool[1].name)
        self.assertEquals(expected_name2, self.test_pool[0].name)
        self.assertEquals(expected_name1, self.test_monitor[1].name)
        self.assertEquals(expected_name2, self.test_monitor[0].name)

    def test_app_suspended(
            self,
            cloud_state='tests/marathon_one_app_zero_instances.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_http_monitor.json'):
        """Test: Suspend Marathon app."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertTrue(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertEquals(self.bigip.member_delete.call_count, 4)

        expected_name = 'server-app_80'
        self.assertEquals(self.bigip.member_delete.call_args_list[0][0][1],
                          expected_name)

    def test_new_iapp(self, cloud_state='tests/marathon_one_iapp.json',
                      bigip_state='tests/bigip_test_blank.json',
                      hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.iapp_create = self.bigip.iapp_create_orig
        self.bigip.sys.application.services.service.create = \
            Mock(side_effect=self.mock_iapp_service_create)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)

        expected_name = 'server-app2_10000'

        # Verfiy the iapp variables and tables
        expected_tables = \
            [{'columnNames': ['addr', 'port', 'connection_limit'], 'rows':
              [{'row': ['10.141.141.10', '31698', '0']},
               {'row': ['10.141.141.10', '31269', '0']},
               {'row': ['10.141.141.10', '31748', '0']},
               {'row': ['10.141.141.10', '31256', '0']}],
                'name': u'pool__members'}]
        expected_variables = \
            [{'name': u'monitor__monitor', 'value': u'/#create_new#'},
             {'name': u'net__client_mode', 'value': u'wan'},
             {'name': u'pool__pool_to_use', 'value': u'/#create_new#'},
             {'name': u'net__server_mode', 'value': u'lan'},
             {'name': u'pool__addr', 'value': u'10.128.10.240'},
             {'name': u'monitor__response', 'value': u'none'},
             {'name': u'monitor__uri', 'value': u'/'},
             {'name': u'pool__port', 'value': u'8080'}]

        self.assertEquals(expected_name, self.test_iapp.name)
        self.assertEquals(expected_tables, self.test_iapp.tables)
        self.assertEquals(expected_variables, self.test_iapp.variables)

    def check_expected_iapp_poolmember_table(self, pool_member_table_input,
                                             expected_tables):
        """Check that the controller properly interprets POOL_MEMBER_TABLE.

        pool_member_table_description - Converted to a JSON string and assigned
            to F5_0_IAPP_POOL_MEMBER_TABLE.
        expected_tables - These tables must match the iApp definition's
            "tables" property that the controller would attempt to set on the
            BIG-IP (compared with assertEquals).
        """
        cloud_state = 'tests/marathon_one_iapp_column_names.json'
        bigip_state = 'tests/bigip_test_blank.json'
        hm_state = 'tests/bigip_test_blank.json'

        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Overload the pool member table label - this tells the controller how
        # to fill in the pool member table.  Properly interpreting this is
        # what's under test.
        self.cloud_data[0]['labels']['F5_0_IAPP_POOL_MEMBER_TABLE'] = \
            json.dumps(pool_member_table_input)

        self.bigip.iapp_create = self.bigip.iapp_create_orig
        self.bigip.sys.application.services.service.create = \
            Mock(side_effect=self.mock_iapp_service_create)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        expected_name = 'server-app2_10000'

        # Verify the iapp variables and tables
        self.assertEquals(expected_name, self.test_iapp.name)
        self.assertEquals(expected_tables, self.test_iapp.tables)

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
        expected_tables = \
            [{'columnNames': [u'IPAddress', u'Port', u'ConnectionLimit'],
              'rows':
              [{'row': ['10.141.141.10', '31698', '0']},
               {'row': ['10.141.141.10', '31269', '0']},
               {'row': ['10.141.141.10', '31748', '0']},
               {'row': ['10.141.141.10', '31256', '0']}],
                'name': u'pool__members'}]
        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_tables)

    def test_new_iapp_nondefault_column_names_short(self):
        """Test: Marathon app with iApp, override only IPAddress and Port."""
        pool_member_table_input = {
            "name": "pool__members",
            "columns": [
                {"name": "IPAddress", "kind": "IPAddress"},
                {"name": "Port", "kind": "Port"},
            ]
        }
        expected_tables = \
            [{'columnNames': [u'IPAddress', u'Port'],
              'rows':
              [{'row': ['10.141.141.10', '31698']},
               {'row': ['10.141.141.10', '31269']},
               {'row': ['10.141.141.10', '31748']},
               {'row': ['10.141.141.10', '31256']}],
                'name': u'pool__members'}]
        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_tables)

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
        expected_tables = \
            [{'columnNames': [u'ConnectionLimit', u'Port', u'IPAddress'],
              'rows':
              [{'row': ['0', '31698', '10.141.141.10']},
               {'row': ['0', '31269', '10.141.141.10']},
               {'row': ['0', '31748', '10.141.141.10']},
               {'row': ['0', '31256', '10.141.141.10']}],
                'name': u'pool__members'}]
        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_tables)

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
        expected_tables = [{
            'columnNames': [
                u'Index',
                u'IPAddress',
                u'Port',
                u'ConnectionLimit',
                u'Ratio',
                u'PriorityGroup',
                u'State',
                u'AdvOptions',
            ],
            'rows': [
                {'row': ['0', '10.141.141.10', '31698', '1000', '1', '0',
                         'enabled', '']},
                {'row': ['0', '10.141.141.10', '31269', '1000', '1', '0',
                         'enabled', '']},
                {'row': ['0', '10.141.141.10', '31748', '1000', '1', '0',
                         'enabled', '']},
                {'row': ['0', '10.141.141.10', '31256', '1000', '1', '0',
                         'enabled', '']},
            ],
            'name': u'pool__members'
        }]
        self.check_expected_iapp_poolmember_table(
            pool_member_table_input,
            expected_tables)

    def check_failed_iapp_pool_member_table(self, pool_member_table_input,
                                            do_json=True):
        """Check that invalid pool member table formats fail cleanly."""
        cloud_state = 'tests/marathon_one_iapp_column_names.json'
        bigip_state = 'tests/bigip_test_blank.json'
        hm_state = 'tests/bigip_test_blank.json'

        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

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
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Should be 0 because parsing the table should have failed.
        self.assertEquals(self.bigip.iapp_create.call_count, 0)

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
        bigip_state = 'tests/bigip_test_blank.json'
        hm_state = 'tests/bigip_test_blank.json'

        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

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
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Should be 0 because parsing the table should have failed.
        self.assertEquals(self.bigip.iapp_create.call_count, 0)

    def test_new_iapp_with_tables(
            self,
            cloud_state='tests/marathon_one_iapp_with_tables.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app with iApp with iApp tables."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.iapp_create = self.bigip.iapp_create_orig
        self.bigip.sys.application.services.service.create = \
            Mock(side_effect=self.mock_iapp_service_create)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        expected_name = 'server-app2_10000'

        # Verify the iapp variables and tables
        expected_tables = \
            [{'columnNames': [u'addr', u'port', u'connection_limit'],
              'rows':
              [{'row': ['10.141.141.10', '31698', '0']},
               {'row': ['10.141.141.10', '31269', '0']},
               {'row': ['10.141.141.10', '31748', '0']},
               {'row': ['10.141.141.10', '31256', '0']}],
                'name': u'pool__members'},
             {'columnNames': [u'Group', u'Operand', u'Negate', u'Condition',
                              u'Value', u'CaseSensitive', u'Missing'],
              'rows':
              [{'row': [0, u'http-uri/request/path', u'no', u'starts-with',
                        u'/env', u'no', u'no']},
               {'row': [u'default', u'', u'no', u'', u'', u'no', u'no']}],
                'name': u'l7policy__rulesMatch'},
             {'columnNames': [u'Group', u'Target', u'Parameter'],
              'rows':
              [{'row': [0, u'forward/request/reset', u'none']},
               {'row': [u'default', u'forward/request/select/pool',
                        u'pool:0']}],
                'name': u"'l7policy__rulesAction"}]

        self.assertEquals(expected_name, self.test_iapp.name)
        self.assertEquals(expected_tables, self.test_iapp.tables)

    def test_delete_iapp(self, cloud_state='tests/marathon_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Marathon app associated with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.iapp_delete = self.bigip.iapp_delete_orig
        self.bigip.sys.application.services.get_collection = \
            Mock(side_effect=self.mock_iapp_services_get_collection)
        self.bigip.sys.application.services.service.load = \
            Mock(side_effect=self.mock_iapp_service_load)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.iapp_create.called)

        expected_name = 'server-app2_iapp_10000_vs'
        self.assertEqual(len(self.test_iapp_list), 1)
        self.assertEqual(self.test_iapp_list[0].partition,
                         self.test_partition)
        self.assertEqual(self.test_iapp_list[0].name, expected_name)
        self.assertEqual(self.test_iapp.partition, self.test_partition)
        self.assertEqual(self.test_iapp.name, expected_name)

    def test_https_app(
            self,
            cloud_state='tests/marathon_one_app_https.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Start Marathon app that uses HTTPS."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

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
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)

        # Restore the mocked 'update' functions to their original state
        self.bigip.pool_update = self.bigip.pool_update_orig
        self.bigip.virtual_update = self.bigip.virtual_update_orig
        self.bigip.member_update = self.bigip.member_update_orig
        self.bigip.healthcheck_update = self.bigip.healthcheck_update_orig

        # Mock the 'get' resource functions. We will use these to supply
        # mocked resources
        self.bigip.get_pool = Mock(side_effect=self.mock_get_pool)
        self.bigip.get_virtual = Mock(side_effect=self.mock_get_virtual)
        self.bigip.get_virtual_profiles = Mock(
            side_effect=self.mock_get_virtual_profiles)
        self.bigip.get_member = Mock(side_effect=self.mock_get_member)
        self.bigip.get_healthcheck = Mock(
            side_effect=self.mock_get_healthcheck)
        self.bigip.get_virtual_address = Mock(
            side_effect=self.mock_get_virtual_address)

        # Create a mock Pool
        pool_data_unchanged = {'monitor': '/mesos/server-app_80',
                               'balance': 'round-robin'}
        pool = self.create_mock_pool('server-app_80',
                                     **pool_data_unchanged)

        # Create a mock Virtual
        virtual_data_unchanged = {'enabled': True,
                                  'disabled': False,
                                  'ipProtocol': 'tcp',
                                  'destination': '/mesos/10.128.10.240:80',
                                  'pool': '/mesos/server-app_80',
                                  'sourceAddressTranslation':
                                  {'type': 'automap'},
                                  'profiles': [{'partition': 'Common',
                                                'name': 'clientssl'},
                                               {'partition': 'Common',
                                                'name': 'http'}]}
        virtual = self.create_mock_virtual('server-app_80',
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
            'send': 'GET / HTTP/1.0\\r\\n\\r\\n'
        }
        healthcheck = self.create_mock_healthcheck(
            'server-app_80', **health_data_unchanged)

        # Pool, Virtual, Member, and Healthcheck are not modified
        self.bigip.regenerate_config_f5(cfg)
        self.assertFalse(pool.modify.called)
        self.assertFalse(virtual.modify.called)
        self.assertFalse(virtual.profiles_s.profiles.create.called)
        self.assertFalse(member.modify.called)
        self.assertFalse(healthcheck.modify.called)

        # Pool is modified
        pool_data_changed = {
            'balance': 'least-connections',
            'monitor': 'server-app_8080'
        }
        for key in pool_data_changed:
            data = pool_data_unchanged.copy()
            # Change one thing
            data[key] = pool_data_changed[key]
            pool = self.create_mock_pool('server-app_80', **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(pool.modify.called)

        # Virtual is modified
        virtual_data_changed = {
            'enabled': False,
            'disabled': True,
            'ipProtocol': 'udp',
            'destination': '/Common/10.128.10.240:80',
            'pool': '/Common/server-app_80',
            'sourceAddressTranslation': {'type': 'snat'},
            'profiles': [{'partition': 'Common', 'name': 'clientssl'},
                         {'partition': 'Common', 'name': 'tcp'}]
        }
        for key in virtual_data_changed:
            data = virtual_data_unchanged.copy()
            # Change one thing
            data[key] = virtual_data_changed[key]
            virtual = self.create_mock_virtual('server-app_80',
                                               **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(virtual.modify.called)

        # Member is modified
        member_data_changed = {
            'state': 'user-down',
            'session': 'user-disabled'
        }
        for key in member_data_changed:
            data = member_data_unchanged.copy()
            # Change one thing
            data[key] = member_data_changed[key]
            member = self.create_mock_pool_member('10.141.141.10:31132',
                                                  **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(member.modify.called)

        # Healthcheck is modified
        health_data_changed = {
            'interval': 10,
            'timeout': 30,
            'send': 'GET /mypath HTTP/1.0\\r\\n\\r\\n'
        }
        for key in health_data_changed:
            data = health_data_unchanged.copy()
            # Change one thing
            data[key] = health_data_changed[key]
            healthcheck = self.create_mock_healthcheck(
                'server-app_80', **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(healthcheck.modify.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)

    def test_event_processor(self):
        """Test Marathon event processing."""
        args_app_name = ['marathon-bigip-ctlr.py']
        args_mandatory = ['--marathon', 'http://10.0.0.10:8080',
                          '--partition', 'mesos',
                          '--hostname', '10.10.1.145',
                          '--username', 'admin',
                          '--password', 'default']
        sys.argv[0:] = args_app_name + args_mandatory
        args = ctlr.parse_args()
        marathon = ctlr.Marathon(args.marathon,
                                 args.health_check,
                                 get_marathon_auth_params(args))

        ctlr.Marathon.list = Mock(return_value=[])
        ctlr.Marathon.health_check = Mock(return_value=True)
        ctlr.MarathonEventProcessor.start_checkpoint_timer = Mock()
        ctlr.MarathonEventProcessor.retry_backoff = Mock()
        ep = ctlr.MarathonEventProcessor(marathon, 100, self.bigip)

        event_empty = Event(data='')
        event_app = Event(data='{"eventType": "app_terminated_event"}')
        event_unknown = Event(data='{"eventType": "unknown_event"}')
        event_detached = Event(data='{"eventType": "event_stream_detached"}')
        event_invalid = Event(data='{"eventType": }')
        events = [event_empty, event_app, event_unknown, event_detached]

        with patch.object(self.bigip, 'regenerate_config_f5',
                          return_value=False):
            ctlr.process_sse_events(ep, events, self.bigip)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid], self.bigip)
            time.sleep(1)

        with patch.object(self.bigip, 'regenerate_config_f5',
                          side_effect=requests.exceptions.ConnectionError):
            ctlr.process_sse_events(ep, events, self.bigip)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid], self.bigip)
            time.sleep(1)

        with patch.object(self.bigip, 'regenerate_config_f5',
                          side_effect=TypeError):
            ctlr.process_sse_events(ep, events, self.bigip)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid], self.bigip)
            time.sleep(1)

        with patch.object(self.bigip, 'regenerate_config_f5',
                          return_value=True):
            ctlr.process_sse_events(ep, events, self.bigip)
            self.assertRaises(ValueError, ctlr.process_sse_events, ep,
                              [event_invalid], self.bigip)

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

    def test_app_with_two_healthchecks(
            self,
            cloud_state='tests/marathon_one_app_two_health_checks.json',
            bigip_state='tests/bigip_test_app_two_monitors.json',
            hm_state='tests/bigip_test_one_app_two_monitors.json'):
        """Test: Marathon app with one app and two health monitors."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertEqual(self.bigip.healthcheck_update.call_count, 2)
        self.assertEqual(self.bigip.pool_update.call_count, 2)
        health_checks = self.bigip.healthcheck_update.call_args_list
        pool_list = self.bigip.get_pool_list("mesos")
        for i in range(0, 1):
            hc = health_checks[i][0][2]
            name = hc['name']
            self.assertTrue(name in self.hm_data)
            self.assertTrue(name in pool_list)
            self.assertEqual(hc['protocol'], self.hm_data[name]['type'])

    def test_create_pool_only(
            self,
            cloud_state='tests/marathon_one_app_pool_only.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app that does not create a virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)
        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 0)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        expected_name = 'server-app_80'
        self.assertEqual(expected_name, self.test_pool[0]['name'])
        self.assertEqual(expected_name, self.test_monitor[0]['name'])
        self.assertEqual(self.test_partition, self.test_pool[0]['partition'])
        self.assertEqual(self.test_partition,
                         self.test_monitor[0]['partition'])

    def test_pool_only_to_virtual_server(
            self,
            cloud_state='tests/marathon_one_app_pool_only.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app without a virtual server gets virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Mock out functions not directly under test
        self.bigip.get_pool_list = Mock(side_effect=self.mock_get_pool_list)
        self.bigip.get_virtual_list = \
            Mock(side_effect=self.mock_get_virtual_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)
        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP initial configuration
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 0)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        # Reconfigure BIG-IP by adding virtual server to existing pool
        self.cloud_data[1]['labels'].update({unicode('F5_0_MODE'):
                                             unicode('http'),
                                             unicode('F5_0_BIND_ADDR'):
                                             unicode('10.128.10.240')})
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)
        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP reconfiguration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        expected_name = 'server-app_80'
        self.assertEqual(expected_name, self.test_pool[0]['name'])
        self.assertEqual(expected_name, self.test_monitor[0]['name'])
        self.assertEqual(expected_name, self.test_virtual[0]['name'])
        self.assertEqual(self.test_partition, self.test_pool[0]['partition'])
        self.assertEqual(self.test_partition,
                         self.test_monitor[0]['partition'])
        self.assertEqual(self.test_partition,
                         self.test_virtual[0]['partition'])

    def test_virtual_server_to_pool_only(
            self,
            cloud_state='tests/marathon_one_app.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app with virtual server removes virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Mock out functions not directly under test
        self.bigip.get_pool_list = Mock(side_effect=self.mock_get_pool_list)
        self.bigip.get_virtual_list = \
            Mock(side_effect=self.mock_get_virtual_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)
        self.bigip.virtual_delete = Mock(side_effect=self.mock_virtual_delete)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)
        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP initial configuration
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        # Reconfigure BIG-IP by adding virtual server to existing pool
        self.cloud_data[1]['labels'].pop(unicode('F5_0_MODE'))
        self.cloud_data[1]['labels'].pop(unicode('F5_0_BIND_ADDR'))
        apps = ctlr.get_apps(self.cloud_data, True)
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)
        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP reconfiguration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        expected_name = 'server-app_80'
        self.assertEqual(expected_name, self.test_pool[0]['name'])
        self.assertEqual(expected_name, self.test_monitor[0]['name'])
        self.assertEqual(self.test_partition, self.test_pool[0]['partition'])
        self.assertEqual(self.test_partition,
                         self.test_monitor[0]['partition'])
        self.assertEqual(0, len(self.test_virtual))

    def test_updates_pool_only(
            self,
            cloud_state='tests/marathon_one_app_pool_only.json',
            bigip_state='tests/bigip_test_one_app.json',
            hm_state='tests/bigip_test_one_monitor.json'):
        """Test: Verify BIG-IP updates in pool only mode.

        Verify that resources are only updated when the state
        of the resource changes.
        """
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)

        # Restore the mocked 'update' functions to their original state
        self.bigip.pool_update = self.bigip.pool_update_orig
        self.bigip.member_update = self.bigip.member_update_orig
        self.bigip.healthcheck_update = self.bigip.healthcheck_update_orig

        # Mock the 'get' resource functions. We will use these to supply
        # mocked resources
        self.bigip.get_pool = Mock(side_effect=self.mock_get_pool)
        self.bigip.get_virtual = Mock(side_effect=self.mock_get_virtual)
        self.bigip.get_member = Mock(side_effect=self.mock_get_member)
        self.bigip.get_healthcheck = Mock(
            side_effect=self.mock_get_healthcheck)

        # Create a mock Pool
        pool_data_unchanged = {'monitor': '/mesos/server-app_80',
                               'balance': 'round-robin'}
        pool = self.create_mock_pool('server-app_80',
                                     **pool_data_unchanged)

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
            'send': 'GET / HTTP/1.0\\r\\n\\r\\n'
        }
        healthcheck = self.create_mock_healthcheck(
            'server-app_80', **health_data_unchanged)

        # Pool, Member, and Healthcheck are not modified
        cfg = ctlr.create_config_marathon(self.bigip, apps)
        self.bigip.regenerate_config_f5(cfg)
        self.assertFalse(pool.modify.called)
        self.assertFalse(member.modify.called)
        self.assertFalse(healthcheck.modify.called)

        # Pool is modified
        pool_data_changed = {
            'balance': 'least-connections',
            'monitor': 'server-app_8080'
        }
        for key in pool_data_changed:
            data = pool_data_unchanged.copy()
            # Change one thing
            data[key] = pool_data_changed[key]
            pool = self.create_mock_pool('server-app_80', **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(pool.modify.called)

        # Member is modified
        member_data_changed = {
            'state': 'user-down',
            'session': 'user-disabled'
        }
        for key in member_data_changed:
            data = member_data_unchanged.copy()
            # Change one thing
            data[key] = member_data_changed[key]
            member = self.create_mock_pool_member('10.141.141.10:31132',
                                                  **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(member.modify.called)

        # Healthcheck is modified
        health_data_changed = {
            'interval': 10,
            'timeout': 30,
            'send': 'GET /mypath HTTP/1.0\\r\\n\\r\\n'
        }
        for key in health_data_changed:
            data = health_data_unchanged.copy()
            # Change one thing
            data[key] = health_data_changed[key]
            healthcheck = self.create_mock_healthcheck(
                'server-app_80', **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(healthcheck.modify.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)


class HealthCheckParmsTest(unittest.TestCase):
    """Tests for validating what is sent to the Big-IP for health monitors."""

    http_keys = ('adaptive',
                 'adaptiveDivergenceType',
                 'adaptiveDivergenceValue',
                 'adaptiveLimit',
                 'adaptiveSamplingTimespan',
                 'appService',
                 'defaultsFrom',
                 'description',
                 'destination',
                 'interval',
                 'ipDscp',
                 'manualResume',
                 'name',
                 'tmPartition',
                 'password',
                 'recv',
                 'recvDisable',
                 'reverse',
                 'send',
                 'timeUntilUp',
                 'timeout',
                 'transparent',
                 'upInterval',
                 'username',
                 )
    tcp_keys = ('adaptive',
                'adaptiveDivergenceType',
                'adaptiveDivergenceValue',
                'adaptiveLimit',
                'adaptiveSamplingTimespan',
                'appService',
                'defaultsFrom',
                'description',
                'destination',
                'interval',
                'ipDscp',
                'manualResume',
                'name',
                'tmPartition',
                'recv',
                'recvDisable',
                'reverse',
                'send',
                'timeUntilUp',
                'timeout',
                'transparent',
                'upInterval',
                )
    tcpHealthData = {}
    httpHealthData = {}
    partition = 'hctest'
    health_monitor = None

    def setUp(self):
        """Test suite set up."""
        with patch.object(BigIP, '_get_tmos_version'):
            self.bigip = CloudBigIP('1.2.3.4', '443', 'admin',
                                    'default', [self.partition])
        self.bigip.get_healthcheck = Mock(
            side_effect=self.mock_get_healthcheck)
        self.bigip.get_http_healthmonitor = Mock(
            side_effect=self.mock_get_healthmonitor)
        self.bigip.get_tcp_healthmonitor = Mock(
            side_effect=self.mock_get_healthmonitor)

        self.bigip.healthcheck_exists = Mock()
        self.bigip.healthcheck_exists.return_value = {'http': True,
                                                      'tcp': True}
        self.httpHealthData = {
            'description': 'this one is http',
            'portIndex': 0,
            'protocol': 'http',
            'timeoutSeconds': 20,
            'interval': 20,
            'intervalSeconds': 20,
            'ignoreHttp1xx': False,
            'gracePeriodSeconds': 5,
            'send': 'GET / HTTP/1.0\\r\\n\\r\\n',
            'timeout': 61,
            'maxConsecutiveFailures': 3,
            'path': '/',
            'username': 'admin',
            'password': 'changeme',
            }
        self.tcpHealthData = {
            'description': 'this one is tcp',
            'portIndex': 0,
            'protocol': 'tcp',
            'timeoutSeconds': 20,
            'interval': 20,
            'intervalSeconds': 20,
            'ignoreHttp1xx': False,
            'gracePeriodSeconds': 5,
            'send': None,
            'timeout': 61,
            'maxConsecutiveFailures': 3,
            'path': '/',
            'username': 'admin',
            'password': 'changeme',
            }

    def mock_get_healthmonitor(self):
        """Map this call to our cached health_monitor."""
        return self.health_monitor

    def mock_get_healthcheck(self, partition, hc, hc_type):
        """Map this call to our cached health_monitor."""
        return self.health_monitor

    def validate_http_data(self, **data):
        """Make sure only valid http data is present in the dict."""
        for k in data:
            self.assertTrue(k in self.http_keys)

    def validate_tcp_data(self, **data):
        """Make sure only valid tcp data is present in the dict."""
        for k in data:
            self.assertTrue(k in self.tcp_keys)

    def mock_healthcheck_create_http(self, partition, **data):
        """Mock which gets called to actually do the create."""
        self.validate_http_data(**data)

    def mock_healthcheck_modify_http(self, **data):
        """Mock which gets called to actually do the modify."""
        self.validate_http_data(**data)

    def mock_healthcheck_create_tcp(self, partition, **data):
        """Mock which gets called to actually do the create."""
        self.validate_tcp_data(**data)

    def mock_healthcheck_modify_tcp(self, **data):
        """Mock which gets called to actually do the modify."""
        self.validate_tcp_data(**data)

    def test_healthmonitor_http(self):
        """Test creating and updating http health monitors."""
        hc = HealthCheck('http-server')
        hc.create = Mock(side_effect=self.mock_healthcheck_create_http)
        hc.modify = Mock(side_effect=self.mock_healthcheck_modify_http)
        self.health_monitor = hc
        self.bigip.healthcheck_create(self.partition, self.httpHealthData)
        self.assertTrue(hc.create.called)
        self.httpHealthData['description'] = 'this should trigger a modify'
        self.bigip.healthcheck_update(self.partition, hc, self.httpHealthData)
        self.assertTrue(hc.modify.called)

    def test_healthmonitor_tcp(self):
        """Test creating and updating tcp health monitors."""
        hc = HealthCheck('tcp-server')
        hc.create = Mock(side_effect=self.mock_healthcheck_create_tcp)
        hc.modify = Mock(side_effect=self.mock_healthcheck_modify_tcp)
        self.health_monitor = hc
        self.bigip.healthcheck_create(self.partition, self.tcpHealthData)
        self.assertTrue(hc.create.called)
        self.tcpHealthData['description'] = 'this should trigger a modify'
        self.bigip.healthcheck_update(self.partition, hc, self.tcpHealthData)
        self.assertTrue(hc.modify.called)

    def test_healthcheck_update_change_protocol_http(self):
        """Test updating the protocol for a health monitor from http to tcp."""
        hc = HealthCheck('http-server')
        hc.create = Mock(side_effect=self.mock_healthcheck_create_http)
        hc.modify = Mock()
        fake_pool = Pool('fake_pool', monitor='test_monitor')
        self.health_monitor = hc
        # Mock that the monitor already exists in the http protocol
        self.bigip.healthcheck_exists.return_value = {'http': True,
                                                      'tcp': False}
        self.bigip.healthcheck_create = Mock(
            wraps=self.bigip.healthcheck_create)
        self.bigip.monitor_protocol_change = Mock(
            wraps=self.bigip.monitor_protocol_change)
        self.bigip.healthcheck_delete = Mock()
        self.bigip.get_pool = Mock(return_value=fake_pool)
        # Create the health monitor
        self.bigip.healthcheck_create(self.partition, self.httpHealthData)
        self.assertTrue(hc.create.called)
        hc.create.side_effect = self.mock_healthcheck_create_tcp
        # Update the health monitor with our new protocol
        self.bigip.healthcheck_update(self.partition, hc, self.tcpHealthData)
        self.assertTrue(self.bigip.healthcheck_delete.called)
        self.assertEqual(self.bigip.healthcheck_create.call_count, 2)
        self.assertEqual(hc.create.call_count, 2)
        self.assertFalse(hc.modify.called)
        # Verify monitor_protocol_change is called with the old protocol
        self.assertEqual(self.bigip.monitor_protocol_change.call_args[0][3],
                         'http')

    def test_healthcheck_update_change_protocol_tcp(self):
        """Test updating the protocol for a health monitor from tcp to http."""
        hc = HealthCheck('tcp-server')
        hc.create = Mock(side_effect=self.mock_healthcheck_create_tcp)
        hc.modify = Mock()
        fake_pool = Pool('fake_pool', monitor='test_monitor')
        self.health_monitor = hc
        # Mock that the monitor already exists in the tcp protocol
        self.bigip.healthcheck_exists.return_value = {'http': False,
                                                      'tcp': True}
        self.bigip.healthcheck_create = Mock(
            wraps=self.bigip.healthcheck_create)
        self.bigip.monitor_protocol_change = Mock(
            wraps=self.bigip.monitor_protocol_change)
        self.bigip.healthcheck_delete = Mock()
        self.bigip.get_pool = Mock(return_value=fake_pool)
        # Create the health monitor
        self.bigip.healthcheck_create(self.partition, self.tcpHealthData)
        self.assertTrue(hc.create.called)
        hc.create.side_effect = self.mock_healthcheck_create_http
        # Update the health monitor with our new protocol
        self.bigip.healthcheck_update(self.partition, hc, self.httpHealthData)
        self.assertTrue(self.bigip.healthcheck_delete.called)
        self.assertEqual(self.bigip.healthcheck_create.call_count, 2)
        self.assertEqual(hc.create.call_count, 2)
        self.assertFalse(hc.modify.called)
        # Verify monitor_protocol_change is called with the old protocol
        self.assertEqual(self.bigip.monitor_protocol_change.call_args[0][3],
                         'tcp')


class GetProtocolTest(unittest.TestCase):
    """Test marathon-bigip-ctlr get_protocol function."""

    def test_get_protocol_valid_input(self):
        """Test get_protocol with valid input."""
        valid = ['tcp', 'http', 'udp', 'TCP', 'HTTP', 'UDP', 'tCp', 'Http',
                 'udP']
        exp_res = ['tcp', 'tcp', 'udp', 'tcp', 'tcp', 'udp', 'tcp', 'tcp',
                   'udp']
        for i in range(0, len(valid)):
            res = get_protocol(valid[i])
            self.assertEqual(res, exp_res[i])

    def test_get_protocol_invalid_input(self):
        """Test get_protocol with invalid input."""
        invalid = ['abc', 'ABC', 'aBc', '', ' ', True, 1, [], {}]
        for i in range(0, len(invalid)):
            res = get_protocol(invalid[i])
            self.assertEqual(res, None)


class MockAppLabelData():
    """Mock marathon label data."""

    def __init__(self, proto, port, addr, balance):
        """Initialize a MockAppLabelData object."""
        self.appId = 'mockApp'
        self.mode = proto
        self.servicePort = port
        self.bindAddr = addr
        self.balance = balance


class IsLabelDataValidTest(unittest.TestCase):
    """Test marathon-bigip-ctlr is_label_data_valid method."""

    def setUp(self):
        """Test suite set up."""
        with patch.object(BigIP, '_get_tmos_version'):
            self.bigip = CloudBigIP('1.2.3.4', '443', 'admin',
                                    'default', ['test'])

    def test_is_label_data_valid_valid_input(self):
        """Test is_label_data_valid with valid input."""
        proto = ['tcp', 'http', 'udp']
        port = [1, 10000, 65535]
        addr = [unicode('192.168.0.1'), unicode('2001:db8::')]
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
            app = MockAppLabelData(proto[i], port[0], addr[0], balance[0])
            res = self.bigip.is_label_data_valid(app)
            self.assertTrue(res)
        for i in range(0, len(port)):
            app = MockAppLabelData(proto[0], port[i], addr[0], balance[0])
            res = self.bigip.is_label_data_valid(app)
            self.assertTrue(res)
        for i in range(0, len(addr)):
            app = MockAppLabelData(proto[0], port[0], addr[i], balance[0])
            res = self.bigip.is_label_data_valid(app)
            self.assertTrue(res)
        for i in range(0, len(balance)):
            app = MockAppLabelData(proto[0], port[0], addr[0], balance[i])
            res = self.bigip.is_label_data_valid(app)
            self.assertTrue(res)

    def test_is_label_data_valid_invalid_input(self):
        """Test is_label_data_valid with invalid input."""
        proto = ['abc', 'ABC', 'abc', '', ' ', 1, False, [], {}]
        port = [0, -10000, 65536, '123', '', False, [], {}]
        addr = [unicode('258.0.0.1'), unicode('2001:dg8::1'),
                unicode('string'), unicode(''), unicode(' '), 'string', True,
                [], {}]
        balance = ['string', '', ' ', 123, False, [], {}]
        for i in range(0, len(proto)):
            app = MockAppLabelData(proto[i], port[0], addr[0], balance[0])
            res = self.bigip.is_label_data_valid(app)
            self.assertFalse(res)
        for i in range(0, len(port)):
            app = MockAppLabelData(proto[0], port[i], addr[0], balance[0])
            res = self.bigip.is_label_data_valid(app)
            self.assertFalse(res)
        for i in range(0, len(addr)):
            app = MockAppLabelData(proto[0], port[0], addr[i], balance[0])
            res = self.bigip.is_label_data_valid(app)
            self.assertFalse(res)
        for i in range(0, len(balance)):
            app = MockAppLabelData(proto[0], port[0], addr[0], balance[i])
            res = self.bigip.is_label_data_valid(app)
            self.assertFalse(res)


if __name__ == '__main__':
    unittest.main()
