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
import f5
import icontrol
import requests
import os
from mock import Mock
from mock import patch
from common import DCOSAuth, ipv4_to_mac
from f5.bigip import BigIP
from _f5 import CloudBigIP
from StringIO import StringIO
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

    def test_hostname_arg(self):
        """Test: Hostname arg."""
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

    def test_timeout_arg(self):
        """Test: 'SSE timeout' arg."""
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

        sys.argv[0:] = self._args_app_name + self._args_mandatory + \
            ['--dcos-auth-credentials', creds]
        args = ctlr.parse_args()
        self.assertEqual(args.dcos_auth_credentials, creds)

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
        return r


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

    def update(self, **kwargs):
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


class VxLANTunnel():
    """A mock BIG-IP VxLAN tunnel."""

    def __init__(self, partition, name, initial_records):
        """Initialize the object."""
        self.partition = partition
        self.name = name
        self.records = initial_records

    def update(self, **kwargs):
        """Update list of vxlan records."""
        self.records = []
        if 'records' in kwargs:
            self.records = kwargs['records']


class BigIPTest(unittest.TestCase):
    """BIG-IP configuration tests.

    Test BIG-IP configuration given various cloud states and existing
    BIG-IP states
    """

    virtuals = {}
    profiles = {}
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
        self.profiles = kwargs.get('profiles', [])
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

    def mock_get_virtual_profiles(self, virtual):
        """Return a list of Virtual Server profiles."""
        return self.profiles

    def mock_net_fdb_tunnels_tunnel_load(self, partition, name):
        """Mock: Get a mocked vxla tunnel to store the vxlan record config."""
        if not hasattr(self, 'vxlan_tunnel'):
            # create a BigIP resource to store the 'current' tunnel
            # FDB as well as updates.
            self.vxlan_tunnel = VxLANTunnel(partition, name, self.network_data)
        return self.vxlan_tunnel

    def read_test_vectors(self, cloud_state, bigip_state=None,
                          hm_state=None, network_state=None):
        """Read test vectors for the various states."""
        # Read the Marathon state
        if cloud_state:
            with open(cloud_state) as json_data:
                self.cloud_data = json.load(json_data)

        # Read the BIG-IP state
        if bigip_state:
            with open(bigip_state) as json_data:
                self.bigip_data = json.load(json_data)
            self.bigip.get_pool_list = Mock(
                    return_value=self.bigip_data.keys())
            self.bigip.get_virtual_list = Mock(
                    return_value=self.bigip_data.keys())
        else:
            self.bigip_data = {}
            self.bigip.get_pool_list = Mock(
                    return_value=[])
            self.bigip.get_virtual_list = Mock(
                    return_value=[])

        if hm_state:
            with open(hm_state) as json_data:
                self.hm_data = json.load(json_data)
        else:
            self.hm_data = {}

        if network_state:
            with open(network_state) as json_data:
                self.network_data = json.load(json_data)

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
            self.bigip = CloudBigIP(cloud, '1.2.3.4', '443', 'admin',
                                    'default', [partition])

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
        self.bigip.fdb_records_update_orig = self.bigip.fdb_records_update
        self.bigip.get_fdb_records_orig = self.bigip.get_fdb_records
        self.bigip.healthcheck_exists_orig = self.bigip.healthcheck_exists

        self.bigip.get_node = Mock()
        self.bigip.pool_create = Mock()
        self.bigip.pool_delete = Mock()
        self.bigip.pool_update = Mock()

        self.bigip.healthcheck_create = Mock()
        self.bigip.healthcheck_delete = Mock()
        self.bigip.healthcheck_update = Mock()
        self.bigip.healthcheck_exists = Mock()
        self.bigip.healthcheck_exists.return_value = {'http': True,
                                                      'tcp': True}

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

        # mock out the bigip.net.fdb.tunnels.tunnel resource
        self.bigip.net = type('', (), {})()
        self.bigip.net.fdb = type('', (), {})()
        self.bigip.net.fdb.tunnels = type('', (), {})()
        self.bigip.net.fdb.tunnels.tunnel = type('', (), {})()
        self.bigip.net.fdb.tunnels.tunnel.load = \
            Mock(side_effect=self.mock_net_fdb_tunnels_tunnel_load)

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
        apps = ctlr.get_apps(self.cloud_data, True)

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
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.virtual_create.called)
        self.assertTrue(self.bigip.pool_create.called)
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.healthcheck_delete.called)

        expected_name = 'my_services_test-2_server-app_10.128.10.240_80'
        self.assertEquals(self.bigip.virtual_create.call_args[0][1],
                          expected_name)
        self.assertEquals(self.bigip.pool_create.call_args[0][1],
                          expected_name)
        self.assertEquals(self.bigip.member_create.call_args[0][1],
                          expected_name)

    def test_no_change(self, cloud_state='tests/marathon_two_apps.json',
                       bigip_state='tests/bigip_test_no_change.json',
                       hm_state='tests/bigip_test_two_monitors.json'):
        """Test: No Marathon state change."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, False)
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

        config = self.bigip.iapp_create.call_args_list[0][0][2]
        iapp_def = self.bigip.iapp_build_definition(config)

        self.assertEquals(expected_tables, iapp_def['tables'])
        self.assertEquals(expected_variables, iapp_def['variables'])

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

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        self.assertEquals(self.bigip.iapp_create.call_count, 1)

        expected_name = 'server-app2_iapp_10000'
        self.assertEquals(self.bigip.iapp_create.call_args_list[0][0][1],
                          expected_name)

        # Verify the iapp variables and tables
        config = self.bigip.iapp_create.call_args_list[0][0][2]
        iapp_def = self.bigip.iapp_build_definition(config)
        self.assertEquals(expected_tables, iapp_def['tables'])

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

    def test_new_iapp_with_tables(
            self,
            cloud_state='tests/marathon_one_iapp_with_tables.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app with iApp with iApp tables."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, False)
        self.bigip.regenerate_config_f5(apps)

        self.check_labels(self.cloud_data, apps)

        self.assertEquals(self.bigip.iapp_create.call_count, 1)

        expected_name = 'server-app2_iapp_10000'
        self.assertEquals(self.bigip.iapp_create.call_args_list[0][0][1],
                          expected_name)

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

        config = self.bigip.iapp_create.call_args_list[0][0][2]
        iapp_def = self.bigip.iapp_build_definition(config)
        self.assertEquals(expected_tables, iapp_def['tables'])

    def test_delete_iapp(self, cloud_state='tests/marathon_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Marathon app associated with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_list)

        # Do the BIG-IP configuration
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)
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
        apps = ctlr.get_apps(self.cloud_data, True)

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
                                                'name': 'clientssl'},
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
            'send': 'GET / HTTP/1.0\\r\\n\\r\\n'
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
            data = pool_data_unchanged.copy()
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
            'sourceAddressTranslation': {'type': 'snat'},
            'profiles': [{'partition': 'Common', 'name': 'clientssl'},
                         {'partition': 'Common', 'name': 'tcp'}]
        }
        for key in virtual_data_changed:
            data = virtual_data_unchanged.copy()
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
            data = member_data_unchanged.copy()
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
            'send': 'GET /mypath HTTP/1.0\\r\\n\\r\\n'
        }
        for key in health_data_changed:
            data = health_data_unchanged.copy()
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


class KubernetesTest(BigIPTest):
    """Kubernetes/Big-IP configuration tests.

    Test BIG-IP configuration given various Kubernetes states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        super(KubernetesTest, self).setUp('kubernetes', 'k8s')

    def test_svc_create(self,
                        cloud_state='tests/kubernetes_one_svc_two_nodes.json',
                        bigip_state='tests/bigip_test_blank.json',
                        hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service created."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

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
        self.assertTrue(self.bigip.healthcheck_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)
        self.assertEqual(self.bigip.healthcheck_create.call_count, 2)
        expected_name = 'foo_10.128.10.240_5051'
        self.assertEquals(self.bigip.healthcheck_create.
                          call_args_list[0][0][1]['name'],
                          expected_name)
        expected_name = 'foo_10.128.10.240_5051_1'
        self.assertEquals(self.bigip.healthcheck_create.
                          call_args_list[1][0][1]['name'],
                          expected_name)

    def test_svc_scaled_down(
            self,
            cloud_state='tests/kubernetes_one_svc_one_node.json',
            bigip_state='tests/bigip_test_one_svc_two_nodes.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service scaled down."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

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
        self.bigip.regenerate_config_f5(self.cloud_data)

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
        self.bigip.regenerate_config_f5(self.cloud_data)

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

        # Verfiy the iapp variables and tables
        expected_tables = \
            [{'columnNames': ['addr', 'port', 'connection_limit'], 'rows':
             [{'row': [u'172.16.0.5', u'30008', '0']}],
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

        config = self.bigip.iapp_create.call_args_list[0][0][2]
        iapp_def = self.bigip.iapp_build_definition(config)

        self.assertEquals(expected_tables, iapp_def['tables'])
        self.assertEquals(expected_variables, iapp_def['variables'])

    def test_delete_iapp(self, cloud_state='tests/kubernetes_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Kubernetes app associated with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.get_iapp_list = \
            Mock(side_effect=self.mock_get_iapp_list)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

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

    def test_updates(self,
                     cloud_state='tests/kubernetes_one_svc_two_nodes.json',
                     bigip_state='tests/bigip_test_one_svc_two_nodes.json',
                     hm_state='tests/bigip_test_blank.json'):
        """Test: Verify BIG-IP updates.

        Verify that resources are only updated when the state
        of the resource changes.
        """
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Restore the mocked 'update' functions to their original state
        self.bigip.pool_update = self.bigip.pool_update_orig
        self.bigip.virtual_update = self.bigip.virtual_update_orig
        self.bigip.member_update = self.bigip.member_update_orig

        # Mock the 'get' resource functions. We will use these to supply
        # mocked resources
        self.bigip.get_pool = Mock(side_effect=self.mock_get_pool)
        self.bigip.get_virtual = Mock(side_effect=self.mock_get_virtual)
        self.bigip.get_virtual_profiles = Mock(
            side_effect=self.mock_get_virtual_profiles)
        self.bigip.get_member = Mock(side_effect=self.mock_get_member)
        self.bigip.get_virtual_address = Mock(
            side_effect=self.mock_get_virtual_address)

        # Create a mock Pool
        pool_data_unchanged = {'monitor': '/k8s/foo_10.128.10.240_5051 and '
                                          '/k8s/foo_10.128.10.240_5051_1',
                               'balance': 'round-robin'}
        pool = self.create_mock_pool('foo_10.128.10.240_5051',
                                     **pool_data_unchanged)

        # Create a mock Virtual
        virtual_data_unchanged = {'enabled': True,
                                  'disabled': False,
                                  'ipProtocol': 'tcp',
                                  'destination': '/k8s/10.128.10.240:5051',
                                  'pool': '/k8s/foo_10.128.10.240_5051',
                                  'sourceAddressTranslation':
                                  {'type': 'automap'},
                                  'profiles': [{'partition': 'Common',
                                                'name': 'clientssl'},
                                               {'partition': 'Common',
                                                'name': 'http'}]}
        virtual = self.create_mock_virtual('foo_10.128.10.240_5051',
                                           **virtual_data_unchanged)

        # Create mock Pool Members
        member_data_unchanged = {'state': 'user-up', 'session': 'user-enabled'}
        member = self.create_mock_pool_member('172.16.0.5:30008',
                                              **member_data_unchanged)
        member = self.create_mock_pool_member('172.16.0.6:30008',
                                              **member_data_unchanged)

        # Pool, Virtual, and Member are not modified
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertFalse(pool.modify.called)
        self.assertFalse(virtual.modify.called)
        self.assertFalse(virtual.profiles_s.profiles.create.called)
        self.assertFalse(member.modify.called)

        # Pool is modified
        pool_data_changed = {
            'balance': 'least-connections'
        }
        for key in pool_data_changed:
            data = pool_data_unchanged.copy()
            # Change one thing
            data[key] = pool_data_changed[key]
            pool = self.create_mock_pool('foo_10.128.10.240_5051', **data)
            self.bigip.regenerate_config_f5(self.cloud_data)
            self.assertTrue(pool.modify.called)

        # Virtual is modified
        virtual_data_changed = {
            'enabled': False,
            'disabled': True,
            'ipProtocol': 'udp',
            'destination': '/Common/10.128.10.240:5051',
            'pool': '/Common/foo_10.128.10.240_5051',
            'sourceAddressTranslation': {'type': 'snat'},
            'profiles': [{'partition': 'Common', 'name': 'clientssl'},
                         {'partition': 'Common', 'name': 'tcp'}]
        }
        for key in virtual_data_changed:
            data = virtual_data_unchanged.copy()
            # Change one thing
            data[key] = virtual_data_changed[key]
            virtual = self.create_mock_virtual('foo_10.128.10.240_5051',
                                               **data)
            self.bigip.regenerate_config_f5(self.cloud_data)
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
            member = self.create_mock_pool_member('172.16.0.5:30008',
                                                  **data)
            self.bigip.regenerate_config_f5(self.cloud_data)
            self.assertTrue(member.modify.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.virtual_create.called)
        self.assertFalse(self.bigip.virtual_delete.called)
        self.assertFalse(self.bigip.pool_create.called)
        self.assertFalse(self.bigip.pool_delete.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)

    def test_network_0_existing_vxlan_nodes_0_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_0_records.json',
            cloud_state='tests/kubernetes_openshift_0_nodes.json'):
        """Test: openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

        # Verify we only query bigip once for the initial state and
        # don't try to write an update if nothing has changed.
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 1)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_1_existing_vxlan_nodes_1_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_1_record.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: openshift environment with 1 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

        # Verify we only query bigip once for the initial state and
        # don't try to write an update if nothing has changed.
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 1)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_1_existing_vxlan_nodes_0_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_1_record.json',
            cloud_state='tests/kubernetes_openshift_0_nodes.json'):
        """Test: openshift environment with 1 existing node, 0 requested."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_0_existing_vxlan_nodes_1_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_0_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: openshift environment with 0 existing nodes, 1 requested."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_1_existing_vxlan_nodes_3_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_1_record.json',
            cloud_state='tests/kubernetes_openshift_3_nodes.json'):
        """Test: Kubernetes openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_3_existing_vxlan_nodes_1_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_3_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: Kubernetes openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        self.bigip.regenerate_config_f5(self.cloud_data)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_bad_vxlan_ip(
            self,
            network_state='tests/bigip_test_vxlan_3_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: BigIP not updated if IP address in badly formatted."""
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Verify original configuration is untouched if we have errors
        # in the cloud config file
        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = '55'
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = 55
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = 'myaddr'
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

    def test_network_bad_partition_name(
            self,
            network_state='tests/bigip_test_vxlan_3_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: BigIP not updated if the partition name format is bad."""
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Verify original configuration is untouched if we have errors
        # in the cloud config file
        self.cloud_data['openshift-sdn']['vxlan-name'] = \
            '/bad/partition/name/idf/'
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

        self.cloud_data['openshift-sdn']['vxlan-name'] = \
            'bad/partition/name'
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

        self.cloud_data['openshift-sdn']['vxlan-name'] = ''
        self.bigip.regenerate_config_f5(self.cloud_data)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

    def compute_fdb_records(self):
        """Create a FDB record for each openshift node."""
        records = []
        if self.cloud_data and 'openshift-sdn' in self.cloud_data and \
                'vxlan-node-ips' in self.cloud_data['openshift-sdn']:
            for node_ip in self.cloud_data['openshift-sdn']['vxlan-node-ips']:
                record = {'endpoint': node_ip, 'name': ipv4_to_mac(node_ip)}
                records.append(record)
        return records


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
            self.bigip = CloudBigIP('mesos', '1.2.3.4', '443', 'admin',
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


if __name__ == '__main__':
    unittest.main()
