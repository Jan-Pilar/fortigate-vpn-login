import unittest
from unittest.mock import patch

from fortigate_vpn_login.tls import TLSRefreshError, VerifiedPins
from fortigate_vpn_login.utils import get_gateway_cert_hash


class GatewayCertificateHashTest(unittest.TestCase):
    @patch('fortigate_vpn_login.utils.refresh_pins')
    def test_uses_ca_verified_public_key_pin(self, refresh):
        refresh.return_value = VerifiedPins('verified-leaf', 'pin-sha256:verified-key')
        self.assertEqual(get_gateway_cert_hash('vpn.example.com', 8443), 'pin-sha256:verified-key')
        refresh.assert_called_once_with('https://vpn.example.com:8443')

    @patch('fortigate_vpn_login.utils.refresh_pins')
    def test_refuses_unverified_certificate(self, refresh):
        refresh.side_effect = TLSRefreshError('untrusted issuer')
        self.assertIsNone(get_gateway_cert_hash('vpn.example.com'))

    @patch('fortigate_vpn_login.utils.refresh_pins')
    def test_formats_ipv6_literal(self, refresh):
        refresh.return_value = VerifiedPins('verified-leaf', 'pin-sha256:verified-key')
        get_gateway_cert_hash('2001:db8::1', 8443)
        refresh.assert_called_once_with('https://[2001:db8::1]:8443')


if __name__ == '__main__':
    unittest.main()
