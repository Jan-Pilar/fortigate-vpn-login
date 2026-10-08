import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

from fortigate_vpn_login.fortigate import FingerprintAdapter, Fortigate
from fortigate_vpn_login.tls import TLSRefreshError, VerifiedPins


class ConnectSamlErrorsTest(unittest.TestCase):
    def response(self):
        return Mock(status_code=200, text="<script>window.location='https://idp.example.com/login'</script>")

    @patch("fortigate_vpn_login.fortigate.requests.Session.get")
    def test_reports_tls_certificate_error(self, get):
        get.side_effect = requests.exceptions.SSLError(
            "certificate verify failed: unable to get local issuer certificate"
        )

        output = io.StringIO()
        with redirect_stdout(output):
            result = Fortigate("https://vpn.example.com").connect_saml()

        self.assertIsNone(result)
        self.assertIn("TLS certificate verification failed", output.getvalue())
        self.assertIn("full certificate chain", output.getvalue())

    @patch("fortigate_vpn_login.fortigate.requests.Session.get")
    def test_connection_error_includes_cause(self, get):
        get.side_effect = requests.exceptions.ConnectionError(
            "NameResolutionError: DNS lookup failed"
        )

        output = io.StringIO()
        with redirect_stdout(output):
            result = Fortigate("https://vpn.example.com").connect_saml()

        self.assertIsNone(result)
        self.assertIn("DNS lookup failed", output.getvalue())

    @patch("fortigate_vpn_login.fortigate.requests.Session.get")
    def test_tls_error_refreshes_and_retries_once(self, get):
        get.side_effect = [requests.exceptions.SSLError('old certificate'), self.response()]
        renew = Mock(return_value=VerifiedPins('AA:' * 31 + 'AA', 'pin-sha256:example'))
        client = Fortigate('https://vpn.example.com', tls_refresh=renew)
        with redirect_stdout(io.StringIO()) as output:
            result = client.connect_saml()
        self.assertEqual(result, 'https://idp.example.com/login')
        renew.assert_called_once_with()
        self.assertEqual(get.call_count, 2)
        self.assertIn('attempting a CA-verified certificate refresh', output.getvalue())
        self.assertEqual(client.session.get_adapter('https://vpn.example.com/remote/saml/start').fingerprint,
                         renew.return_value.tls_fingerprint)
        self.assertFalse(hasattr(client.session.get_adapter('https://other.example.com/'), 'fingerprint'))

    @patch("fortigate_vpn_login.fortigate.requests.Session.get")
    def test_failed_refresh_stops_and_provides_manual_instructions(self, get):
        get.side_effect = requests.exceptions.SSLError('certificate failed')
        renew = Mock(side_effect=TLSRefreshError('Untrusted issuer'))
        with redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(Fortigate('https://vpn.example.com', tls_refresh=renew).connect_saml())
        renew.assert_called_once_with()
        get.assert_called_once()
        self.assertIn('Untrusted issuer', output.getvalue())
        self.assertIn('--configure', output.getvalue())
        self.assertIn("choose 'n'", output.getvalue())
        self.assertIn('Do not disable TLS verification', output.getvalue())

    @patch("fortigate_vpn_login.fortigate.requests.Session.get")
    def test_second_tls_error_does_not_loop(self, get):
        get.side_effect = requests.exceptions.SSLError('still invalid')
        renew = Mock(return_value=VerifiedPins('AA:' * 31 + 'AA', 'pin-sha256:example'))
        with redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(Fortigate('https://vpn.example.com', tls_refresh=renew).connect_saml())
        self.assertEqual(get.call_count, 2)
        renew.assert_called_once()
        self.assertIn('Manual recovery', output.getvalue())

    @patch("fortigate_vpn_login.fortigate.requests.Session.get")
    def test_dns_errors_do_not_trigger_certificate_refresh(self, get):
        get.side_effect = requests.exceptions.ConnectionError('DNS failed')
        renew = Mock()
        with redirect_stdout(io.StringIO()):
            self.assertIsNone(Fortigate('https://vpn.example.com', tls_refresh=renew).connect_saml())
        renew.assert_not_called()

    def test_fingerprint_verification_applies_to_proxied_https_too(self):
        fingerprint = 'AA:' * 31 + 'AA'
        adapter = FingerprintAdapter(fingerprint)
        for proxy in ('http://proxy.example.com:8080', 'https://proxy.example.com:8443'):
            with self.subTest(proxy=proxy):
                manager = adapter.proxy_manager_for(proxy)
                self.assertEqual(manager.connection_pool_kw['assert_fingerprint'], fingerprint)


if __name__ == "__main__":
    unittest.main()
