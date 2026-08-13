import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import requests

from fortigate_vpn_login.fortigate import Fortigate


class ConnectSamlErrorsTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
