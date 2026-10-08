import io
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from fortigate_vpn_login import cli
from fortigate_vpn_login.config import Config
from fortigate_vpn_login.tls import TLSRefreshError, VerifiedPins


class CertificateAutomationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'config.ini'
        self.options = Config(config_filename=str(self.path), forti_url='https://vpn.example.com',
                              connection_name='cybrela', tls_fingerprint='old-leaf', server_cert='old-key')
        self.options.write()
        self.pins = VerifiedPins('AA:' * 31 + 'AA', 'pin-sha256:new-key')

    def run_cli(self, args, stack):
        stack.enter_context(patch('sys.argv', ['fortigate-vpn-login'] + args))
        stack.enter_context(patch('fortigate_vpn_login.cli.config.Config', return_value=self.options))
        output = stack.enter_context(redirect_stdout(io.StringIO()))
        return output

    def test_update_saves_both_pins_and_preserves_connection(self):
        with patch('fortigate_vpn_login.cli.refresh_pins', return_value=self.pins):
            with redirect_stdout(io.StringIO()) as output:
                cli.update_tls_pins(self.options, self.options.get('forti_url'))
        saved = Config(config_filename=str(self.path))
        self.assertEqual(saved.get('tls_fingerprint'), self.pins.tls_fingerprint)
        self.assertEqual(saved.get('server_cert'), self.pins.server_cert)
        self.assertEqual(saved.get('connection_name'), 'cybrela')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertIn('updated automatically', output.getvalue())

    def test_failed_verification_preserves_configuration(self):
        previous = self.path.read_bytes()
        with patch('fortigate_vpn_login.cli.refresh_pins', side_effect=TLSRefreshError('invalid certificate')):
            with self.assertRaises(TLSRefreshError):
                cli.update_tls_pins(self.options, self.options.get('forti_url'))
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.options.get('tls_fingerprint'), 'old-leaf')
        self.assertEqual(self.options.get('server_cert'), 'old-key')

    def test_failed_atomic_save_preserves_original_file_and_memory(self):
        previous = self.path.read_bytes()
        with patch('fortigate_vpn_login.cli.refresh_pins', return_value=self.pins):
            with patch('fortigate_vpn_login.config.os.replace', side_effect=OSError('disk failure')):
                with redirect_stdout(io.StringIO()), self.assertRaises(TLSRefreshError):
                    cli.update_tls_pins(self.options, self.options.get('forti_url'))
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.options.get('tls_fingerprint'), 'old-leaf')
        self.assertEqual(self.options.get('server_cert'), 'old-key')
        self.assertEqual(list(self.path.parent.glob('.config-*')), [])

    def test_one_time_enable_verifies_saves_and_never_connects_vpn(self):
        with ExitStack() as stack:
            output = self.run_cli(['--auto-tls', '--refresh-cert'], stack)
            refresh = stack.enter_context(patch('fortigate_vpn_login.cli.refresh_pins', return_value=self.pins))
            browser = stack.enter_context(patch('fortigate_vpn_login.cli.webbrowser.open'))
            process = stack.enter_context(patch('fortigate_vpn_login.cli.subprocess.run'))
            find = stack.enter_context(patch('fortigate_vpn_login.cli.utils.find_openconnect'))
            self.assertEqual(cli.main(), 0)
        saved = Config(config_filename=str(self.path))
        self.assertTrue(saved.getboolean('auto_tls'))
        self.assertEqual(saved.get('tls_fingerprint'), self.pins.tls_fingerprint)
        refresh.assert_called_once()
        browser.assert_not_called()
        process.assert_not_called()
        find.assert_not_called()
        self.assertIn('Automatic refresh is enabled', output.getvalue())

    def test_one_time_enable_failure_preserves_disk_and_explains_manual_recovery(self):
        previous = self.path.read_bytes()
        with ExitStack() as stack:
            output = self.run_cli(['--auto-tls', '--refresh-cert'], stack)
            stack.enter_context(patch('fortigate_vpn_login.cli.refresh_pins', side_effect=TLSRefreshError('CA offline')))
            self.assertEqual(cli.main(), 1)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertIn('CA offline', output.getvalue())
        self.assertIn('--configure', output.getvalue())

    def test_configure_auto_mode_never_asks_for_manual_fingerprints(self):
        with patch('builtins.input', side_effect=['', '', '']) as input_mock:
            self.options.configure()
        self.assertTrue(self.options.getboolean('auto_tls'))
        self.assertEqual(self.options.get('connection_name'), 'cybrela')
        self.assertEqual(input_mock.call_count, 3)

    def test_configure_can_disable_auto_mode_and_enter_manual_pins(self):
        with patch('builtins.input', side_effect=['', '', 'n', 'manual-leaf', 'manual-key']):
            self.options.configure()
        self.assertFalse(self.options.getboolean('auto_tls'))
        self.assertEqual(self.options.get('tls_fingerprint'), 'manual-leaf')
        self.assertEqual(self.options.get('server_cert'), 'manual-key')

    def test_automatic_login_refreshes_once_before_browser_and_passes_pin_to_networkmanager(self):
        self.options.set('auto_tls', 'True')
        response = Mock(status_code=200, text="<script>window.location='https://idp.example.com/login'</script>")
        cookie_response = Mock(status_code=200)
        cookie_response.cookies.get_dict.return_value = {'SVPNCOOKIE': 'test-cookie'}
        captured = {}

        def activation(command, **kwargs):
            captured['command'] = command
            filename = Path(command[-1])
            captured['filename'] = filename
            captured['password_file'] = filename.read_text()
            self.assertEqual(filename.stat().st_mode & 0o777, 0o600)
            return Mock(returncode=0)

        with ExitStack() as stack:
            output = self.run_cli([], stack)
            refresh = stack.enter_context(patch('fortigate_vpn_login.cli.refresh_pins', return_value=self.pins))
            get = stack.enter_context(patch('fortigate_vpn_login.fortigate.requests.Session.get',
                                           side_effect=[requests.exceptions.SSLError('missing intermediate'),
                                                        response, cookie_response]))
            stack.enter_context(patch('fortigate_vpn_login.cli.utils.find_openconnect', return_value=Path('/usr/bin/openconnect')))
            stack.enter_context(patch('fortigate_vpn_login.cli.utils.check_openconnect_version', return_value=True))
            stack.enter_context(patch('fortigate_vpn_login.cli.os.getuid', return_value=1000))
            stack.enter_context(patch('fortigate_vpn_login.cli.webserver.run'))
            stack.enter_context(patch('fortigate_vpn_login.cli.webserver.return_token', return_value='test-auth'))
            stack.enter_context(patch('fortigate_vpn_login.cli.webserver.quit'))
            browser = stack.enter_context(patch('fortigate_vpn_login.cli.webbrowser.open'))
            stack.enter_context(patch('fortigate_vpn_login.cli.subprocess.run', side_effect=activation))
            self.assertEqual(cli.main(), 0)
        refresh.assert_called_once()
        self.assertEqual(get.call_count, 3)
        browser.assert_called_once_with('https://idp.example.com/login')
        self.assertEqual(captured['command'][:4], ['/usr/bin/nmcli', 'con', 'up', 'cybrela'])
        self.assertIn('vpn.secrets.gwcert:' + self.pins.server_cert, captured['password_file'])
        self.assertFalse(captured['filename'].exists())
        self.assertIn('updated automatically', output.getvalue())

    def test_refresh_failure_never_starts_browser_or_vpn(self):
        self.options.set('auto_tls', 'True')
        with ExitStack() as stack:
            self.run_cli([], stack)
            stack.enter_context(patch('fortigate_vpn_login.cli.refresh_pins', side_effect=TLSRefreshError('expired')))
            stack.enter_context(patch('fortigate_vpn_login.fortigate.requests.Session.get',
                                      side_effect=requests.exceptions.SSLError('expired')))
            stack.enter_context(patch('fortigate_vpn_login.cli.utils.find_openconnect', return_value=Path('/usr/bin/openconnect')))
            stack.enter_context(patch('fortigate_vpn_login.cli.utils.check_openconnect_version', return_value=True))
            browser = stack.enter_context(patch('fortigate_vpn_login.cli.webbrowser.open'))
            process = stack.enter_context(patch('fortigate_vpn_login.cli.subprocess.run'))
            self.assertEqual(cli.main(), 1)
        browser.assert_not_called()
        process.assert_not_called()

    def test_auto_mode_rejects_explicit_manual_pin(self):
        with ExitStack() as stack:
            self.run_cli(['--auto-tls', '--tls-fingerprint', 'manual'], stack)
            refresh = stack.enter_context(patch('fortigate_vpn_login.cli.refresh_pins'))
            self.assertEqual(cli.main(), 2)
        refresh.assert_not_called()


if __name__ == '__main__':
    unittest.main()
