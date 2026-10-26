import io
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from fortigate_vpn_login import cli, keepalive

PATH = '/org/freedesktop/NetworkManager/ActiveConnection/22'


def gdbus_output(*lines):
    monitor = Mock()
    monitor.stdout = io.StringIO(''.join(line + '\n' for line in lines))
    return monitor


class WaitForDisconnectTest(unittest.TestCase):
    def wait(self, monitor):
        with patch('fortigate_vpn_login.keepalive.active_connection_path', return_value=PATH), \
                patch('fortigate_vpn_login.keepalive.which', return_value='/usr/bin/gdbus'), \
                patch('fortigate_vpn_login.keepalive.subprocess.Popen', return_value=monitor), \
                patch('fortigate_vpn_login.keepalive.select.select', side_effect=lambda r, w, x, t: (r, w, x)):
            return keepalive.wait_for_disconnect('cybrela')

    def test_vpn_failure_reason_is_returned(self):
        monitor = gdbus_output(
            f"{PATH}: org.freedesktop.NetworkManager.VPN.Connection.VpnStateChanged (uint32 6, uint32 10)",
            f"{PATH}: org.freedesktop.NetworkManager.Connection.Active.StateChanged (uint32 4, uint32 0)",
        )
        self.assertEqual(self.wait(monitor), 10)
        monitor.terminate.assert_called_once()

    def test_user_disconnect_is_recognized(self):
        monitor = gdbus_output(
            f"{PATH}: org.freedesktop.NetworkManager.Connection.Active.StateChanged (uint32 3, uint32 2)",
            f"{PATH}: org.freedesktop.NetworkManager.VPN.Connection.VpnStateChanged (uint32 7, uint32 2)",
        )
        self.assertEqual(self.wait(monitor), keepalive.REASON_USER_DISCONNECTED)

    def test_ended_monitor_means_unknown_disconnect(self):
        self.assertEqual(self.wait(gdbus_output()), keepalive.REASON_UNKNOWN)

    def test_inactive_connection_returns_immediately(self):
        with patch('fortigate_vpn_login.keepalive.active_connection_path', return_value=None):
            self.assertEqual(keepalive.wait_for_disconnect('cybrela'), keepalive.REASON_UNKNOWN)


class HelpersTest(unittest.TestCase):
    def test_active_connection_path(self):
        result = subprocess.CompletedProcess([], 0, stdout=f"Wifi:/x/1\ncybrela:{PATH}\n")
        with patch('fortigate_vpn_login.keepalive.subprocess.run', return_value=result):
            self.assertEqual(keepalive.active_connection_path('cybrela'), PATH)
            self.assertIsNone(keepalive.active_connection_path('other'))

    def test_describe_uses_openconnect_journal(self):
        journal = subprocess.CompletedProcess([], 0, stdout=(
            "Detected dead peer!\nGot HTTP response: HTTP/1.1 302 Found\nReconnect failed\n"))
        with patch('fortigate_vpn_login.keepalive.subprocess.run', return_value=journal):
            description = keepalive.describe(10, 0)
        self.assertIn('dead peer detection', description)
        self.assertIn('refused to resume the session', description)
        self.assertIn('login failed / session expired', description)

    def test_parse_duration(self):
        self.assertEqual(keepalive.parse_duration('90m'), 5400)
        self.assertEqual(keepalive.parse_duration('8h'), 28800)
        self.assertEqual(keepalive.parse_duration('30'), 30)
        with self.assertRaises(ValueError):
            keepalive.parse_duration('soon')


class KeepConnectedTest(unittest.TestCase):
    def run_loop(self, connect, reasons, max_time=None):
        messages = []
        with patch('fortigate_vpn_login.cli.keepalive.wait_for_disconnect', side_effect=reasons), \
                patch('fortigate_vpn_login.cli.keepalive.describe', return_value='dead peer'), \
                patch('fortigate_vpn_login.cli.keepalive.notify',
                      side_effect=lambda message, **kwargs: messages.append(message)), \
                patch('fortigate_vpn_login.cli.subprocess.run') as run, \
                patch('fortigate_vpn_login.cli.time.sleep') as sleep, \
                redirect_stdout(io.StringIO()):
            result = cli.keep_connected(connect, 'cybrela', max_time)
        return result, messages, run, sleep

    def test_reconnects_and_reports_cause_until_user_disconnects(self):
        connect = Mock(return_value=0)
        result, messages, _, _ = self.run_loop(connect, [10, keepalive.REASON_USER_DISCONNECTED])
        self.assertEqual(result, 0)
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(any('lost: dead peer' in message for message in messages))
        self.assertTrue(any('restored after a drop: dead peer' in message for message in messages))
        self.assertIn('disconnected by the user', messages[-1])

    def test_failed_reconnects_are_retried_with_backoff(self):
        connect = Mock(side_effect=[0, 1, 1, 0])
        result, _, _, sleep = self.run_loop(connect, [10, keepalive.REASON_USER_DISCONNECTED])
        self.assertEqual(result, 0)
        self.assertEqual(connect.call_count, 4)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [10, 20])

    def test_max_time_disconnects_vpn(self):
        result, messages, run, _ = self.run_loop(Mock(return_value=0), [None], max_time=60)
        self.assertEqual(result, 0)
        run.assert_called_once_with(['nmcli', 'connection', 'down', 'cybrela'])
        self.assertIn('time is over', messages[-1])

    def test_initial_failure_is_returned(self):
        result, _, _, _ = self.run_loop(Mock(return_value=1), [])
        self.assertEqual(result, 1)


if __name__ == '__main__':
    unittest.main()
