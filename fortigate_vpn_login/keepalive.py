# -*- coding: utf-8 -*-
"""
    fortigate_vpn_login.keepalive
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Watches an active NetworkManager VPN connection, so that it can be
    re-established (with a new SAML login) when it drops or expires.
"""
import re
import select
import subprocess
import time
from shutil import which
from typing import Optional
from fortigate_vpn_login import logger

# NMVpnConnectionStateReason / NMActiveConnectionStateReason
REASON_UNKNOWN = 0
REASON_USER_DISCONNECTED = 2
REASONS = {
    0: 'unknown reason',
    1: 'no reason given',
    2: 'disconnected by the user',
    3: 'the underlying network device was disconnected',
    4: 'the VPN service stopped',
    5: 'the VPN returned an invalid IP configuration',
    6: 'connection attempt timed out',
    7: 'the VPN service did not start in time',
    8: 'the VPN service failed to start',
    9: 'no valid secrets',
    10: 'the VPN session was rejected (login failed / session expired)',
    11: 'the connection profile was removed',
    12: 'a dependency failed',
    13: 'the device could not be created',
    14: 'the device was removed',
}

# openconnect messages explaining why a tunnel was torn down
CAUSES = (
    ('Detected dead peer', 'the VPN server stopped responding (dead peer detection)'),
    ('Reconnect failed', 'the FortiGate refused to resume the session without a new login'),
    ('expired', 'the VPN session expired'),
    ('Session terminated', 'the session was terminated by the server'),
    ('terminated by server', 'the session was terminated by the server'),
    ('Failed to reconnect', 'reconnecting to the server failed'),
)

# VpnStateChanged: 6 = FAILED, 7 = DISCONNECTED; StateChanged: 4 = DEACTIVATED
_SIGNAL = re.compile(r'\.(VpnStateChanged|StateChanged) \(uint32 (\d+), uint32 (\d+)\)')
_DOWN_STATES = {'VpnStateChanged': {6, 7}, 'StateChanged': {4}}


def active_connection_path(connection_name: str) -> Optional[str]:
    """Returns the D-Bus path of the active connection, or None when it is not active."""
    result = subprocess.run(['nmcli', '-g', 'NAME,ACTIVE-PATH', 'connection', 'show', '--active'],
                            capture_output=True, text=True)
    for line in result.stdout.splitlines():
        name, _, path = line.rpartition(':')
        if name.replace('\\:', ':') == connection_name and path:
            return path
    return None


def wait_for_disconnect(connection_name: str, deadline: Optional[float] = None) -> Optional[int]:
    """
    Blocks while the VPN connection stays active.

    Returns:
        int|None: the NetworkManager reason code of the disconnection, or None when
            `deadline` (a `time.monotonic()` value) was reached first.
    """
    path = active_connection_path(connection_name)
    if not path:
        return REASON_UNKNOWN
    if not which('gdbus'):
        logger.debug('gdbus not found, polling the connection state instead')
        return _poll_for_disconnect(connection_name, path, deadline)

    monitor = subprocess.Popen(['gdbus', 'monitor', '--system', '--dest', 'org.freedesktop.NetworkManager',
                                '--object-path', path], stdout=subprocess.PIPE, text=True)
    reason = None
    try:
        # the connection may have dropped before the monitor was subscribed
        if active_connection_path(connection_name) != path:
            return REASON_UNKNOWN
        while True:
            timeout = None if deadline is None else deadline - time.monotonic()
            if timeout is not None and timeout <= 0:
                return None
            ready, _, _ = select.select([monitor.stdout], [], [], timeout)
            if not ready:
                continue
            line = monitor.stdout.readline()
            if not line:
                # monitor ended, e.g. NetworkManager restarted
                return reason if reason is not None else REASON_UNKNOWN
            logger.debug(f"NetworkManager signal: {line.strip()}")
            match = _SIGNAL.search(line)
            if not match:
                continue
            signal, state, code = match.group(1), int(match.group(2)), int(match.group(3))
            if state in _DOWN_STATES[signal]:
                # VpnStateChanged carries the more specific reason, so prefer it
                if signal == 'VpnStateChanged' or reason is None:
                    reason = code
                if signal == 'StateChanged' or code != REASON_UNKNOWN:
                    return reason
    finally:
        monitor.terminate()
        monitor.wait()


def _poll_for_disconnect(connection_name: str, path: str, deadline: Optional[float]) -> Optional[int]:
    while active_connection_path(connection_name) == path:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        time.sleep(5)
    return REASON_UNKNOWN


def disconnect_cause(since: float) -> Optional[str]:
    """Looks for the openconnect message explaining the disconnection in the journal."""
    try:
        result = subprocess.run(['journalctl', '--no-pager', '-o', 'cat', '--since', f"@{int(since)}",
                                 '_COMM=openconnect'],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    causes = []
    for line in result.stdout.splitlines():
        for pattern, cause in CAUSES:
            if pattern in line and cause not in causes:
                causes.append(cause)
    return '; '.join(causes) or None


def describe(reason: int, since: float) -> str:
    """Builds a human readable explanation of why the VPN went down."""
    description = REASONS.get(reason, f"reason code {reason}")
    cause = disconnect_cause(since)
    return f"{cause} ({description})" if cause else description


def notify(message: str, urgency: str = 'normal') -> None:
    """Prints the message and shows it as a desktop notification when possible."""
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)
    if which('notify-send'):
        subprocess.run(['notify-send', '-u', urgency, '-a', 'fortigate-vpn-login', 'Fortigate VPN', message],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def parse_duration(value: str) -> float:
    """Parses durations such as `90m`, `8h`, `1d` or `3600` (seconds) into seconds."""
    match = re.fullmatch(r'\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*', value.lower())
    if not match:
        raise ValueError(f"invalid duration: {value!r} (use e.g. 90m, 8h, 1d)")
    return float(match.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400}[match.group(2)]
