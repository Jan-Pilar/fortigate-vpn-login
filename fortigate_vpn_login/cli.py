# -*- coding: utf-8 -*-
"""
    fortigate_vpn_login.cli
    ~~~~~~~~~~~~~~~~~~~~~~

    This is the CLI interface for running the package.
"""
import logging
import os
import sys
import webbrowser
import subprocess
import tempfile
import hashlib
import time
from typing import Optional
from pathlib import Path
from urllib.parse import urlsplit
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from fortigate_vpn_login import __version__, __description__, get_log_level, logger
from fortigate_vpn_login import utils, config, keepalive
from fortigate_vpn_login.fortigate import Fortigate, report_tls_failure
from fortigate_vpn_login.tls import refresh_pins, TLSRefreshError
import fortigate_vpn_login.webserver as webserver


def update_tls_pins(options, url, persist=True):
    """Save both pins together, and only after the endpoint has been verified."""
    cache_name = hashlib.sha256(url.rstrip('/').encode('utf-8')).hexdigest()[:16]
    cache_path = Path(options.config_filename).parent / ('intermediates-' + cache_name + '.pem')
    pins = refresh_pins(url, cache_path=cache_path)
    if persist:
        previous = {key: options.get(key) for key in ('tls_fingerprint', 'server_cert')}
        options.set('tls_fingerprint', pins.tls_fingerprint)
        options.set('server_cert', pins.server_cert)
        if not options.write():
            for key, value in previous.items():
                options.set(key, value)
            raise TLSRefreshError('Could not save the verified certificate pins.')
        if (previous['tls_fingerprint'] != pins.tls_fingerprint
                or previous['server_cert'] != pins.server_cert):
            print('VPN certificate verified; TLS fingerprint and OpenConnect pin updated automatically.')
        else:
            print('VPN certificate verified; stored pins are up to date.')
    else:
        print('VPN certificate verified; current pins will be used for this connection.')
    return pins


def main() -> int:
    """
    Main method which is called by CLI.

    Returns:
        int: The status from the program.

    Exit codes:
        0: Everything went well.
        1: General error while connecting to the VPN
        2: Usage/syntax error
    """
    # main program argument parser
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=(
            f"fortigate-vpn-login {__version__}{os.linesep}"
            f"{__description__}"
        )
    )

    parser.add_argument(
        '-d',
        '--debug',
        help='Set LOG_LEVEL to DEBUG.',
        dest="DEBUG_MODE",
        action='store_true'
    )

    parser.add_argument(
        '-q',
        '--quiet',
        help='Do not log at all.',
        dest="QUIET_MODE",
        action='store_true'
    )

    parser.add_argument(
        '--configure',
        help='Interactive configuration.',
        dest='INTERACTIVE_CONFIGURE',
        action='store_true'
    )

    parser.add_argument(
        '-s',
        '--forti-url',
        help='URL of the Fortigate VPN server.',
        dest='FORTI_URL'
    )

    parser.add_argument('--connection-name', help='NetworkManager VPN connection name.')
    parser.add_argument('--tls-fingerprint', help='SHA-256 fingerprint used when the server CA chain is broken.')
    parser.add_argument('--server-cert', help='OpenConnect server pin (pin-sha256:...).')
    parser.add_argument('--auto-tls', action='store_true',
                        help='Enable and save automatic CA-verified certificate refresh.')
    parser.add_argument('--refresh-cert', action='store_true',
                        help='Verify and update certificate pins without opening the browser or connecting VPN.')
    parser.add_argument('--keep-alive', action='store_true',
                        help='Stay running and log in again whenever the VPN drops or expires, '
                             'until the user disconnects it or presses CTRL+C.')
    parser.add_argument('--max-time', metavar='DURATION',
                        help='With --keep-alive: disconnect after this time (e.g. 90m, 8h). Implies --keep-alive.')

    # windows don't have these options supported
    if not utils.is_windows():
        parser.add_argument(
            '-F',
            '--foreground',
            help='Run VPN in foreground.',
            dest="FOREGROUND",
            action='store_true'
        )

        parser.add_argument(
            '-B',
            '--background',
            help='Run VPN in background (default).',
            dest="BACKGROUND",
            action='store_true',
            default=True
        )

    # parse the arguments, show in the screen if needed, etc
    parser = parser.parse_args()

    if parser.DEBUG_MODE:
        log_level = get_log_level("DEBUG")
        logger.setLevel(log_level)
        logging.getLogger().setLevel(log_level)
        # TODO: on debug mode, change log format to
        # '[%(asctime)s] [%(levelname)s] [%(name)s:%(filename)s:%(lineno)s: %(funcName)s()] %(message)s'))
    else:
        # defaults to info
        log_level = get_log_level("INFO")
        logger.setLevel(log_level)
        logging.getLogger().setLevel(log_level)

    if parser.QUIET_MODE:
        logging.disable(logging.CRITICAL)

    if getattr(parser, 'FOREGROUND', False):
        parser.BACKGROUND = False

    # load configuration
    options = config.Config()

    # do we need to configure interactively?
    if parser.INTERACTIVE_CONFIGURE:
        options.configure()
        return 0 if options.write() else 1

    # server url
    if not parser.FORTI_URL:
        fortigate_vpn_url = options.get('forti_url')
        if not fortigate_vpn_url:
            print('ERROR: "forti_url" option is not set. Use "-s" or "--configure" to set it.')
            return 2
    else:
        fortigate_vpn_url = parser.FORTI_URL

    auto_tls = parser.auto_tls or options.getboolean('auto_tls')
    if auto_tls and (parser.tls_fingerprint or parser.server_cert):
        print('ERROR: Explicit certificate pins cannot be combined with automatic refresh. '
              'Use --configure to disable automatic refresh for manual pins.')
        return 2
    persist_pins = not parser.FORTI_URL or fortigate_vpn_url.rstrip('/') == (options.get('forti_url') or '').rstrip('/')
    if parser.auto_tls or parser.refresh_cert:
        options.set('forti_url', fortigate_vpn_url)
        if parser.connection_name:
            options.set('connection_name', parser.connection_name)
        if parser.auto_tls:
            options.set('auto_tls', 'True')
        persist_pins = True
    current_pins = None

    def renew_certificate():
        nonlocal current_pins
        current_pins = update_tls_pins(options, fortigate_vpn_url, persist=persist_pins)
        return current_pins

    if parser.refresh_cert:
        try:
            renew_certificate()
        except TLSRefreshError as error:
            report_tls_failure(fortigate_vpn_url, error)
            return 1
        print('VPN certificate verified and both pins updated.'
              + (' Automatic refresh is enabled.' if auto_tls else ''))
        return 0

    openconnect_path = utils.find_openconnect()
    if not utils.check_openconnect_version(openconnect_path):
        print("ERROR: Your openconnect version isn't compatible with this program. "
              "Make sure you have the latest version, which supports the \"fortinet\" protocol.")
        return 1

    # Automatic mode starts with normal CA validation, so expired certificates
    # cannot be silently accepted by an old stored fingerprint.
    tls_fingerprint = parser.tls_fingerprint or options.get('tls_fingerprint') or None
    connection_name = parser.connection_name or options.get('connection_name')
    connection_name = connection_name or urlsplit(fortigate_vpn_url).hostname

    def connect() -> int:
        nonlocal current_pins
        current_pins = None
        fortigate = Fortigate(fortigate_vpn_url, tls_fingerprint=None if auto_tls else tls_fingerprint,
                             tls_refresh=renew_certificate if auto_tls else None)
        url = fortigate.connect_saml()
        if not url:
            return 1
        if auto_tls and current_pins is None:
            # A server serving a full chain may rotate its key without a TLS error.
            # Refresh the OpenConnect pin before handing it any credentials too.
            try:
                renew_certificate()
            except TLSRefreshError as error:
                report_tls_failure(fortigate_vpn_url, error)
                return 1

        # webserver to get the response from the IDP through browser request
        ws = webserver.run()
        webbrowser.open(url)
        auth_id = webserver.return_token()
        webserver.quit(ws)

        if auth_id == '-1':
            print("ERROR: Invalid ID from provider. Try again or contact your provider support.")
            return 1

        cookie_svpn = fortigate.get_cookie(auth_id)
        if not cookie_svpn:
            print("ERROR: FortiGate did not return an SVPNCOOKIE after SAML authentication.")
            return 1

        server_cert = current_pins.server_cert if current_pins else parser.server_cert or options.get('server_cert')
        if not server_cert:
            print('ERROR: "server_cert" is not set. Run --configure and provide the pin-sha256 value.')
            return 2

        password_file = tempfile.NamedTemporaryFile(
            mode='w', prefix='fortigate-vpn-', delete=False
        )
        try:
            password_file.write(f"vpn.secrets.cookie:SVPNCOOKIE={cookie_svpn}\n")
            password_file.write(f"vpn.secrets.gwcert:{server_cert}\n")
            password_file.write(f"vpn.secrets.gateway:{urlsplit(fortigate_vpn_url).netloc}\n")
            password_file.write("vpn.secrets.resolve:\n")
            password_file.close()
            os.chmod(password_file.name, 0o600)

            nmcli_command = [
                "/usr/bin/nmcli", "con", "up", connection_name,
                "passwd-file", password_file.name,
            ]

            openconnect_arguments = [
                "--protocol=fortinet",
                f"--servercert={server_cert}",
                f"--server={fortigate_vpn_url}",
                f"--useragent=fortigate-vpn-login-{__version__}:{os.uname().version}",
                "--no-dtls",
                "--non-inter",
                "--disable-ipv6",
                f"--cookie=SVPNCOOKIE={cookie_svpn}",
            ]

            if parser.QUIET_MODE:
                openconnect_arguments.append("--quiet")

            if parser.DEBUG_MODE:
                openconnect_arguments.append("--verbose")

            if parser.BACKGROUND:
                openconnect_arguments.append("--quiet")
                openconnect_arguments.append("--background")

            command_line = []
            if utils.is_windows():
                workdir = openconnect_path.parent
                command_line = [
                    "powershell",
                    "-Command",
                    f"Start-Process '{str(openconnect_path)}' "
                    f"-ArgumentList {','.join(openconnect_arguments)} "
                    f"-Verb runAs -WorkingDirectory {workdir}",
                ]
            else:
                if not os.getuid() == 0:
                    command_line = nmcli_command
                else:
                    command_line = [str(openconnect_path)] + openconnect_arguments

            env = os.environ.copy()
            env['LC_ALL'] = 'C'

            try:
                result = subprocess.run(command_line, env=env)
                if result.returncode:
                    print(f"ERROR: VPN activation failed (exit code {result.returncode}).")
                    return 1
            except KeyboardInterrupt:
                logger.debug("User interrupted process.")
                print("CTRL+C/SIGTERM detected. Exiting.")
                return 130
        finally:
            password_file.close()
            try:
                os.unlink(password_file.name)
            except FileNotFoundError:
                pass

        return 0

    keep_alive = parser.keep_alive or bool(parser.max_time) or options.getboolean('keep_alive')
    if not keep_alive:
        return connect()
    if utils.is_windows() or os.getuid() == 0:
        print('ERROR: --keep-alive requires running as a regular user with NetworkManager (nmcli).')
        return 2
    try:
        max_time = keepalive.parse_duration(parser.max_time) if parser.max_time else None
    except ValueError as error:
        print(f'ERROR: {error}')
        return 2
    return keep_connected(connect, connection_name, max_time)


def keep_connected(connect, connection_name: str, max_time: Optional[float] = None) -> int:
    """
    Keeps the VPN connected until the user disconnects it, presses CTRL+C or `max_time`
    seconds pass. Every drop (dead peer, expired session, network change, ...) is
    reported together with its cause and followed by a new login.
    """
    deadline = time.monotonic() + max_time if max_time else None
    try:
        result = connect()
        if result:
            return result
        until = f" until {time.strftime('%H:%M', time.localtime(time.time() + max_time))}" if max_time else ''
        keepalive.notify(f"VPN connected; keeping it up{until}. Press CTRL+C to stop watching.")
        while True:
            connected_at = time.time()
            reason = keepalive.wait_for_disconnect(connection_name, deadline)
            if reason is None:
                subprocess.run(['nmcli', 'connection', 'down', connection_name])
                keepalive.notify('Requested VPN time is over; VPN disconnected.')
                return 0
            if reason == keepalive.REASON_USER_DISCONNECTED:
                keepalive.notify('VPN was disconnected by the user; not reconnecting.')
                return 0
            cause = keepalive.describe(reason, connected_at)
            keepalive.notify(f"VPN connection lost: {cause}. Reconnecting...", urgency='critical')
            attempt = 0
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    keepalive.notify('Requested VPN time is over; not reconnecting.')
                    return 0
                result = connect()
                if result == 0:
                    keepalive.notify(f"VPN connection restored after a drop: {cause}.")
                    break
                if result in (2, 130):
                    return result
                delay = min(300, 10 * 2 ** attempt)
                attempt += 1
                keepalive.notify(f"Reconnect attempt {attempt} failed; retrying in {delay} s.")
                time.sleep(delay)
    except KeyboardInterrupt:
        print("CTRL+C detected. Stopped watching the VPN; the current connection is left as it is.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
