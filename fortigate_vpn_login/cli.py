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
from urllib.parse import urlsplit
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from fortigate_vpn_login import __version__, __description__, get_log_level, logger
from fortigate_vpn_login import utils, config
from fortigate_vpn_login.fortigate import Fortigate
import fortigate_vpn_login.webserver as webserver


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
        options.write()
        return 0

    openconnect_path = utils.find_openconnect()

    # openconnect compatability check
    if not utils.check_openconnect_version(openconnect_path):
        print("ERROR: Your openconnect version isn't compatible with this program. "
              "Make sure you have the latest version, which supports the \"fortinet\" protocol.")
        return 1

    # server url
    if not parser.FORTI_URL:
        fortigate_vpn_url = options.get('forti_url')
        if not fortigate_vpn_url:
            print('ERROR: "forti_url" option is not set. Use "-s" or "--configure" to set it.')
            return 2
    else:
        fortigate_vpn_url = parser.FORTI_URL

    # establish connection to the Fortigate VPN Server, grab info, etc
    tls_fingerprint = parser.tls_fingerprint or options.get('tls_fingerprint') or None
    fortigate = Fortigate(fortigate_vpn_url, tls_fingerprint=tls_fingerprint)
    url = fortigate.connect_saml()
    if not url:
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

    connection_name = parser.connection_name or options.get('connection_name')
    connection_name = connection_name or urlsplit(fortigate_vpn_url).hostname
    server_cert = parser.server_cert or options.get('server_cert')
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


if __name__ == "__main__":
    sys.exit(main())
