# -*- coding: utf-8 -*-
"""
    fortigate_vpn_login.fortigate
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Talks to the Fortigate VPN Server
"""
import requests
import xmltodict
import re
import ssl
from bs4 import BeautifulSoup
from typing import Optional
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from fortigate_vpn_login import logger


class FingerprintAdapter(HTTPAdapter):
    """Verify HTTPS peers by SHA-256 fingerprint when their CA chain is broken."""

    def __init__(self, fingerprint: str, *args, **kwargs) -> None:
        self.fingerprint = fingerprint
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ssl_context = create_urllib3_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        pool_kwargs["ssl_context"] = ssl_context
        pool_kwargs["assert_fingerprint"] = self.fingerprint
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def cert_verify(self, conn, url, verify, cert):
        # urllib3's assert_fingerprint performs the peer verification instead.
        conn.cert_reqs = "CERT_NONE"
        conn.ca_certs = None
        conn.ca_cert_dir = None


class Fortigate(object):
    """
    Represents a Fortigate VPN Server connection
    """
    def __init__(self, url: str, tls_fingerprint: Optional[str] = None) -> None:
        """
        Creates a connection with a Fortigate VPN Server

        Args:
            url (str): The URL of the fortigate vpn server.
        """
        self.xml_config = None
        self.json_config = None
        self.url = url.rstrip('/')
        self.session = requests.Session()
        if tls_fingerprint:
            self.session.mount("https://", FingerprintAdapter(tls_fingerprint))

    def connect_saml(self) -> Optional[str]:
        """
        Initiates the SAML workflow.

        Returns:
            str|Optional: The URL that the user should be redirected to continue the SAML workflow.
        """
        try:
            logger.debug(f"Requesting: {self.url}/remote/saml/start?redirect=1")
            response = self.session.get(url=f"{self.url}/remote/saml/start?redirect=1", timeout=10)

        except requests.exceptions.MissingSchema as e:
            print(f"ERROR: Invalid forti_url option: {self.url}, should be something like: "
                  'https://server-vpn.example.com')
            logger.debug("Invalid VPN URL: %s", e)
            return None

        # SSLError inherits from ConnectionError, so it must be handled first.
        except requests.exceptions.SSLError as e:
            print(
                f"ERROR: TLS certificate verification failed for {self.url}. "
                "Check that the FortiGate serves the full certificate chain "
                "(including intermediate certificates)."
            )
            logger.debug("TLS certificate verification failed: %s", e)
            return None

        except requests.exceptions.Timeout as e:
            print(f"ERROR: Connection to server {self.url} timed out.")
            logger.debug("VPN server request timed out: %s", e)
            return None

        except requests.exceptions.ConnectionError as e:
            print(f"ERROR: Connection error while requesting server {self.url}: {e}")
            logger.debug("VPN server connection failed: %s", e)
            return None

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            script = soup.find('script')
            match = re.search(r"window\.location='([^']+)'", script.text if script else '')
            if not match:
                print("ERROR: FortiGate response did not contain a SAML redirect URL.")
                return None
            match = match.group(1)
            logger.debug(f"window.location redirect has: {match}")
            return match
        else:
            print('ERROR: Server didn\'t return a proper response, check if it\'s indeed the Fortigate VPN Server.')
            return None

    def get_cookie(self, auth_id: str) -> Optional[str]:
        """
        Requests a cookie from the server by providing an `auth_id` returned by the SAML workflow. This
        `auth_id` is obtained after sucessful authentication throught the web browser, and when the local
        webserver grabs it.

        Args:
            auth_id (str): code provided by the IDP to be feed to the vpn server

        Returns:
            str|Optional: The `SVPNCOOKIE` returned from the vpn server.
        """
        response = self.session.get(url=f"{self.url}/remote/saml/auth_id?id={auth_id}", timeout=10)
        if response.status_code == 200:
            cookies = response.cookies.get_dict()
            logger.debug("FortiGate returned %d cookie(s).", len(cookies))
            try:
                return cookies['SVPNCOOKIE']
            except KeyError:
                return None
        else:
            return None

    def get_xml_config(self) -> str:
        """
        Gets the XML configuration from the Fortigate SSL VPN configuration

        Returns:
            str: a XML with the vpn configuration
        """
        if self.xml_config is None:
            response = self.session.get(url=f"{self.url}/remote/fortisslvpn_xml", timeout=5)
            self.xml_config = response.text

        logger.debug(f"VPN XML configuration: {self.xml_config}")
        return self.xml_config

    def get_json_config(self) -> dict:
        """
        Transforms the XML configuration to JSON

        Returns:
            dict: the vpn configuration
        """
        if self.json_config is None:
            xml_config = self.get_xml_config()
            self.json_config = xmltodict.parse(xml_config)

        logger.debug(f"VPN JSON configuration: {self.json_config}")
        return self.json_config
