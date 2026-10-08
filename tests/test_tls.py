import base64
import hashlib
import io
import ipaddress
import socket
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from fortigate_vpn_login.tls import TLSRefreshError, _download_issuer, refresh_pins
from fortigate_vpn_login.fortigate import Fortigate


def make_certificate(name, key, issuer_cert=None, issuer_key=None, ca=False,
                     issuer_url=None, expired=False, future=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer_cert.subject if issuer_cert else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=10))
               .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   (issuer_key or key).public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                           key_encipherment=not ca, data_encipherment=False,
                                           key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                           encipher_only=False, decipher_only=False), critical=True))
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if issuer_url:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier(issuer_url))]), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


class TLSFixtureServer:
    """A real local TLS endpoint; CA downloads are separately mocked."""

    def __init__(self, directory, cert, key, chain=()):
        cert_path = directory / 'server.pem'
        key_path = directory / 'server.key'
        cert_path.write_bytes(pem(cert) + b''.join(pem(item) for item in chain))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)

        class Handler(BaseHTTPRequestHandler):
            def handle(self):
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError):
                    # Certificate-only discovery intentionally closes without HTTP.
                    pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<script>window.location='https://idp.example.com/login'</script>")

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                sock, address = super().get_request()
                sock.settimeout(2)
                try:
                    return context.wrap_socket(sock, server_side=True), address
                except OSError:
                    sock.close()
                    raise

        self.server = Server(('127.0.0.1', 0), Handler)
        self.url = 'https://localhost:%d' % self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.01}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class RefreshPinsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_key = new_key()
        cls.root = make_certificate('Trusted test root', cls.root_key, ca=True)
        cls.issuer_key = new_key()
        cls.issuer = make_certificate('Test intermediate', cls.issuer_key, cls.root, cls.root_key,
                                      ca=True, issuer_url='http://ca.example.com/root.crt')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.ca_path = self.directory / 'roots.pem'
        self.ca_path.write_bytes(pem(self.root))
        self.cache = self.directory / 'intermediates.pem'
        self.leaf_key = new_key()
        self.leaf = self.make_leaf()

    def make_leaf(self, name='localhost', **kwargs):
        return make_certificate(name, self.leaf_key, self.issuer, self.issuer_key,
                                issuer_url='http://ca.example.com/issuer.crt', **kwargs)

    def refresh(self, server):
        return refresh_pins(server.url, cache_path=self.cache, cafile=self.ca_path)

    def test_full_chain_verified_without_download(self):
        with TLSFixtureServer(self.directory, self.leaf, self.leaf_key, [self.issuer]) as server:
            with patch('fortigate_vpn_login.tls._download_issuer') as download:
                pins = self.refresh(server)
        download.assert_not_called()
        expected = self.leaf.fingerprint(hashes.SHA256()).hex().upper()
        self.assertEqual(pins.tls_fingerprint.replace(':', ''), expected)
        spki = self.leaf_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(pins.server_cert, 'pin-sha256:' + base64.b64encode(
            hashlib.sha256(spki).digest()).decode('ascii'))

    def test_missing_intermediate_downloaded_and_verified_then_cached(self):
        with TLSFixtureServer(self.directory, self.leaf, self.leaf_key) as server:
            with patch('fortigate_vpn_login.tls._download_issuer', return_value=self.issuer.public_bytes(
                    serialization.Encoding.DER)) as download:
                first = self.refresh(server)
            download.assert_called_once_with('http://ca.example.com/issuer.crt')
            with patch('fortigate_vpn_login.tls._download_issuer') as download_again:
                self.assertEqual(self.refresh(server), first)
            download_again.assert_not_called()
        self.assertEqual(self.cache.read_bytes(), pem(self.issuer))
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)

    def test_real_https_saml_request_recovers_after_missing_chain(self):
        with TLSFixtureServer(self.directory, self.leaf, self.leaf_key) as server:
            with patch('fortigate_vpn_login.tls._download_issuer', return_value=pem(self.issuer)) as download:
                client = Fortigate(server.url, tls_refresh=lambda: self.refresh(server))
                client.session.trust_env = False
                client.session.verify = str(self.ca_path)
                self.addCleanup(client.session.close)
                with redirect_stdout(io.StringIO()) as output:
                    result = client.connect_saml()
        self.assertEqual(result, 'https://idp.example.com/login')
        self.assertTrue(client.tls_refreshed)
        download.assert_called_once()
        self.assertIn('attempting a CA-verified certificate refresh', output.getvalue())

    def test_valid_rotation_updates_both_pins_using_cached_intermediate(self):
        self.cache.write_bytes(pem(self.issuer))
        with TLSFixtureServer(self.directory, self.leaf, self.leaf_key) as server:
            first = self.refresh(server)
        self.leaf_key = new_key()
        rotated = self.make_leaf()
        with TLSFixtureServer(self.directory, rotated, self.leaf_key) as server:
            with patch('fortigate_vpn_login.tls._download_issuer') as download:
                second = self.refresh(server)
        download.assert_not_called()
        self.assertNotEqual(first.tls_fingerprint, second.tls_fingerprint)
        self.assertNotEqual(first.server_cert, second.server_cert)

    def test_same_key_certificate_renewal_changes_only_leaf_pin(self):
        self.cache.write_bytes(pem(self.issuer))
        with TLSFixtureServer(self.directory, self.leaf, self.leaf_key) as server:
            first = self.refresh(server)
        with TLSFixtureServer(self.directory, self.make_leaf(), self.leaf_key) as server:
            second = self.refresh(server)
        self.assertNotEqual(first.tls_fingerprint, second.tls_fingerprint)
        self.assertEqual(first.server_cert, second.server_cert)

    def test_rejects_expired_future_and_wrong_hostname_without_changing_cache(self):
        for leaf in (self.make_leaf(expired=True), self.make_leaf(future=True),
                     self.make_leaf(name='different.example.com')):
            with self.subTest(subject=leaf.subject):
                self.cache.write_bytes(pem(self.issuer))
                previous = self.cache.read_bytes()
                with TLSFixtureServer(self.directory, leaf, self.leaf_key) as server:
                    with patch('fortigate_vpn_login.tls._download_issuer') as download:
                        with self.assertRaises(TLSRefreshError):
                            self.refresh(server)
                download.assert_not_called()
                self.assertEqual(self.cache.read_bytes(), previous)

    def test_downloaded_intermediate_is_not_a_trust_anchor(self):
        rogue_key = new_key()
        rogue_root = make_certificate('Untrusted root', rogue_key, ca=True)
        rogue_issuer = make_certificate('Untrusted intermediate', self.issuer_key,
                                        rogue_root, rogue_key, ca=True,
                                        issuer_url='http://ca.example.com/root.crt')
        rogue_leaf = make_certificate('localhost', self.leaf_key, rogue_issuer, self.issuer_key,
                                      issuer_url='http://ca.example.com/issuer.crt')
        with TLSFixtureServer(self.directory, rogue_leaf, self.leaf_key) as server:
            with patch('fortigate_vpn_login.tls._download_issuer', side_effect=[pem(rogue_issuer), pem(rogue_root)]):
                with self.assertRaises(TLSRefreshError):
                    self.refresh(server)
        self.assertFalse(self.cache.exists())

    def test_cached_rogue_root_is_not_trusted(self):
        rogue_key = new_key()
        rogue_root = make_certificate('Untrusted root', rogue_key, ca=True)
        rogue_leaf = make_certificate('localhost', self.leaf_key, rogue_root, rogue_key)
        self.cache.write_bytes(pem(rogue_root))
        with TLSFixtureServer(self.directory, rogue_leaf, self.leaf_key) as server:
            with self.assertRaises(TLSRefreshError):
                self.refresh(server)
        self.assertEqual(self.cache.read_bytes(), pem(rogue_root))

    def test_download_failure_and_malformed_download_leave_cache_unchanged(self):
        for value in (OSError('CA offline'), b'not a certificate'):
            with self.subTest(value=value):
                self.cache.write_bytes(b'previous cache')
                with TLSFixtureServer(self.directory, self.leaf, self.leaf_key) as server:
                    with patch('fortigate_vpn_login.tls._download_issuer',
                               side_effect=value if isinstance(value, Exception) else None,
                               return_value=value):
                        with self.assertRaises(TLSRefreshError):
                            self.refresh(server)
                self.assertEqual(self.cache.read_bytes(), b'previous cache')

    def test_follows_multiple_intermediates(self):
        second_key = new_key()
        second = make_certificate('Second intermediate', second_key, self.issuer, self.issuer_key,
                                   ca=True, issuer_url='http://ca.example.com/issuer.crt')
        leaf = make_certificate('localhost', self.leaf_key, second, second_key,
                                issuer_url='http://ca.example.com/second.crt')
        with TLSFixtureServer(self.directory, leaf, self.leaf_key) as server:
            with patch('fortigate_vpn_login.tls._download_issuer', side_effect=[pem(second), pem(self.issuer)]) as download:
                pins = self.refresh(server)
        self.assertEqual(download.call_count, 2)
        self.assertEqual(pins.tls_fingerprint.replace(':', ''), leaf.fingerprint(hashes.SHA256()).hex().upper())

    def test_rejects_non_https_and_credentials_before_network(self):
        with patch('fortigate_vpn_login.tls._peer_certificate') as peer:
            for url in ('http://vpn.example.com', 'https://user:password@vpn.example.com',
                        'https://vpn.example.com/other', 'https://vpn.example.com:invalid'):
                with self.subTest(url=url), self.assertRaises(TLSRefreshError):
                    refresh_pins(url)
        peer.assert_not_called()


class IssuerDownloadTest(unittest.TestCase):
    def test_blocks_private_loopback_link_local_and_mixed_dns(self):
        for addresses in (['127.0.0.1'], ['10.0.0.1'], ['169.254.169.254'], ['::1'],
                          ['8.8.8.8', '192.168.1.1']):
            with self.subTest(addresses=addresses):
                records = [(socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                            socket.SOCK_STREAM, 6, '', (ip, 80)) for ip in addresses]
                with patch('fortigate_vpn_login.tls.socket.getaddrinfo', return_value=records):
                    with patch('fortigate_vpn_login.tls.socket.create_connection') as connect:
                        with self.assertRaises(TLSRefreshError):
                            _download_issuer('http://ca.example.com/issuer.crt')
                connect.assert_not_called()

    def test_blocks_non_http_credentials_and_unexpected_ports(self):
        with patch('fortigate_vpn_login.tls.socket.getaddrinfo') as lookup:
            for url in ('file:///etc/passwd', 'ftp://ca.example.com/cert',
                        'http://user:secret@ca.example.com/cert', 'http://ca.example.com:22/cert'):
                with self.subTest(url=url), self.assertRaises(TLSRefreshError):
                    _download_issuer(url)
        lookup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
