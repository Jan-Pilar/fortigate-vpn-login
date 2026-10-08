"""Refresh VPN pins only after CA-chain, hostname and lifetime verification."""
import base64
import hashlib
import http.client
import ipaddress
import os
import re
import socket
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID

from fortigate_vpn_login import logger

TIMEOUT = 10
MAX_CERT_BYTES = 1024 * 1024
MAX_DOWNLOADS = 8
MISSING_ISSUER_CODES = (2, 20, 21)


class TLSRefreshError(Exception):
    """The server could not be authenticated; existing pins must stay unchanged."""


@dataclass(frozen=True)
class VerifiedPins:
    tls_fingerprint: str
    server_cert: str


def _verified_context(cafile=None):
    cafile = cafile or os.getenv('REQUESTS_CA_BUNDLE') or os.getenv('CURL_CA_BUNDLE') or requests.certs.where()
    context = ssl.create_default_context(cafile=str(cafile))
    # Downloaded intermediates are chain-building material, never trust anchors.
    # Python 3.13+ enables PARTIAL_CHAIN by default, which would change that.
    context.verify_flags &= ~getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
    return context


def _peer_certificate(host, port, context):
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as peer:
            return peer.getpeercert(binary_form=True)


def _download_issuer(url):
    """Fetch a bounded public AIA URL, pinning resolved IPs to prevent rebinding.

    HTTP is permitted for CA distribution: certificate signatures, not the
    download transport, establish trust. No cookies, credentials or proxies.
    """
    for _ in range(4):
        parsed = urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 80, 443)):
            raise TLSRefreshError('Unsupported issuer certificate URL.')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise TLSRefreshError('Issuer certificate URL must resolve to public IP addresses.')
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=TIMEOUT)
        try:
            last_error = None
            for address in addresses:
                try:
                    connection.sock = socket.create_connection((address[4][0], port), timeout=TIMEOUT)
                    break
                except OSError as error:
                    last_error = error
            else:
                raise last_error
            if parsed.scheme == 'https':
                connection.sock = _verified_context().wrap_socket(
                    connection.sock, server_hostname=parsed.hostname)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            connection.request('GET', path, headers={'User-Agent': 'fortigate-vpn-login'})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise TLSRefreshError('Issuer download redirect has no destination.')
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise TLSRefreshError('Issuer certificate download returned HTTP %d.' % response.status)
            data = response.read(MAX_CERT_BYTES + 1)
            if len(data) > MAX_CERT_BYTES:
                raise TLSRefreshError('Issuer certificate download is too large.')
            return data
        finally:
            connection.close()
    raise TLSRefreshError('Too many issuer certificate redirects.')


def _certificates(data):
    if len(data) > MAX_CERT_BYTES:
        raise TLSRefreshError('Certificate data is too large.')
    blocks = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', data, re.S)
    if blocks:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    return [x509.load_der_x509_certificate(data)]


def _is_intermediate(cert):
    try:
        return cert.subject != cert.issuer and cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _issuer_urls(cert):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [item.access_location.value for item in aia
            if item.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(item.access_location, x509.UniformResourceIdentifier)]


def _save_cache(path, intermediates):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in intermediates)
    filename = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.tls-', delete=False) as output:
            filename = output.name
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(filename, path)
    finally:
        if filename and os.path.exists(filename):
            os.unlink(filename)


def refresh_pins(url, cache_path=None, cafile=None):
    """Authenticate the current endpoint, completing missing AIA intermediates.

    An unauthenticated handshake is used ONLY to discover issuer URLs. No
    application data is sent and its leaf certificate never becomes a pin.
    A second, fully verified handshake supplies the pins returned to callers.
    Downloaded roots are never imported. Failure never changes the cache.
    """
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ('', '/')
                or parsed.query or parsed.fragment):
            raise TLSRefreshError('VPN URL must be an HTTPS origin without credentials or a path.')
        host, port = parsed.hostname, parsed.port or 443
        context = _verified_context(cafile)
        intermediates = []
        if cache_path and Path(cache_path).exists():
            try:
                with open(cache_path, 'rb') as cached:
                    intermediates = [cert for cert in _certificates(cached.read(MAX_CERT_BYTES + 1))
                                     if _is_intermediate(cert)][:MAX_DOWNLOADS]
                for cert in intermediates:
                    context.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM).decode('ascii'))
            except (OSError, ValueError, TLSRefreshError) as error:
                logger.debug('Ignoring unusable intermediate cache: %s', error)
                intermediates = []
                context = _verified_context(cafile)
        try:
            verified_der = _peer_certificate(host, port, context)
        except ssl.SSLCertVerificationError as error:
            if error.verify_code not in MISSING_ISSUER_CODES:
                raise
            # Discovery is not authentication: no cookies or VPN login here.
            discovery = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            discovery.check_hostname = False
            discovery.verify_mode = ssl.CERT_NONE
            leaf = x509.load_der_x509_certificate(_peer_certificate(host, port, discovery))
            pending = _issuer_urls(leaf)
            for cert in intermediates:
                pending.extend(_issuer_urls(cert))
            seen_urls = set()
            seen_certs = {cert.fingerprint(hashes.SHA256()) for cert in intermediates}
            verified_der = None
            last_error = error
            while pending and len(seen_urls) < MAX_DOWNLOADS:
                issuer_url = pending.pop(0)
                if issuer_url in seen_urls:
                    continue
                seen_urls.add(issuer_url)
                try:
                    downloaded = _certificates(_download_issuer(issuer_url))
                except (OSError, ValueError, http.client.HTTPException, TLSRefreshError) as download_error:
                    last_error = download_error
                    continue
                for cert in downloaded[:MAX_DOWNLOADS]:
                    digest = cert.fingerprint(hashes.SHA256())
                    if not _is_intermediate(cert) or digest in seen_certs:
                        continue
                    if len(intermediates) >= MAX_DOWNLOADS:
                        raise TLSRefreshError('Too many intermediate certificates.')
                    seen_certs.add(digest)
                    intermediates.append(cert)
                    context.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM).decode('ascii'))
                    pending.extend(_issuer_urls(cert))
                try:
                    verified_der = _peer_certificate(host, port, context)
                    break
                except ssl.SSLCertVerificationError as verification_error:
                    if verification_error.verify_code not in MISSING_ISSUER_CODES:
                        raise
                    last_error = verification_error
            if verified_der is None:
                raise TLSRefreshError('Could not build a chain to a trusted root: %s' % last_error)
            if cache_path:
                _save_cache(cache_path, intermediates)
        cert = x509.load_der_x509_certificate(verified_der)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        public_key = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return VerifiedPins(
            ':'.join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)),
            'pin-sha256:' + base64.b64encode(hashlib.sha256(public_key).digest()).decode('ascii'))
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise TLSRefreshError('TLS certificate refresh failed: %s' % error) from error
