# fortigate-vpn-login

Uses `openconnect` to connect to Fortinet VPNs, with extra features. This was created because sometimes we don't want
to use the Forticlient program, or just want a background daemon working for us.

So why not use only `openconnect`? Because there's no proper SAML / OAuth2 support on it, so I decided to do a python
wrapper to extract the `SVPNCOOKIE` from the browser workflow and use it on `openconnect`.

## Usage

To configure this utility on an interactive mode, run:

```bash
fortigate-vpn-login --configure
```

To initiate the SAML workflow on a fortigate ssl vpn server:

```bash
fortigate-vpn-login -s https://vpn-server.example.com
```

To enable automatic certificate handling once for your existing VPN profile:

```bash
fortigate-vpn-login --auto-tls --refresh-cert
```

This verifies the current server certificate, calculates and saves both the
TLS SHA-256 fingerprint and the OpenConnect `pin-sha256:...` public-key pin,
and enables automatic updates. The VPN URL and NetworkManager connection name
are preserved. The command does not open the browser or activate the VPN.
For a new configuration, specify the URL and profile name:

```bash
fortigate-vpn-login -s https://vpn-server.example.com --connection-name my-vpn --auto-tls --refresh-cert
```

Then connect normally:

```bash
fortigate-vpn-login
```

In automatic mode, a TLS verification error triggers one certificate-refresh
attempt and one SAML retry. Missing intermediates are downloaded from the
certificate's CA Issuers (AIA) URLs and cached locally. A fresh TLS handshake
must validate the hostname, certificate lifetime and chain to an already
trusted root before either pin is saved. Downloaded certificates never become
new root trust anchors. Expired, self-signed, wrong-hostname and untrusted
certificates are rejected. Updates are announced without asking for input;
failed verification preserves the previous pins and prints manual instructions.
Servers serving a complete chain also have their current public-key pin checked
before SAML login continues, so a legitimate key rotation updates both pins.

`--refresh-cert` can also refresh the saved pins on demand without connecting.
Automatic mode works when starting this wrapper; activating a NetworkManager
profile directly does not run its SAML or certificate-refresh workflow.

To use administrator-confirmed manual pins instead, run:

```bash
fortigate-vpn-login --configure
```

Choose `n` at the automatic-refresh prompt. The configuration then asks for:

- the NetworkManager VPN connection name;
- the leaf certificate SHA-256 fingerprint used by the SAML HTTPS requests;
- the OpenConnect `pin-sha256:...` public-key pin.

Manual certificate pins must be updated after a legitimate server certificate/key
rotation. Do not disable certificate verification. Installing the complete
intermediate chain on the FortiGate remains the permanent server-side fix.

To get help and more options:

```bash
fortigate-vpn-login -h
```

## Contents

- [ChangeLog](CHANGELOG.md)

## Setup and usage for local development

Make a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Note that this will also install the local dependencies, which might change after
some time. If needed, you can run `pip install -e .` again to reinstall the
updated dependencies anytime.

Run the automated tests (including local TLS servers with generated certificates):

```bash
python3 -m unittest discover -v
```
