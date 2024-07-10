import datetime
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path
from typing import Callable, Optional, Union

import OpenSSL.SSL
import pytest
import service_identity.pyopenssl  # type: ignore[import-not-found]
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

import trustme
from trustme import CA, KeyType, LeafCert

SslSocket = Union[ssl.SSLSocket, OpenSSL.SSL.Connection]


def _path_length(ca_cert: x509.Certificate) -> Optional[int]:
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    return bc.value.path_length


def assert_is_ca(ca_cert: x509.Certificate) -> None:
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    assert bc.critical is True

    ku = ca_cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True
    assert ku.critical is True

    with pytest.raises(x509.ExtensionNotFound):
        ca_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def assert_is_leaf(leaf_cert: x509.Certificate) -> None:
    bc = leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is False
    assert bc.critical is True

    ku = leaf_cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.digital_signature is True
    assert ku.value.key_encipherment is True
    assert ku.value.key_cert_sign is False
    assert ku.value.crl_sign is False
    assert ku.critical is True

    eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert eku.value == x509.ExtendedKeyUsage(
        [
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        ]
    )
    assert eku.critical is True


@pytest.mark.parametrize(
    "key_type,expected_key_header", [(KeyType.RSA, b"RSA"), (KeyType.ECDSA, b"EC")]
)
def test_basics(key_type: KeyType, expected_key_header: bytes) -> None:
    ca = CA(key_type=key_type)

    today = datetime.datetime.now(datetime.timezone.utc)

    assert (
        b"BEGIN " + expected_key_header + b" PRIVATE KEY" in ca.private_key_pem.bytes()
    )
    assert b"BEGIN CERTIFICATE" in ca.cert_pem.bytes()

    private_key = load_pem_private_key(ca.private_key_pem.bytes(), password=None)

    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.bytes())
    assert ca_cert.not_valid_before_utc <= today <= ca_cert.not_valid_after_utc

    public_key1 = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    public_key2 = ca_cert.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    assert public_key1 == public_key2

    assert ca_cert.issuer == ca_cert.subject
    assert_is_ca(ca_cert)

    with pytest.raises(ValueError):
        ca.issue_cert()

    server = ca.issue_cert(
        "test-1.example.org", "test-2.example.org", key_type=key_type
    )

    assert b"PRIVATE KEY" in server.private_key_pem.bytes()
    assert b"BEGIN CERTIFICATE" in server.cert_chain_pems[0].bytes()
    assert len(server.cert_chain_pems) == 1
    assert (
        server.private_key_pem.bytes() in server.private_key_and_cert_chain_pem.bytes()
    )
    for blob in server.cert_chain_pems:
        assert blob.bytes() in server.private_key_and_cert_chain_pem.bytes()

    server_cert = x509.load_pem_x509_certificate(server.cert_chain_pems[0].bytes())

    assert server_cert.not_valid_before_utc <= today <= server_cert.not_valid_after_utc
    assert server_cert.issuer == ca_cert.subject
    assert_is_leaf(server_cert)

    san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    hostnames = san.value.get_values_for_type(x509.DNSName)
    assert hostnames == ["test-1.example.org", "test-2.example.org"]


def test_ca_custom_names() -> None:
    ca = CA(
        organization_name="python-trio",
        organization_unit_name="trustme",
    )

    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.bytes())

    assert {
        "O=python-trio",
        "OU=trustme",
    }.issubset({rdn.rfc4514_string() for rdn in ca_cert.subject.rdns})


def test_issue_cert_custom_names() -> None:
    ca = CA()
    leaf_cert = ca.issue_cert(
        "example.org",
        organization_name="python-trio",
        organization_unit_name="trustme",
    )

    cert = x509.load_pem_x509_certificate(leaf_cert.cert_chain_pems[0].bytes())

    assert {
        "O=python-trio",
        "OU=trustme",
    }.issubset({rdn.rfc4514_string() for rdn in cert.subject.rdns})


def test_issue_cert_custom_not_after() -> None:
    now = datetime.datetime.now()
    expires = datetime.datetime(2025, 12, 1, 8, 10, 10)
    ca = CA()

    leaf_cert = ca.issue_cert(
        "example.org",
        organization_name="python-trio",
        organization_unit_name="trustme",
        not_after=expires,
    )

    cert = x509.load_pem_x509_certificate(leaf_cert.cert_chain_pems[0].bytes())

    for t in ["year", "month", "day", "hour", "minute", "second"]:
        assert getattr(cert.not_valid_after_utc, t) == getattr(expires, t)


def test_issue_cert_custom_not_before() -> None:
    not_before = datetime.datetime(2027, 7, 5, 17, 15, 30)
    ca = CA()

    leaf_cert = ca.issue_cert(
        "example.org",
        organization_name="python-trio",
        organization_unit_name="trustme",
        not_before=not_before,
    )

    cert = x509.load_pem_x509_certificate(leaf_cert.cert_chain_pems[0].bytes())

    for t in ["year", "month", "day", "hour", "minute", "second"]:
        assert getattr(cert.not_valid_before_utc, t) == getattr(not_before, t)


def test_intermediate() -> None:
    ca = CA()
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.bytes())
    assert_is_ca(ca_cert)
    assert ca_cert.issuer == ca_cert.subject
    assert _path_length(ca_cert) == 9

    child_ca = ca.create_child_ca()
    child_ca_cert = x509.load_pem_x509_certificate(child_ca.cert_pem.bytes())
    assert_is_ca(child_ca_cert)
    assert child_ca_cert.issuer == ca_cert.subject
    assert _path_length(child_ca_cert) == 8
    aki = child_ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert aki.critical is False
    expected_aki_key_id = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest
    assert aki.value.key_identifier == expected_aki_key_id

    child_server = child_ca.issue_cert("test-host.example.org")
    assert len(child_server.cert_chain_pems) == 2
    child_server_cert = x509.load_pem_x509_certificate(
        child_server.cert_chain_pems[0].bytes()
    )
    assert child_server_cert.issuer == child_ca_cert.subject
    assert_is_leaf(child_server_cert)


def test_path_length() -> None:
    ca = CA()
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.bytes())
    assert _path_length(ca_cert) == 9

    child_ca = ca
    for i in range(9):
        child_ca = child_ca.create_child_ca()

    # Can't create new child CAs anymore
    child_ca_cert = x509.load_pem_x509_certificate(child_ca.cert_pem.bytes())
    assert _path_length(child_ca_cert) == 0
    with pytest.raises(ValueError):
        child_ca.create_child_ca()


def test_unrecognized_context_type() -> None:
    ca = CA()
    server = ca.issue_cert("test-1.example.org")

    with pytest.raises(TypeError):
        ca.configure_trust(None)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        server.configure_cert(None)  # type: ignore[arg-type]


def test_blob(tmp_path: Path) -> None:
    test_data = b"xyzzy"
    b = trustme.Blob(test_data)

    # bytes

    assert b.bytes() == test_data

    # write_to_path

    b.write_to_path(str(tmp_path / "test1"))
    with (tmp_path / "test1").open("rb") as f:
        assert f.read() == test_data

    # append=False overwrites
    with (tmp_path / "test2").open("wb") as f:
        f.write(b"asdf")
    b.write_to_path(str(tmp_path / "test2"))
    with (tmp_path / "test2").open("rb") as f:
        assert f.read() == test_data

    # append=True appends
    with (tmp_path / "test2").open("wb") as f:
        f.write(b"asdf")
    b.write_to_path(str(tmp_path / "test2"), append=True)
    with (tmp_path / "test2").open("rb") as f:
        assert f.read() == b"asdf" + test_data

    # tempfile
    with b.tempfile(dir=str(tmp_path)) as path:
        assert path.startswith(str(tmp_path))
        assert path.endswith(".pem")
        with open(path, "rb") as f:
            assert f.read() == test_data


def test_ca_from_pem(tmp_path: Path) -> None:
    ca1 = trustme.CA()
    ca2 = trustme.CA.from_pem(ca1.cert_pem.bytes(), ca1.private_key_pem.bytes())
    assert ca1._certificate == ca2._certificate
    assert ca1.private_key_pem.bytes() == ca2.private_key_pem.bytes()


def check_connection_end_to_end(
    wrap_client: Callable[[CA, socket.socket, str], SslSocket],
    wrap_server: Callable[[LeafCert, socket.socket], SslSocket],
    key_type: KeyType,
) -> None:
    # Client side
    def fake_ssl_client(ca: CA, raw_client_sock: socket.socket, hostname: str) -> None:
        try:
            wrapped_client_sock = wrap_client(ca, raw_client_sock, hostname)
            # Send and receive some data to prove the connection is good
            wrapped_client_sock.send(b"x")
            assert wrapped_client_sock.recv(1) == b"y"
            wrapped_client_sock.close()
        except:  # pragma: no cover
            sys.excepthook(*sys.exc_info())
            raise
        finally:
            raw_client_sock.close()

    # Server side
    def fake_ssl_server(server_cert: LeafCert, raw_server_sock: socket.socket) -> None:
        try:
            wrapped_server_sock = wrap_server(server_cert, raw_server_sock)
            # Prove that we're connected
            assert wrapped_server_sock.recv(1) == b"x"
            wrapped_server_sock.send(b"y")
            wrapped_server_sock.close()
        except:  # pragma: no cover
            sys.excepthook(*sys.exc_info())
            raise
        finally:
            raw_server_sock.close()

    def doit(ca: CA, hostname: str, server_cert: LeafCert) -> None:
        # socketpair and ssl don't work together on py2, because... reasons.
        # So we need to do this the hard way.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        raw_client_sock = socket.socket()
        raw_client_sock.connect(listener.getsockname())
        raw_server_sock, _ = listener.accept()
        listener.close()
        with ThreadPoolExecutor(2) as tpe:
            f1 = tpe.submit(fake_ssl_client, ca, raw_client_sock, hostname)
            f2 = tpe.submit(fake_ssl_server, server_cert, raw_server_sock)
            f1.result()
            f2.result()

    ca = CA(key_type=key_type)
    intermediate_ca = ca.create_child_ca(key_type=key_type)
    hostname = "my-test-host.example.org"

    # Should work
    doit(ca, hostname, ca.issue_cert(hostname, key_type=key_type))

    # Should work
    doit(ca, hostname, intermediate_ca.issue_cert(hostname, key_type=key_type))

    # To make sure that the above success actually required that the
    # CA and cert logic is all working, make sure that the same code
    # fails if the certs or CA aren't right:

    # Bad hostname fails
    with pytest.raises(Exception):
        doit(ca, "asdf.example.org", ca.issue_cert(hostname, key_type=key_type))

    # Bad CA fails
    bad_ca = CA()
    with pytest.raises(Exception):
        doit(bad_ca, hostname, ca.issue_cert(hostname, key_type=key_type))


@pytest.mark.parametrize("key_type", [KeyType.RSA, KeyType.ECDSA])
def test_stdlib_end_to_end(key_type: KeyType) -> None:
    def wrap_client(
        ca: CA, raw_client_sock: socket.socket, hostname: str
    ) -> ssl.SSLSocket:
        ctx = ssl.create_default_context()
        ca.configure_trust(ctx)
        wrapped_client_sock = ctx.wrap_socket(raw_client_sock, server_hostname=hostname)
        print("Client got server cert:", wrapped_client_sock.getpeercert())
        peercert = wrapped_client_sock.getpeercert()
        assert peercert is not None
        san = peercert["subjectAltName"]
        assert san == (("DNS", "my-test-host.example.org"),)
        return wrapped_client_sock

    def wrap_server(
        server_cert: LeafCert, raw_server_sock: socket.socket
    ) -> ssl.SSLSocket:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_cert.configure_cert(ctx)
        wrapped_server_sock = ctx.wrap_socket(raw_server_sock, server_side=True)
        print("server encrypted with:", wrapped_server_sock.cipher())
        return wrapped_server_sock

    check_connection_end_to_end(wrap_client, wrap_server, key_type)


@pytest.mark.parametrize("key_type", [KeyType.RSA, KeyType.ECDSA])
def test_pyopenssl_end_to_end(key_type: KeyType) -> None:
    def wrap_client(
        ca: CA, raw_client_sock: socket.socket, hostname: str
    ) -> OpenSSL.SSL.Connection:
        # Cribbed from example at
        #   https://service-identity.readthedocs.io/en/stable/api.html#service_identity.pyopenssl.verify_hostname
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_verify(
            OpenSSL.SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: bool(ok)
        )
        ca.configure_trust(ctx)
        conn = OpenSSL.SSL.Connection(ctx, raw_client_sock)
        conn.set_connect_state()
        conn.do_handshake()
        service_identity.pyopenssl.verify_hostname(conn, hostname)
        return conn

    def wrap_server(
        server_cert: LeafCert, raw_server_sock: socket.socket
    ) -> OpenSSL.SSL.Connection:
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        server_cert.configure_cert(ctx)

        conn = OpenSSL.SSL.Connection(ctx, raw_server_sock)
        conn.set_accept_state()
        conn.do_handshake()
        return conn

    check_connection_end_to_end(wrap_client, wrap_server, key_type)


def test_identity_variants() -> None:
    ca = CA()

    for bad in [b"example.org", bytearray(b"example.org"), 123]:
        with pytest.raises(TypeError):
            ca.issue_cert(bad)  # type: ignore[arg-type]

    cases = {
        # Traditional ascii hostname
        "example.org": x509.DNSName("example.org"),
        # Wildcard
        "*.example.org": x509.DNSName("*.example.org"),
        # IDN
        "éxamplë.org": x509.DNSName("xn--xampl-9rat.org"),
        "xn--xampl-9rat.org": x509.DNSName("xn--xampl-9rat.org"),
        # IDN + wildcard
        "*.éxamplë.org": x509.DNSName("*.xn--xampl-9rat.org"),
        "*.xn--xampl-9rat.org": x509.DNSName("*.xn--xampl-9rat.org"),
        # IDN that acts differently in IDNA-2003 vs IDNA-2008
        "faß.de": x509.DNSName("xn--fa-hia.de"),
        "xn--fa-hia.de": x509.DNSName("xn--fa-hia.de"),
        # IDN with non-permissable character (uppercase K)
        # (example taken from idna package docs)
        "Königsgäßchen.de": x509.DNSName("xn--knigsgchen-b4a3dun.de"),
        # IP addresses
        "127.0.0.1": x509.IPAddress(IPv4Address("127.0.0.1")),
        "::1": x509.IPAddress(IPv6Address("::1")),
        # Check normalization
        "0000::1": x509.IPAddress(IPv6Address("::1")),
        # IP networks
        "127.0.0.0/24": x509.IPAddress(IPv4Network("127.0.0.0/24")),
        "2001::/16": x509.IPAddress(IPv6Network("2001::/16")),
        # Check normalization
        "2001:0000::/16": x509.IPAddress(IPv6Network("2001::/16")),
        # Email address
        "example@example.com": x509.RFC822Name("example@example.com"),
    }

    for hostname, expected in cases.items():
        # Can't repr the got or expected values here, at least until
        # cryptography v2.1 is out, because in v2.0 on py2, DNSName.__repr__
        # blows up on IDNs.
        print(f"testing: {hostname!r}")
        pem = ca.issue_cert(hostname).cert_chain_pems[0].bytes()
        cert = x509.load_pem_x509_certificate(pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert_is_leaf(cert)
        got = list(san.value)[0]
        assert got == expected


def test_backcompat() -> None:
    ca = CA()
    # We can still use the old name
    ca.issue_server_cert("example.com")


def test_CN() -> None:
    ca = CA()

    # Must be str
    with pytest.raises(TypeError):
        ca.issue_cert(common_name=b"bad kwarg value")  # type: ignore[arg-type]

    # Default is no common name
    pem = ca.issue_cert("example.com").cert_chain_pems[0].bytes()
    cert = x509.load_pem_x509_certificate(pem)
    common_names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    assert common_names == []

    # Common name on its own is valid
    pem = ca.issue_cert(common_name="woo").cert_chain_pems[0].bytes()
    cert = x509.load_pem_x509_certificate(pem)
    common_names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    assert common_names[0].value == "woo"

    # Common name + SAN
    pem = ca.issue_cert("example.com", common_name="woo").cert_chain_pems[0].bytes()
    cert = x509.load_pem_x509_certificate(pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert list(san.value)[0] == x509.DNSName("example.com")
    common_names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    assert common_names[0].value == "woo"
