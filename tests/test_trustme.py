# -*- coding: utf-8 -*-

import pytest

import sys
import ssl
import socket
import threading
import datetime
from concurrent.futures import ThreadPoolExecutor

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import OpenSSL
import service_identity.pyopenssl

import trustme
from trustme import CA

def test_basics():
    ca = CA()

    today = datetime.datetime.today()

    assert b"BEGIN CERTIFICATE" in ca.cert_pem.bytes()

    ca_cert = x509.load_pem_x509_certificate(
        ca.cert_pem.bytes(), default_backend())
    assert ca_cert.not_valid_before <= today <= ca_cert.not_valid_after

    assert ca_cert.issuer == ca_cert.subject
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca == True
    assert bc.critical == True

    with pytest.raises(ValueError):
        ca.issue_server_cert()

    server = ca.issue_server_cert(u"test-1.example.org", u"test-2.example.org")

    assert b"PRIVATE KEY" in server.private_key_pem.bytes()
    assert b"BEGIN CERTIFICATE" in server.cert_chain_pems[0].bytes()
    assert len(server.cert_chain_pems) == 1
    assert server.private_key_pem.bytes() in server.private_key_and_cert_chain_pem.bytes()
    for blob in server.cert_chain_pems:
        assert blob.bytes() in server.private_key_and_cert_chain_pem.bytes()

    server_cert = x509.load_pem_x509_certificate(
        server.cert_chain_pems[0].bytes(), default_backend())

    assert server_cert.not_valid_before <= today <= server_cert.not_valid_after
    assert server_cert.issuer == ca_cert.subject

    san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    hostnames = san.value.get_values_for_type(x509.DNSName)
    assert hostnames == [u"test-1.example.org", u"test-2.example.org"]


def test_unrecognized_context_type():
    ca = CA()
    server = ca.issue_server_cert(u"test-1.example.org")

    with pytest.raises(TypeError):
        ca.configure_trust(None)

    with pytest.raises(TypeError):
        server.configure_cert(None)


def test_blob(tmpdir):
    test_data = b"xyzzy"
    b = trustme.Blob(test_data)

    # bytes

    assert b.bytes() == test_data

    # write_to_path

    b.write_to_path(str(tmpdir / "test1"))
    with (tmpdir / "test1").open("rb") as f:
        assert f.read() == test_data

    # append=False overwrites
    with (tmpdir / "test2").open("wb") as f:
        f.write(b"asdf")
    b.write_to_path(str(tmpdir / "test2"))
    with (tmpdir / "test2").open("rb") as f:
        assert f.read() == test_data

    # append=True appends
    with (tmpdir / "test2").open("wb") as f:
        f.write(b"asdf")
    b.write_to_path(str(tmpdir / "test2"), append=True)
    with (tmpdir / "test2").open("rb") as f:
        assert f.read() == b"asdf" + test_data

    # tempfile
    with b.tempfile(dir=str(tmpdir)) as path:
        assert path.startswith(str(tmpdir))
        assert path.endswith(".pem")
        with open(path, "rb") as f:
            assert f.read() == test_data


def check_connection_end_to_end(wrap_client, wrap_server):
    # Client side
    def fake_ssl_client(ca, raw_client_sock, hostname):
        try:
            wrapped_client_sock = wrap_client(ca, raw_client_sock, hostname)
            # Send and receive some data to prove the connection is good
            wrapped_client_sock.send(b"x")
            assert wrapped_client_sock.recv(1) == b"y"
        except:  # pragma: no cover
            sys.excepthook(*sys.exc_info())
            raise
        finally:
            raw_client_sock.close()

    # Server side
    def fake_ssl_server(server_cert, raw_server_sock):
        try:
            wrapped_server_sock = wrap_server(server_cert, raw_server_sock)
            # Prove that we're connected
            assert wrapped_server_sock.recv(1) == b"x"
            wrapped_server_sock.send(b"y")
        except:  # pragma: no cover
            sys.excepthook(*sys.exc_info())
            raise
        finally:
            raw_server_sock.close()

    def doit(ca, hostname, server_cert):
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

    ca = CA()
    hostname = u"my-test-host.example.org"
    server_cert = ca.issue_server_cert(hostname)

    # Should work
    doit(ca, hostname, server_cert)

    # To make sure that the above success actually required that the
    # CA and cert logic is all working, make sure that the same code
    # fails if the certs or CA aren't right:

    # Bad hostname fails
    with pytest.raises(Exception):
        doit(ca, u"asdf.example.org", server_cert)

    # Bad CA fails
    bad_ca = CA()
    with pytest.raises(Exception):
        doit(bad_ca, hostname, server_cert)


def test_stdlib_end_to_end():
    def wrap_client(ca, raw_client_sock, hostname):
        ctx = ssl.create_default_context()
        ca.configure_trust(ctx)
        wrapped_client_sock = ctx.wrap_socket(
            raw_client_sock, server_hostname=hostname)
        print("Client got server cert:", wrapped_client_sock.getpeercert())
        peercert = wrapped_client_sock.getpeercert()
        san = peercert["subjectAltName"]
        assert san == (("DNS", "my-test-host.example.org"),)
        return wrapped_client_sock

    def wrap_server(server_cert, raw_server_sock):
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_cert.configure_cert(ctx)
        wrapped_server_sock = ctx.wrap_socket(
            raw_server_sock, server_side=True)
        print("server encrypted with:", wrapped_server_sock.cipher())
        return wrapped_server_sock

    check_connection_end_to_end(wrap_client, wrap_server)


def test_pyopenssl_end_to_end():
    def wrap_client(ca, raw_client_sock, hostname):
        # Cribbed from example at
        #   https://service-identity.readthedocs.io/en/stable/api.html#service_identity.pyopenssl.verify_hostname
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_verify(OpenSSL.SSL.VERIFY_PEER,
                       lambda conn, cert, errno, depth, ok: ok)
        ca.configure_trust(ctx)
        conn = OpenSSL.SSL.Connection(ctx, raw_client_sock)
        conn.set_connect_state()
        conn.do_handshake()
        service_identity.pyopenssl.verify_hostname(conn, hostname)
        return conn

    def wrap_server(server_cert, raw_server_sock):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        server_cert.configure_cert(ctx)

        conn = OpenSSL.SSL.Connection(ctx, raw_server_sock)
        conn.set_accept_state()
        conn.do_handshake()
        return conn

    check_connection_end_to_end(wrap_client, wrap_server)


def test_hostname_variants():
    ca = CA()

    for bad in [b"example.org", bytearray(b"example.org"), 123]:
        with pytest.raises(TypeError):
            ca.issue_server_cert(bad)

    cases = {
        # Traditional ascii hostname
        u"example.org": x509.DNSName(u"example.org"),

        # Wildcard
        u"*.example.org": x509.DNSName(u"*.example.org"),

        # IDN
        u"éxamplë.org": x509.DNSName(u"éxamplë.org"),
        u"xn--xampl-9rat.org": x509.DNSName(u"éxamplë.org"),

        # IDN + wildcard
        u"*.éxamplë.org": x509.DNSName(u"*.éxamplë.org"),
        u"*.xn--xampl-9rat.org": x509.DNSName(u"*.éxamplë.org"),

        # IDN that acts differently in IDNA-2003 vs IDNA-2008
        u"faß.de": x509.DNSName(u"faß.de"),
        u"xn--fa-hia.de": x509.DNSName(u"faß.de"),

        # IDN with non-permissable character (uppercase K)
        # (example taken from idna package docs)
        u"Königsgäßchen.de": x509.DNSName(u"königsgäßchen.de"),

        # IP addresses
        u"127.0.0.1": x509.IPAddress(IPv4Address(u"127.0.0.1")),
        u"::1": x509.IPAddress(IPv6Address(u"::1")),
        # Check normalization
        u"0000::1": x509.IPAddress(IPv6Address(u"::1")),

        # IP networks
        u"127.0.0.0/24": x509.IPAddress(IPv4Network(u"127.0.0.0/24")),
        u"2001::/16": x509.IPAddress(IPv6Network(u"2001::/16")),
        # Check normalization
        u"2001:0000::/16": x509.IPAddress(IPv6Network(u"2001::/16")),
    }

    for hostname, expected in cases.items():
        # Can't repr the got or expected values here, at least until
        # cryptography v2.1 is out, because in v2.0 on py2, DNSName.__repr__
        # blows up on IDNs.
        print("testing: {!r}".format(hostname))
        pem = ca.issue_server_cert(hostname).cert_chain_pems[0].bytes()
        cert = x509.load_pem_x509_certificate(pem, default_backend())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        got = san.value[0]
        assert got == expected
