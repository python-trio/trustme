import pytest

import sys
import ssl
import socket
import threading
import datetime
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import OpenSSL
import service_identity.pyopenssl

from trustme import CA

def test_basics():
    ca = CA()

    today = datetime.datetime.today()

    assert b"BEGIN CERTIFICATE" in ca.cert_pem

    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem, default_backend())
    assert ca_cert.not_valid_before <= today <= ca_cert.not_valid_after

    assert ca_cert.issuer == ca_cert.subject
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca == True
    assert bc.critical == True

    with pytest.raises(ValueError):
        ca.issue_server_cert()

    server = ca.issue_server_cert(u"test-1.example.org", u"test-2.example.org")

    assert b"PRIVATE KEY" in server.private_key_pem
    assert b"BEGIN CERTIFICATE" in server.cert_chain_pem
    assert server.private_key_pem in server.private_key_and_cert_chain_pem
    assert server.cert_chain_pem in server.private_key_and_cert_chain_pem

    server_cert = x509.load_pem_x509_certificate(
        server.cert_chain_pem, default_backend())

    assert server_cert.not_valid_before <= today <= server_cert.not_valid_after
    assert server_cert.issuer == ca_cert.subject

    san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    hostnames = san.value.get_values_for_type(x509.DNSName)
    assert hostnames == [u"test-1.example.org", u"test-2.example.org"]


def test_unrecognized_context_type():
    ca = CA()
    server = ca.issue_server_cert(u"test-1.example.org")

    with pytest.raises(TypeError):
        ca.trust(None)

    with pytest.raises(TypeError):
        server.use(None)


def check_connection_end_to_end(wrap_client, wrap_server):
    ca = CA()
    hostname = u"my-test-host.example.org"
    server_cert = ca.issue_server_cert(hostname)

    # Client side
    def fake_ssl_client(raw_client_sock):
        try:
            wrapped_client_sock = wrap_client(ca, raw_client_sock, hostname)
            # Send and receive some data to prove the connection is good
            wrapped_client_sock.send(b"x")
            assert wrapped_client_sock.recv(1) == b"y"
        except:  # pragma: no cover
            sys.excepthook(*sys.exc_info())
            raise

    # Server side
    def fake_ssl_server(raw_server_sock):
        try:
            wrapped_server_sock = wrap_server(server_cert, raw_server_sock)
            # Prove that we're connected
            assert wrapped_server_sock.recv(1) == b"x"
            wrapped_server_sock.send(b"y")
        except:  # pragma: no cover
            sys.excepthook(*sys.exc_info())
            raise

    # socketpair and ssl don't work together on py2, because... reasons
    #raw_client_sock, raw_server_sock = socket.socketpair()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    raw_client_sock = socket.socket()
    raw_client_sock.connect(listener.getsockname())
    raw_server_sock, _ = listener.accept()
    listener.close()
    with ThreadPoolExecutor(2) as tpe:
        f1 = tpe.submit(fake_ssl_client, raw_client_sock)
        f2 = tpe.submit(fake_ssl_server, raw_server_sock)
        f1.result()
        f2.result()
    raw_client_sock.close()
    raw_server_sock.close()


def test_stdlib_end_to_end():
    def wrap_client(ca, raw_client_sock, hostname):
        ctx = ssl.create_default_context()
        ca.trust(ctx)
        wrapped_client_sock = ctx.wrap_socket(
            raw_client_sock, server_hostname=hostname)
        print("Client got server cert:", wrapped_client_sock.getpeercert())
        peercert = wrapped_client_sock.getpeercert()
        san = peercert["subjectAltName"]
        assert san == (("DNS", "my-test-host.example.org"),)
        return wrapped_client_sock

    def wrap_server(server_cert, raw_server_sock):
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_cert.use(ctx)
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
        ca.trust(ctx)
        conn = OpenSSL.SSL.Connection(ctx, raw_client_sock)
        conn.set_connect_state()
        conn.do_handshake()
        service_identity.pyopenssl.verify_hostname(conn, hostname)
        return conn

    def wrap_server(server_cert, raw_server_sock):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        server_cert.use(ctx)

        conn = OpenSSL.SSL.Connection(ctx, raw_server_sock)
        conn.set_accept_state()
        conn.do_handshake()
        return conn

    check_connection_end_to_end(wrap_client, wrap_server)
