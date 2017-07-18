import pytest

import ssl
import socket
import threading
import datetime
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.backends import default_backend

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


def test_connection_using_stdlib():
    ca = CA()
    server_cert = ca.issue_server_cert(u"my-test-host.example.org")

    # Client side
    def fake_ssl_client(raw_client_sock):
        ssl_ctx = ca.stdlib_client_context()
        wrapped_client_sock = ssl_ctx.wrap_socket(
            raw_client_sock, server_hostname="my-test-host.example.org")
        print("Client got server cert:", wrapped_client_sock.getpeercert())
        peercert = wrapped_client_sock.getpeercert()
        san = peercert["subjectAltName"]
        assert san == (("DNS", "my-test-host.example.org"),)
        # Send and receive some data to prove the connection is good
        wrapped_client_sock.send(b"x")
        assert wrapped_client_sock.recv(1) == b"y"

    # Server side
    def fake_ssl_server(raw_server_sock):
        # Get an ssl.SSLContext object configured to use your server cert
        ssl_ctx = server_cert.stdlib_server_context()
        wrapped_server_sock = ssl_ctx.wrap_socket(raw_server_sock, server_side=True)
        # Prove that we're connected
        print("server encrypted with:", wrapped_server_sock.cipher())
        assert wrapped_server_sock.recv(1) == b"x"
        wrapped_server_sock.send(b"y")

    raw_client_sock, raw_server_sock = socket.socketpair()
    with ThreadPoolExecutor(2) as tpe:
        f1 = tpe.submit(fake_ssl_client, raw_client_sock)
        f2 = tpe.submit(fake_ssl_server, raw_server_sock)
        f1.result()
        f2.result()
