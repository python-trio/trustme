# trustme-trio-example.py

import trustme
import trio

# Create our fake certificates
ca = trustme.CA()
client_ca = trustme.CA()
server_cert = ca.issue_cert(u"test-host.example.org")
client_cert = client_ca.issue_cert(u"@webknjaz here")


async def demo_server(server_raw_stream):
    server_ssl_context = trio.ssl.create_default_context(
        trio.ssl.Purpose.CLIENT_AUTH)

    # Set up the server's SSLContext to use our fake server cert
    server_cert.configure_cert(server_ssl_context)

    # Set up the server's SSLContext to trust our fake CA, that signed
    # our client cert
    client_ca.configure_trust(server_ssl_context)

    # Verify that client sent us their TLS cert signed by a trusted CA
    server_ssl_context.verify_mode = trio.ssl.CERT_REQUIRED

    server_ssl_stream = trio.ssl.SSLStream(
        server_raw_stream,
        server_ssl_context,
        server_side=True,
    )

    # Send some data to check that the connection is really working
    await server_ssl_stream.send_all(b"x")
    print("Server successfully sent data over the encrypted channel!")
    print("Client cert looks like:", server_ssl_stream.getpeercert())


async def demo_client(client_raw_stream):
    client_ssl_context = trio.ssl.create_default_context()

    # Set up the client's SSLContext to trust our fake CA, that signed our
    # server cert
    ca.configure_trust(client_ssl_context)

    # Set up the client's SSLContext to use our fake client cert
    client_cert.configure_cert(client_ssl_context)

    client_ssl_stream = trio.ssl.SSLStream(
        client_raw_stream,
        client_ssl_context,
        # Tell the client that it's looking for a trusted cert for this
        # particular hostname (must match what we passed to issue_cert)
        server_hostname="test-host.example.org",
    )

    assert await client_ssl_stream.receive_some(1) == b"x"
    print("Client successfully received data over the encrypted channel!")
    print("Server cert looks like:", client_ssl_stream.getpeercert())


async def main():
    from trio.testing import memory_stream_pair
    server_raw_stream, client_raw_stream = memory_stream_pair()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(demo_server, server_raw_stream)
        nursery.start_soon(demo_client, client_raw_stream)


trio.run(main)
