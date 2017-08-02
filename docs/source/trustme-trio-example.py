# trustme-trio-example.py

import trustme
import trio

# Create our fake certificates
ca = trustme.CA()
server_cert = ca.issue_server_cert(u"test-host.example.org")


async def demo_server(server_raw_stream):
    server_ssl_context = trio.ssl.create_default_context(
        trio.ssl.Purpose.CLIENT_AUTH)

    # Set up the server's SSLContext to use our fake server cert
    server_cert.configure_cert(server_ssl_context)

    server_ssl_stream = trio.ssl.SSLStream(
        server_raw_stream,
        server_ssl_context,
        server_side=True,
    )

    # Send some data to check that the connection is really working
    await server_ssl_stream.send_all(b"x")


async def demo_client(client_raw_stream):
    client_ssl_context = trio.ssl.create_default_context()

    # Set up the client's SSLContext to trust our fake CA, that signed our
    # server cert
    ca.configure_trust(client_ssl_context)

    client_ssl_stream = trio.ssl.SSLStream(
        client_raw_stream,
        client_ssl_context,
        # Tell the client that it's looking for a trusted cert for this
        # particular hostname (must match what we passed to issue_server_cert)
        server_hostname="test-host.example.org",
    )

    assert await client_ssl_stream.receive_some(1) == b"x"
    print("Client successfully received data over the encrypted channel!")
    print("Cert looks like:", client_ssl_stream.getpeercert())


async def main():
    from trio.testing import memory_stream_pair
    server_raw_stream, client_raw_stream = memory_stream_pair()

    async with trio.open_nursery() as nursery:
        nursery.spawn(demo_server, server_raw_stream)
        nursery.spawn(demo_client, client_raw_stream)


trio.run(main)
