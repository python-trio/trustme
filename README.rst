trustme: #1 quality TLS certs while you wait
============================================

.. image:: https://vignette2.wikia.nocookie.net/jadensadventures/images/1/1e/Kaa%27s_hypnotic_eyes.jpg/revision/latest?cb=20140310173415
   :width: 200px
   :align: right

You wrote a cool network client or server. You encrypt your
connections using `TLS
<https://en.wikipedia.org/wiki/Transport_Layer_Security>`__. Your test
suite needs to make TLS connections.

Uh oh. Your test suite *probably* doesn't have a valid TLS
certificate. Now what?

``trustme`` is a tiny Python package that does one thing: it gives you
a `fake <https://martinfowler.com/bliki/TestDouble.html>`__
certificate authority (CA) that you can use to generate fake TLS certs
to use in your tests. Well, technically they're real certs, they're
just signed by your CA, which nobody trusts. But you can trust
it. Trust me.


Example
=======

.. code-block:: python

   from trustme import CA

   # Look, you just became a certificate authority
   ca = CA()

   # Issue a server cert, signed by your fake CA
   # https://en.wikipedia.org/wiki/Example.org
   server_cert = ca.issue_server_cert(u"my-test-host.example.org")

   # That's it! You have your certs. Now let's see how to use them.

   ###########

   # The simplest thing to do is to take the raw PEM certificates, and
   # write them out to some files. Maybe this is useful if you want to 
   # use them for a test suite written in some other language.

   with open("fake-ca.pem", "wb") as f:
       f.write(ca.cert_pem)
   with open("fake-server-private-key-and-cert-chain.pem", "wb") as f:
       f.write(server_cert.private_key_and_cert_chain_pem)

   ###########

   # Or, you can use them directly, for example to make a within-process
   # connection between two threads.

   import ssl, socket, threading

   # Client side
   def fake_ssl_client(raw_client_sock):
       # Get an ssl.SSLContext object configured to trust your CA
       ssl_ctx = ca.stdlib_client_context()
       wrapped_client_sock = ssl_ctx.wrap_socket(
           raw_client_sock, server_hostname="my-test-host.example.org")
       # Look, here's the cert presented by the server
       print("Client got server cert:", wrapped_client_sock.getpeercert())
       # Send some data to prove the connection is good
       wrapped_client_sock.send(b"x")

   # Server side
   def fake_ssl_server(raw_server_sock):
       # Get an ssl.SSLContext object configured to use your server cert
       ssl_ctx = server_cert.stdlib_server_context()
       wrapped_server_sock = ssl_ctx.wrap_socket(raw_server_sock, server_side=True)
       # Prove that we're connected
       print("server encrypted with:", wrapped_server_sock.cipher())
       assert wrapped_server_sock.recv(1) == b"x"

   # Blah blah blah actually run the things
   raw_client_sock, raw_server_sock = socket.socketpair()
   client_thread = threading.Thread(target=fake_ssl_client, args=(raw_client_sock,))
   server_thread = threading.Thread(target=fake_ssl_server, args=(raw_server_sock,))
   client_thread.start()
   server_thread.start()
   client_thread.join()
   server_thread.join()


Docs
====

``CA()`` gives you a certificate authority. It has attributes
``.cert_pem`` which is a bytestring containing what it sounds like,
``.issue_server_cert(hostname1, [hostname2, ...])`` which does what it
says on the tin, and ``.stdlib_client_context()``, which is a
convenience method that returns an ``ssl.SSLContext`` object
preconfigured to trust this CA.

``CA.issue_server_cert`` returns a ``ServerCert`` object, which has
attributes ``.private_key_pem``, ``.cert_chain_pem``, and
``.private_key_and_cert_chain_pem``, which are bytestrings containing
what they sound like. It also has a convenience method
``.stdlib_server_context()`` which returns an ``ssl.SSLContext``
object preconfigured to present this cert to any client that
connects.

The ``.stdlib_*_context`` methods accept ``**kwargs``, which are
passed on to `ssl.create_default_context
<https://docs.python.org/3/library/ssl.html#ssl.create_default_context>`__.

Probably this should get moved into Sphinx or something but whatever,
hopefully you get the idea. Or feel free to send a PR converting this
into proper docs.


FAQ
===

**Should I use these certs for anything real?** Certainly not.

**Why not just use self-signed certificates?** These are more
realistic. You don't have to disable your certificate validation code
in your test suite, which is good, because you want to test what you
run in production, and you would *never* disable your certificate
validation code in production, right? Plus they're just as easy to
work with. Maybe easier.

**Why do you only have convenience methods for the stdlib ssl module,
and not PyOpenSSL / Twisted / ...?** Because you didn't send me a PR
yet.

**I want to test some weirdo TLS configuration.** I'm happy to accept
PRs to do simple things like override the default validity period or
set key sizes or whatever, within reason. But if you have complicated
needs then you're probably better offer stealing the code from this
library and adapting it to do what you want. The underlying API is
pretty straightforward. This is just a convenience library for those
of us who need a cheat sheet to tie our shoelaces, X.509-wise.


Vital statistics
================

**Bug tracker and source code:** https://github.com/python-trio/trustme

**License:** MIT or Apache 2, your choice.

**Install:** ``pip install -U trustme``

**Code of conduct:** Contributors are requested to follow our `code of
conduct
<https://github.com/python-trio/trustme/blob/master/CODE_OF_CONDUCT.md>`__
in all project spaces.


Acknowledgements
================

This is basically just a trivial wrapper around the awesome Python
`cryptography <https://cryptography.io/>`__ library. Also, `Glyph
<https://glyph.twistedmatrix.com/>`__ wrote most of the tricky bits. I
got tired of never being able to remember how this works or find the
magic snippets to copy/paste, so I stole the code out of `Twisted
<http://twistedmatrix.com/>`__ and wrapped it in a bow.
