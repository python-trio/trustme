.. note that this README gets 'include'ed into the main documentation

==============================================
 trustme: #1 quality TLS certs while you wait
==============================================

.. image:: https://vignette2.wikia.nocookie.net/jadensadventures/images/1/1e/Kaa%27s_hypnotic_eyes.jpg/revision/latest?cb=20140310173415
   :width: 200px
   :align: right

You wrote a cool network client or server. It encrypts connections
using `TLS
<https://en.wikipedia.org/wiki/Transport_Layer_Security>`__. Your test
suite needs to make TLS connections to itself.

Uh oh. Your test suite *probably* doesn't have a valid TLS
certificate. Now what?

``trustme`` is a tiny Python package that does one thing: it gives you
a `fake <https://martinfowler.com/bliki/TestDouble.html>`__
certificate authority (CA) that you can use to generate fake TLS certs
to use in your tests. Well, technically they're real certs, they're
just signed by your CA, which nobody trusts. But you can trust
it. Trust me.


Vital statistics
================

**Install:** ``pip install -U trustme``

**Documentation:** https://trustme.readthedocs.io

**Bug tracker and source code:** https://github.com/python-trio/trustme

**Tested on:** Python 3.7+, CPython and PyPy

**License:** MIT or Apache 2, your choice.

**Code of conduct:** Contributors are requested to follow our `code of
conduct
<https://github.com/python-trio/trustme/blob/master/CODE_OF_CONDUCT.md>`__
in all project spaces.


Cheat sheet
===========

Programmatic usage:

.. code-block:: python

   import trustme

   # ----- Creating certs -----

   # Look, you just created your certificate authority!
   ca = trustme.CA()

   # And now you issued a cert signed by this fake CA
   # https://en.wikipedia.org/wiki/Example.org
   server_cert = ca.issue_cert(u"test-host.example.org")

   # That's it!

   # ----- Using your shiny new certs -----

   # You can configure SSL context objects to trust this CA:
   ca.configure_trust(ssl_context)
   # Or configure them to present the server certificate
   server_cert.configure_cert(ssl_context)
   # You can use standard library or PyOpenSSL context objects here,
   # trustme is happy either way.

   # ----- or -----
                
   # Save the PEM-encoded data to a file to use in non-Python test
   # suites:
   ca.cert_pem.write_to_path("ca.pem")
   server_cert.private_key_and_cert_chain_pem.write_to_path("server.pem")
   
   # ----- or -----
                
   # Put the PEM-encoded data in a temporary file, for libraries that
   # insist on that:
   with ca.cert_pem.tempfile() as ca_temp_path:
       requests.get("https://...", verify=ca_temp_path)

Command line usage:

.. code-block:: console

   $ # Certs may be generated from anywhere. Here's where we are:
   $ pwd
   /tmp
   $ # ----- Creating certs -----
   $ python -m trustme
   Generated a certificate for 'localhost', '127.0.0.1', '::1'
   Configure your server to use the following files:
     cert=/tmp/server.pem
     key=/tmp/server.key
   Configure your client to use the following files:
     cert=/tmp/client.pem
   $ # ----- Using certs -----
   $ gunicorn --keyfile server.key --certfile server.pem app:app
   $ curl --cacert client.pem https://localhost:8000/
   Hello, world!


FAQ
===

**Should I use these certs for anything real?** Certainly not.

**Why not just use self-signed certificates?** These are more
realistic. You don't have to disable your certificate validation code
in your test suite, which is good because you want to test what you
run in production, and you would *never* disable your certificate
validation code in production, right? Plus, they're just as easy to
work with. Actually easier, in many cases.

**What if I want to test how my code handles some bizarre TLS
configuration?** We think trustme hits a sweet spot of ease-of-use
and generality as it is. The defaults are carefully chosen to work
on all major operating systems and be as fast as possible. We don't
want to turn trustme into a second-rate re-export of everything in
`cryptography <https://cryptography.io>`__. If you have more complex
needs, consider using them directly, possibly starting from the
trustme code.

**Will you automate installing CA cert into system trust store?** No.
`mkcert <https://github.com/FiloSottile/mkcert>`__ already does this
well, and we would not have anything to add.
