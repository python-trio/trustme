.. module:: trustme

.. include:: ../../README.rst


Full working example
====================

Here's a fully working example you can run to see how :mod:`trustme`
works. It demonstrates a simple TLS server and client that connect to
each other using :mod:`trustme`\-generated certs.

This example requires `Trio <https://trio.readthedocs.io>`__ (``pip
install -U trio``) and Python 3.5+. Note that while :mod:`trustme` is
maintained by the Trio project, :mod:`trustme` is happy to work with
any networking library, and also supports Python 2.

[Actually, as of 2017-08-02 this needs the dev branch of Trio: ``pip
install -U https://github.com/pythontrio/trio/archive/master.zip``. If
you notice this message is still here after Trio v0.2.0 has been
released then please `poke me
<https://github.com/python-trio/trustme/issues/new>`__.]

The key lines are the calls to :meth:`~CA.configure_trust`,
:meth:`~LeafCert.configure_cert` – try commenting them out one at a
time to see what happens! Also notice that the hostname
``test-host.example.org`` appears twice – try changing one of the
strings so that the two copies no longer match, and see what happens
then!

.. literalinclude:: trustme-trio-example.py


API reference
=============

.. autoclass:: CA
   :members:

.. autoclass:: LeafCert()
   :members:

.. autoclass:: Blob()

   .. automethod:: bytes

   .. automethod:: tempfile
      :with: path

   .. automethod:: write_to_path


Change history
==============

.. towncrier release notes start

Trustme 0.3.0 (2017-08-03)
--------------------------

Bugfixes
~~~~~~~~

- Don't crash on Windows (`#10
  <https://github.com/python-trio/trustme/issues/10>`__)


Misc
~~~~

- `#11 <https://github.com/python-trio/trustme/issues/11>`__, `#12
  <https://github.com/python-trio/trustme/issues/12>`__


Trustme 0.2.0 (2017-08-02)
--------------------------

- Broke and re-did almost the entire public API. Sorry! Let's just
  pretend v0.1.0 never happened.

- Hey there are docs now though, that should be worth something right?


Trustme 0.1.0 (2017-07-18)
--------------------------

- Initial release


Acknowledgements
================

This is basically just a trivial wrapper around the awesome Python
`cryptography <https://cryptography.io/>`__ library. Also, `Glyph
<https://glyph.twistedmatrix.com/>`__ originally wrote most of the
tricky bits. I got tired of never being able to remember how this
works or find the magic snippets to copy/paste, so I stole the code
out of `Twisted <http://twistedmatrix.com/>`__ and wrapped it in a
bow.
