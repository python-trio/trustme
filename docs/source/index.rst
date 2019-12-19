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
   :exclude-members: issue_server_cert

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

Trustme 0.6.0 (2019-12-19)
--------------------------

Features
~~~~~~~~

- Allow specifying organization and organization unit in CA and issued certs. (`#126 <https://github.com/python-trio/trustme/issues/126>`__)


Trustme 0.5.3 (2019-10-31)
--------------------------

Features
~~~~~~~~

- Added :attr:`CA.from_pem` to import an existing certificate authority; this allows migrating to trustme step-by-step. (`#107 <https://github.com/python-trio/trustme/issues/107>`__)


Trustme 0.5.2 (2019-06-03)
--------------------------

Bugfixes
~~~~~~~~

- Update to avoid a deprecation warning on cryptography 2.7. (`#47 <https://github.com/python-trio/trustme/issues/47>`__)


Trustme 0.5.1 (2019-04-15)
--------------------------

Bugfixes
~~~~~~~~

- Update key size to 2048 bits, as required by recent Debian. (`#45 <https://github.com/python-trio/trustme/issues/45>`__)


Trustme 0.5.0 (2019-01-21)
--------------------------

Features
~~~~~~~~

- Added :meth:`CA.create_child_ca` to allow for certificate chains (`#3 <https://github.com/python-trio/trustme/issues/3>`__)
- Added :attr:`CA.private_key_pem` to export CA private keys; this allows signing other certs with the same CA outside of trustme. (`#27 <https://github.com/python-trio/trustme/issues/27>`__)
- CAs now include the KeyUsage and ExtendedKeyUsage extensions configured for SSL certificates. (`#30 <https://github.com/python-trio/trustme/issues/30>`__)
- `CA.issue_cert` now accepts email addresses as a valid form of identity. (`#33 <https://github.com/python-trio/trustme/issues/33>`__)
- It's now possible to set the "common name" of generated certs; see `CA.issue_cert` for details. (`#34 <https://github.com/python-trio/trustme/issues/34>`__)
- ``CA.issue_server_cert`` has been renamed to `CA.issue_cert`, since it supports both server and client certs. To preserve backwards compatibility, the old name is retained as an undocumented alias. (`#35 <https://github.com/python-trio/trustme/issues/35>`__)


Bugfixes
~~~~~~~~

- Make sure cert expiration dates don't exceed 2038-01-01, to avoid
  issues on some 32-bit platforms that suffer from the `Y2038 problem
  <https://en.wikipedia.org/wiki/Year_2038_problem>`__. (`#41 <https://github.com/python-trio/trustme/issues/41>`__)


Trustme 0.4.0 (2017-08-06)
--------------------------

Features
~~~~~~~~

- :meth:`CA.issue_cert` now accepts IP addresses and IP networks.
  (`#19 <https://github.com/python-trio/trustme/issues/19>`__)


Bugfixes
~~~~~~~~

- Start doing our own handling of Unicode hostname (IDNs), instead of relying
  on cryptography to do it; this allows us to correctly handle a broader range
  of cases, and avoids relying on soon-to-be-deprecated behavior (`#17
  <https://github.com/python-trio/trustme/issues/17>`__)
- Generated certs no longer contain a subject:commonName field, to better match
  CABF guidelines (`#18 <https://github.com/python-trio/trustme/issues/18>`__)


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
