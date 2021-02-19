# -*- coding: utf-8 -*-

import datetime
import re
import ssl
from base64 import urlsafe_b64encode
from tempfile import NamedTemporaryFile
from contextlib import contextmanager
import os

import ipaddress
import idna

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    PrivateFormat, NoEncryption
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from ._version import __version__

__all__ = ["CA"]

# Python 2/3 annoyingness
try:
    unicode
except NameError:
    unicode = str

# On my laptop, making a CA + server certificate using 2048 bit keys takes ~160
# ms, and using 4096 bit keys takes ~2 seconds. We want tests to run in 160 ms,
# not 2 seconds. And we can't go lower, since Debian (and probably others)
# by default reject any keys with <2048 bits (see #45).
_KEY_SIZE = 2048

# Default certificate expiry date
DEFAULT_NOT_AFTER = datetime.datetime(2038, 1, 1)


def _name(name, organization_name=None, common_name=None):
    name_pieces = [
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            organization_name or u"trustme v{}".format(__version__),
        ),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name),
    ]
    if common_name is not None:
        name_pieces.append(
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        )
    return x509.Name(name_pieces)


def random_text():
    return urlsafe_b64encode(os.urandom(12)).decode("ascii")


def _smells_like_pyopenssl(ctx):
    return getattr(ctx, "__module__", "").startswith("OpenSSL")


def _cert_builder_common(subject, issuer, public_key, not_after=None):
    if not_after is None:
        not_after = DEFAULT_NOT_AFTER
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .not_valid_before(datetime.datetime(2000, 1, 1))
        # OpenSSL on Windows fails if you try to give it a date after
        # ~3001-01-19:
        #   https://github.com/pyca/cryptography/issues/3194
        # Some versions of cryptography on 32-bit platforms fail if you give
        # them dates after ~2038-01-19:
        #   https://github.com/pyca/cryptography/pull/4658
        .not_valid_after(not_after)
        .serial_number(x509.random_serial_number())
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )


def _identity_string_to_x509(identity):
    # Because we are a DWIM library for lazy slackers, we cheerfully pervert
    # the cryptography library's carefully type-safe API, and silently DTRT
    # for any of the following identity types:
    #
    # - "example.org"
    # - "example.org"
    # - "éxamplë.org"
    # - "xn--xampl-9rat.org"
    # - "xn--xampl-9rat.org"
    # - "127.0.0.1"
    # - "::1"
    # - "10.0.0.0/8"
    # - "2001::/16"
    # - "example@example.org"
    #
    # plus wildcard variants of the identities.
    if not isinstance(identity, unicode):
        raise TypeError("identities must be text (unicode on py2, str on py3)")

    if u"@" in identity:
        return x509.RFC822Name(identity)

    # Have to try ip_address first, because ip_network("127.0.0.1") is
    # interpreted as being the network 127.0.0.1/32. Which I guess would be
    # fine, actually, but why risk it.
    for ip_converter in [ipaddress.ip_address, ipaddress.ip_network]:
        try:
            ip_hostname = ip_converter(identity)
        except ValueError:
            continue
        else:
            return x509.IPAddress(ip_hostname)

    # Encode to an A-label, like cryptography wants
    if identity.startswith("*."):
        alabel_bytes = b"*." + idna.encode(identity[2:], uts46=True)
    else:
        alabel_bytes = idna.encode(identity, uts46=True)
    # Then back to text, which is mandatory on cryptography 2.0 and earlier,
    # and may or may not be deprecated in cryptography 2.1.
    alabel = alabel_bytes.decode("ascii")
    return x509.DNSName(alabel)


def timespan_to_timedelta(value):
    # Given a timespan as a string in the format of Dt, where D is some
    # number and t is a letter representing some span of time:
    #   H - hour
    #   M - minute
    #   S - second
    #   d - day
    #   w - week
    #   m - month
    #   y - year
    #
    #  ...returns a datetime.timedelta representing that span of time.
    #
    # Examples: 7d = 7 days, 9m = 9 months, 2H = 2 hours
    timespans = {
        # key -> type, multiplier
        "H": ["hours", 1],
        "M": ["minutes", 1],
        "S": ["seconds", 1],
        "d": ["days", 1],
        "w": ["weeks", 1],
        "m": ["days", 30],
        "y": ["days", 365],
    }
    check_pattern = "^(\d+)([{spans}])$".format(
        spans="".join(timespans.keys())
    )
    m = re.match(check_pattern, value)
    if m is None:
        raise ValueError(
            (
                "Value '{}' is not in the expected timespan format "
                "of Dt, where D is a number and t is one of 'H', "
                "'M', 'S', 'd', 'w', 'm', or 'y'"
            ).format(value)
        )
    duration, span = m.groups()
    delta_kwargs = {timespans[span][0]: timespans[span][1] * int(duration)}
    return datetime.timedelta(**delta_kwargs)


class Blob(object):
    """A convenience wrapper for a blob of bytes.

    This type has no public constructor. They're used to provide a handy
    interface to the PEM-encoded data generated by `trustme`. For example, see
    `CA.cert_pem` or `LeafCert.private_key_and_cert_chain_pem`.

    """
    def __init__(self, data):
        self._data = data

    def bytes(self):
        """Returns the data as a `bytes` object.

        """
        return self._data

    def write_to_path(self, path, append=False):
        """Writes the data to the file at the given path.

        Args:
          path (str): The path to write to.
          append (bool): If False (the default), replace any existing file
               with the given name. If True, append to any existing file.

        """
        if append:
            mode = "ab"
        else:
            mode = "wb"
        with open(path, mode) as f:
            f.write(self._data)

    @contextmanager
    def tempfile(self, dir=None):
        """Context manager for writing data to a temporary file.

        The file is created when you enter the context manager, and
        automatically deleted when the context manager exits.

        Many libraries have annoying APIs which require that certificates be
        specified as filesystem paths, so even if you have already the data in
        memory, you have to write it out to disk and then let them read it
        back in again. If you encouter such a library, you should probably
        file a bug. But in the mean time, this context manager makes it easy
        to give them what they want.

        Example:

          Here's how to get requests to use a trustme CA (`see also
          <http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification>`__)::

           ca = trustme.CA()
           with ca.cert_pem.tempfile() as ca_cert_path:
               requests.get("https://localhost/...", verify=ca_cert_path)

        Args:
          dir (str or None): Passed to `tempfile.NamedTemporaryFile`.

        """
        # On Windows, you can't re-open a NamedTemporaryFile that's still
        # open. Which seems like it completely defeats the purpose of having a
        # NamedTemporaryFile? Oh well...
        # https://bugs.python.org/issue14243
        f = NamedTemporaryFile(suffix=".pem", dir=dir, delete=False)
        try:
            f.write(self._data)
            f.close()
            yield f.name
        finally:
            f.close()  # in case write() raised an error
            os.unlink(f.name)


class CA(object):
    """A certificate authority."""
    def __init__(
        self,
        parent_cert=None,
        path_length=9,
        organization_name=None,
        organization_unit_name=None,
    ):
        self.parent_cert = parent_cert
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_KEY_SIZE,
            backend=default_backend()
        )
        self._path_length = path_length

        name = _name(
            organization_unit_name or u"Testing CA #" + random_text(),
            organization_name=organization_name,
        )
        issuer = name
        sign_key = self._private_key
        if self.parent_cert is not None:
            sign_key = parent_cert._private_key
            issuer = parent_cert._certificate.subject

        self._certificate = (
            _cert_builder_common(name, issuer, self._private_key.public_key())
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CODE_SIGNING,
                ]),
                critical=True
            )
            .sign(
                private_key=sign_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
            )
        )

    @property
    def cert_pem(self):
        """`Blob`: The PEM-encoded certificate for this CA. Add this to your
        trust store to trust this CA."""
        return Blob(self._certificate.public_bytes(Encoding.PEM))

    @property
    def private_key_pem(self):
        """`Blob`: The PEM-encoded private key for this CA. Use this to sign
        other certificates from this CA."""
        return Blob(
            self._private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption()
                )
            )

    def create_child_ca(self):
        """Creates a child certificate authority

        Returns:
          CA: the newly-generated certificate authority

        Raises:
          ValueError: if the CA path length is 0
        """
        if self._path_length == 0:
            raise ValueError("Can't create child CA: path length is 0")

        path_length = self._path_length - 1
        return CA(parent_cert=self, path_length=path_length)

    def issue_cert(self, *identities, **kwargs):
        """issue_cert(*identities, common_name=None, organization_name=None, \
        organization_unit_name=None)

        Issues a certificate. The certificate can be used for either servers
        or clients.

        All arguments must be text strings (``unicode`` on Python 2, ``str``
        on Python 3).

        Args:
          identities: The identities that this certificate will be valid for.
            Most commonly, these are just hostnames, but we accept any of the
            following forms:

            - Regular hostname: ``example.com``
            - Wildcard hostname: ``*.example.com``
            - International Domain Name (IDN): ``café.example.com``
            - IDN in A-label form: ``xn--caf-dma.example.com``
            - IPv4 address: ``127.0.0.1``
            - IPv6 address: ``::1``
            - IPv4 network: ``10.0.0.0/8``
            - IPv6 network: ``2001::/16``
            - Email address: ``example@example.com``

            These ultimately end up as "Subject Alternative Names", which are
            what modern programs are supposed to use when checking identity.

          common_name: Sets the "Common Name" of the certificate. This is a
            legacy field that used to be used to check identity. It's an
            arbitrary string with poorly-defined semantics, so `modern
            programs are supposed to ignore it
            <https://developers.google.com/web/updates/2017/03/chrome-58-deprecations#remove_support_for_commonname_matching_in_certificates>`__.
            But it might be useful if you need to test how your software
            handles legacy or buggy certificates.

          organization_name: Sets the "Organization Name" (O) attribute on the
            certificate. By default, it will be "trustme" suffixed with a
            version number.

          organization_unit_name: Sets the "Organization Unit Name" (OU)
            attribute on the certificate. By default, a random one will be
            generated.

          not_after: Sets when the certificate will expire (Not After) in
            datetime format. If set to None, the certificate's expiry will
            default to Jan 1, 2038

        Returns:
          LeafCert: the newly-generated certificate.

        """
        common_name = kwargs.pop("common_name", None)
        organization_name = kwargs.pop("organization_name", None)
        organization_unit_name = kwargs.pop("organization_unit_name", None)
        not_after = kwargs.pop("not_after", None)
        if kwargs:
            raise TypeError("unrecognized keyword arguments {}".format(kwargs))

        if not identities and common_name is None:
            raise ValueError(
                "Must specify at least one identity or common name"
            )

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_KEY_SIZE,
            backend=default_backend()
        )

        ski_ext = self._certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier)
        ski = ski_ext.value
        # Workaround a bug in cryptography 2.6 and earlier, where you have to
        # pass the extension object instead of the actual SKI object
        try:
            # The new way
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except AttributeError:
            # The old way
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext)

        cert = (
            _cert_builder_common(
                _name(
                    organization_unit_name or u"Testing cert #" + random_text(),
                    organization_name=organization_name,
                    common_name=common_name,
                ),
                self._certificate.subject,
                key.public_key(),
                not_after=not_after,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(aki, critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [_identity_string_to_x509(ident) for ident in identities]
                ),
                critical=True,
            )
            .sign(
                private_key=self._private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
            )
        )

        chain_to_ca = []
        ca = self
        while ca.parent_cert is not None:
            chain_to_ca.append(ca._certificate.public_bytes(Encoding.PEM))
            ca = ca.parent_cert

        return LeafCert(
                key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.TraditionalOpenSSL,
                    NoEncryption(),
                ),
                cert.public_bytes(Encoding.PEM),
                chain_to_ca,
            )

    # For backwards compatibility
    issue_server_cert = issue_cert

    def configure_trust(self, ctx):
        """Configure the given context object to trust certificates signed by
        this CA.

        Args:
          ctx (ssl.SSLContext or OpenSSL.SSL.Context): The SSL context to be
              modified.

        """
        if isinstance(ctx, ssl.SSLContext):
            ctx.load_verify_locations(
                cadata=self.cert_pem.bytes().decode("ascii"))
        elif _smells_like_pyopenssl(ctx):
            from OpenSSL import crypto
            cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, self.cert_pem.bytes())
            store = ctx.get_cert_store()
            store.add_cert(cert)
        else:
            raise TypeError(
                "unrecognized context type {!r}"
                .format(ctx.__class__.__name__))

    @classmethod
    def from_pem(cls, cert_bytes, private_key_bytes):
        """Build a CA from existing cert and private key.

        This is useful if your test suite has an existing certificate authority and
        you're not ready to switch completely to trustme just yet.

        Args:
          cert_bytes (bytes): The bytes of the certificate in PEM format
          private_key_bytes (bytes): The bytes of the private key in PEM format
        """
        ca = cls()
        ca.parent_cert = None
        ca._certificate = x509.load_pem_x509_certificate(
            cert_bytes, backend=default_backend())
        ca._private_key = load_pem_private_key(
            private_key_bytes, password=None, backend=default_backend())
        return ca


class LeafCert(object):
    """A server or client certificate.

    This type has no public constructor; you get one by calling
    `CA.issue_cert` or similar.

    Attributes:
      private_key_pem (`Blob`): The PEM-encoded private key corresponding to
          this certificate.

      cert_chain_pems (list of `Blob` objects): The zeroth entry in this list
          is the actual PEM-encoded certificate, and any entries after that
          are the rest of the certificate chain needed to reach the root CA.

      private_key_and_cert_chain_pem (`Blob`): A single `Blob` containing the
          concatenation of the PEM-encoded private key and the PEM-encoded
          cert chain.

    """
    def __init__(self, private_key_pem, server_cert_pem, chain_to_ca):
        self.private_key_pem = Blob(private_key_pem)
        self.cert_chain_pems = [
            Blob(pem) for pem in [server_cert_pem] + chain_to_ca]
        self.private_key_and_cert_chain_pem = (
            Blob(private_key_pem + server_cert_pem + b''.join(chain_to_ca)))

    def configure_cert(self, ctx):
        """Configure the given context object to present this certificate.

        Args:
          ctx (ssl.SSLContext or OpenSSL.SSL.Context): The SSL context to be
              modified.

        """
        if isinstance(ctx, ssl.SSLContext):
            # Currently need a temporary file for this, see:
            #   https://bugs.python.org/issue16487
            with self.private_key_and_cert_chain_pem.tempfile() as path:
                ctx.load_cert_chain(path)
        elif _smells_like_pyopenssl(ctx):
            from OpenSSL.crypto import (
                load_privatekey, load_certificate, FILETYPE_PEM,
            )
            key = load_privatekey(FILETYPE_PEM, self.private_key_pem.bytes())
            ctx.use_privatekey(key)
            cert = load_certificate(FILETYPE_PEM,
                                    self.cert_chain_pems[0].bytes())
            ctx.use_certificate(cert)
            for pem in self.cert_chain_pems[1:]:
                cert = load_certificate(FILETYPE_PEM, pem.bytes())
                ctx.add_extra_chain_cert(cert)
        else:
            raise TypeError(
                "unrecognized context type {!r}"
                .format(ctx.__class__.__name__))
