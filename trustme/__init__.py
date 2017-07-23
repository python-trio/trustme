import datetime
import ssl
import tempfile
from base64 import urlsafe_b64encode
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    PrivateFormat, NoEncryption
)
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding

from ._version import __version__

__all__ = ["CA"]

# On my laptop, making a CA + server certificate using 1024 bit keys takes ~40
# ms, and using 4096 bit keys takes ~2 seconds. We want tests to run in 40 ms,
# not 2 seconds.
_KEY_SIZE = 1024

def _name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           u"trustme v{}".format(__version__)),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def random_text():
    return urlsafe_b64encode(os.urandom(12)).decode("ascii")


def _cert_builder_common(subject, issuer, public_key):
    today = datetime.datetime.today()
    yesterday = today - datetime.timedelta(1, 0, 0)
    forever = today.replace(year=today.year + 1000)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        # This is inclusive so today should work too, but let's pad it a
        # bit.
        .not_valid_before(yesterday)
        .not_valid_after(forever)
        .serial_number(x509.random_serial_number())
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )


class CA(object):
    def __init__(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_KEY_SIZE,
            backend=default_backend()
        )

        name = _name(u"Testing CA #" + random_text())
        self._certificate = (
            _cert_builder_common(name, name, self._private_key.public_key())
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=9), critical=True,
            )
            .sign(
                private_key=self._private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
            )
        )

        self.cert_pem = self._certificate.public_bytes(Encoding.PEM)

    def issue_server_cert(self, *hostnames):
        if not hostnames:
            raise ValueError("Must specify at least one hostname")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_KEY_SIZE,
            backend=default_backend()
        )

        ski = self._certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier)

        cert = (
            _cert_builder_common(
                _name(u"Testing server cert #" + random_text()),
                self._certificate.subject,
                key.public_key(),
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ski),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(h) for h in hostnames]
                ),
                critical=True,
            )
            .sign(
                private_key=self._private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
            )
        )
        return ServerCert(
                key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.TraditionalOpenSSL,
                    NoEncryption(),
                ),
                cert.public_bytes(Encoding.PEM),
            )
        
    def stdlib_client_context(self, **kwargs):
        kwargs.setdefault("cadata", "")
        kwargs["cadata"] += "\n" + self.cert_pem.decode("ascii")
        return ssl.create_default_context(**kwargs)


class ServerCert(object):
    def __init__(self, private_key_pem, server_cert_pem):
        self.private_key_pem = private_key_pem
        self.cert_chain_pem = server_cert_pem
        self.private_key_and_cert_chain_pem = private_key_pem + self.cert_chain_pem

    def stdlib_server_context(self, **kwargs):
        # Currently need a temporary file for this, see:
        #   https://bugs.python.org/issue16487
        with tempfile.NamedTemporaryFile() as f:
            f.write(self.private_key_and_cert_chain_pem)
            f.flush()
            # XX should this be configured to trust the CA as well?
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, **kwargs)
            ctx.load_cert_chain(f.name)
            return ctx
