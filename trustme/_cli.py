import argparse
import pathlib
import trustme
import typing
import sys


def main(argv: typing.Sequence[str] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(prog="trustme")
    parser.add_argument(
        "-d",
        "--dir",
        default=pathlib.Path.cwd(),
        help="Directory where certificates and keys are written to. Defaults to cwd.",
    )
    parser.add_argument(
        "-i",
        "--identities",
        nargs="*",
        default=("localhost", "127.0.0.1", "::1"),
        help="Identities for the certificate. Defaults to 'localhost 127.0.0.1 ::1'.",
    )
    parser.add_argument(
        "--common-name",
        nargs=1,
        default=None,
        help="Also sets the deprecated 'commonName' field for all relevant identities.",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        help="Key size of the certificate generated. Defaults to 2048.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Doesn't print out helpful information for humans.",
    )

    args = parser.parse_args(argv)
    cert_dir = pathlib.Path(args.dir)
    identities = args.identities
    common_name = args.common_name[0] if args.common_name else None
    key_size = args.key_size
    quiet = args.quiet

    if not cert_dir.is_dir():
        raise ValueError(f"--dir={cert_dir} is not a directory")
    if len(identities) < 1:
        raise ValueError("Must include at least one identity")

    # Generate the CA certificate
    trustme._KEY_SIZE = key_size
    ca = trustme.CA()
    cert = ca.issue_cert(*identities, common_name=common_name)

    # Write the certificate and private key the server should use
    server_key = cert_dir / "server.key"
    server_cert = cert_dir / "server.pem"
    cert.private_key_pem.write_to_path(path=str(server_key))
    with server_cert.open(mode="w") as f:
        f.truncate()
    for blob in cert.cert_chain_pems:
        blob.write_to_path(path=str(server_cert), append=True)

    # Write the certificate the client should trust
    client_cert = cert_dir / "client.pem"
    ca.cert_pem.write_to_path(path=str(client_cert))

    if not quiet:
        idents = "', '".join(identities)
        print(f"Generated a certificate for '{idents}'")
        print("Configure your server to use the following files:")
        print(f"  cert={server_cert}")
        print(f"  key={server_key}")
        print("Configure your client to use the following files:")
        print(f"  cert={client_cert}")
