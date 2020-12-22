import pathlib

import pytest

from trustme._cli import main


def test_trustme_cli(tmpdir):
    with tmpdir.as_cwd():
        main(argv=[])

    assert (pathlib.Path(tmpdir) / "server.key").exists()
    assert (pathlib.Path(tmpdir) / "server.pem").exists()
    assert (pathlib.Path(tmpdir) / "client.pem").exists()


def test_trustme_cli_directory(tmpdir):
    subdir = tmpdir.mkdir("sub")
    main(argv=["-d", str(subdir)])

    assert (pathlib.Path(subdir) / "server.key").exists()
    assert (pathlib.Path(subdir) / "server.pem").exists()
    assert (pathlib.Path(subdir) / "client.pem").exists()


def test_trustme_cli_directory_does_not_exist(tmpdir):
    notdir = pathlib.Path(str(tmpdir), "notdir")
    with pytest.raises(ValueError, match="is not a directory"):
        main(argv=["-d", str(notdir)])


def test_trustme_cli_identities(tmpdir):
    with tmpdir.as_cwd():
        main(argv=["-i", "example.org", "www.example.org"])

    assert (pathlib.Path(tmpdir) / "server.key").exists()
    assert (pathlib.Path(tmpdir) / "server.pem").exists()
    assert (pathlib.Path(tmpdir) / "client.pem").exists()


def test_trustme_cli_identities_empty(tmpdir):
    with pytest.raises(ValueError, match="at least one identity"):
        main(argv=["-i"])


def test_trustme_cli_common_name(tmpdir):
    with tmpdir.as_cwd():
        main(argv=["--common-name", "localhost"])

    assert (pathlib.Path(tmpdir) / "server.key").exists()
    assert (pathlib.Path(tmpdir) / "server.pem").exists()
    assert (pathlib.Path(tmpdir) / "client.pem").exists()


def test_trustme_cli_key_size(tmpdir):
    with tmpdir.as_cwd():
        main(argv=["--key-size", "1024"])

    assert (pathlib.Path(tmpdir) / "server.key").exists()
    assert (pathlib.Path(tmpdir) / "server.pem").exists()
    assert (pathlib.Path(tmpdir) / "client.pem").exists()


def test_trustme_cli_quiet(capsys, tmpdir):
    with tmpdir.as_cwd():
        main(argv=["-q"])

    assert (pathlib.Path(tmpdir) / "server.key").exists()
    assert (pathlib.Path(tmpdir) / "server.pem").exists()
    assert (pathlib.Path(tmpdir) / "client.pem").exists()

    captured = capsys.readouterr()
    assert not captured.out
