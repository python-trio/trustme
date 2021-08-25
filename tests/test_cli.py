import subprocess
import sys

import py
import pytest

from trustme._cli import main


def test_trustme_cli(tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        main(argv=[])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_e2e(tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        rv = subprocess.call([sys.executable, "-m", "trustme"])
        assert rv == 0

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_directory(tmpdir: py.path.local) -> None:
    subdir = tmpdir.mkdir("sub")
    main(argv=["-d", str(subdir)])

    assert subdir.join("server.key").check(exists=1)
    assert subdir.join("server.pem").check(exists=1)
    assert subdir.join("client.pem").check(exists=1)


def test_trustme_cli_directory_does_not_exist(tmpdir: py.path.local) -> None:
    notdir = tmpdir.join("notdir")
    with pytest.raises(ValueError, match="is not a directory"):
        main(argv=["-d", str(notdir)])


def test_trustme_cli_identities(tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        main(argv=["-i", "example.org", "www.example.org"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_identities_empty(tmpdir: py.path.local) -> None:
    with pytest.raises(ValueError, match="at least one identity"):
        main(argv=["-i"])


def test_trustme_cli_common_name(tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        main(argv=["--common-name", "localhost"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_expires_on(tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        main(argv=["--expires-on", "2035-03-01"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_invalid_expires_on(tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        with pytest.raises(ValueError, match="does not match format"):
            main(argv=["--expires-on", "foobar"])

    assert tmpdir.join("server.key").check(exists=0)
    assert tmpdir.join("server.pem").check(exists=0)
    assert tmpdir.join("client.pem").check(exists=0)


def test_trustme_cli_quiet(capsys: pytest.CaptureFixture[str], tmpdir: py.path.local) -> None:
    with tmpdir.as_cwd():
        main(argv=["-q"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)

    captured = capsys.readouterr()
    assert not captured.out
