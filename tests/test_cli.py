# -*- coding: utf-8 -*-

import subprocess
import sys

import pytest

from trustme._cli import main


def test_trustme_cli(tmpdir):
    with tmpdir.as_cwd():
        main(argv=[])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_e2e(tmpdir):
    with tmpdir.as_cwd():
        rv = subprocess.call([sys.executable, "-m", "trustme"])
        assert rv == 0

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_directory(tmpdir):
    subdir = tmpdir.mkdir("sub")
    main(argv=["-d", str(subdir)])

    assert subdir.join("server.key").check(exists=1)
    assert subdir.join("server.pem").check(exists=1)
    assert subdir.join("client.pem").check(exists=1)


def test_trustme_cli_directory_does_not_exist(tmpdir):
    notdir = tmpdir.join("notdir")
    with pytest.raises(ValueError, match="is not a directory"):
        main(argv=["-d", str(notdir)])


def test_trustme_cli_identities(tmpdir):
    with tmpdir.as_cwd():
        main(argv=["-i", "example.org", "www.example.org"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_identities_empty(tmpdir):
    with pytest.raises(ValueError, match="at least one identity"):
        main(argv=["-i"])


def test_trustme_cli_common_name(tmpdir):
    with tmpdir.as_cwd():
        main(argv=["--common-name", "localhost"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)


def test_trustme_cli_quiet(capsys, tmpdir):
    with tmpdir.as_cwd():
        main(argv=["-q"])

    assert tmpdir.join("server.key").check(exists=1)
    assert tmpdir.join("server.pem").check(exists=1)
    assert tmpdir.join("client.pem").check(exists=1)

    captured = capsys.readouterr()
    assert not captured.out
