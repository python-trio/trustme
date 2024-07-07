import os
import subprocess
import sys
from pathlib import Path

import pytest

from trustme._cli import main


def test_trustme_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    main(argv=[])

    assert tmp_path.joinpath("server.key").exists()
    assert tmp_path.joinpath("server.pem").exists()
    assert tmp_path.joinpath("client.pem").exists()


def test_trustme_cli_e2e(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    rv = subprocess.call([sys.executable, "-m", "trustme"])
    assert rv == 0

    assert tmp_path.joinpath("server.key").exists()
    assert tmp_path.joinpath("server.pem").exists()
    assert tmp_path.joinpath("client.pem").exists()


def test_trustme_cli_directory(tmp_path: Path) -> None:
    subdir = tmp_path.joinpath("sub")
    subdir.mkdir()
    main(argv=["-d", str(subdir)])

    assert subdir.joinpath("server.key").exists()
    assert subdir.joinpath("server.pem").exists()
    assert subdir.joinpath("client.pem").exists()


def test_trustme_cli_directory_does_not_exist(tmp_path: Path) -> None:
    notdir = tmp_path.joinpath("notdir")
    with pytest.raises(ValueError, match="is not a directory"):
        main(argv=["-d", str(notdir)])


def test_trustme_cli_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    main(argv=["-i", "example.org", "www.example.org"])

    assert tmp_path.joinpath("server.key").exists()
    assert tmp_path.joinpath("server.pem").exists()
    assert tmp_path.joinpath("client.pem").exists()


def test_trustme_cli_identities_empty(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one identity"):
        main(argv=["-i"])


def test_trustme_cli_common_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    main(argv=["--common-name", "localhost"])

    assert tmp_path.joinpath("server.key").exists()
    assert tmp_path.joinpath("server.pem").exists()
    assert tmp_path.joinpath("client.pem").exists()


def test_trustme_cli_expires_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    main(argv=["--expires-on", "2035-03-01"])

    assert tmp_path.joinpath("server.key").exists()
    assert tmp_path.joinpath("server.pem").exists()
    assert tmp_path.joinpath("client.pem").exists()


def test_trustme_cli_invalid_expires_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="does not match format"):
        main(argv=["--expires-on", "foobar"])

    assert not tmp_path.joinpath("server.key").exists()
    assert not tmp_path.joinpath("server.pem").exists()
    assert not tmp_path.joinpath("client.pem").exists()


def test_trustme_cli_quiet(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    main(argv=["-q"])

    assert tmp_path.joinpath("server.key").exists()
    assert tmp_path.joinpath("server.pem").exists()
    assert tmp_path.joinpath("client.pem").exists()

    captured = capsys.readouterr()
    assert not captured.out
