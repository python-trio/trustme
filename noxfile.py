import os

import nox


@nox.session()
def lint(session: nox.Session) -> None:
    session.install("-r", "lint-requirements.txt")
    LINT_PATHS = ("src/trustme", "tests", "noxfile.py")
    session.run("black", *LINT_PATHS)
    session.run("isort", "--profile", "black", *LINT_PATHS)
    session.run("mypy", *LINT_PATHS)


@nox.session(python=["3.10", "3.11", "3.12", "3.13", "3.14", "3.14t", "3.15", "pypy3"])
def test(session: nox.Session) -> None:
    session.install(".", "-r", "test-requirements.txt")
    session.run(
        "coverage",
        "run",
        "--parallel-mode",
        "-m",
        "pytest",
        "-W",
        "error",
        "-ra",
        "-s",
        *(session.posargs or ("tests/",)),
    )
    if os.environ.get("CI") != "true":
        session.run("coverage", "combine")
        session.run("coverage", "report", "-m")
