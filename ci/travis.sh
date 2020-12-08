#!/bin/bash

set -exu -o pipefail

pip install -U pip setuptools wheel

python setup.py sdist --formats=zip
pip install dist/*.zip

# Actual tests

pip install -Ur test-requirements.txt
if [ -n "${OLD_CRYPTOGRAPHY:-}" ]; then
    pip install cryptography=="${OLD_CRYPTOGRAPHY}"
fi
mkdir empty
pushd empty
INSTALLDIR=$(python -c "import os, trustme; print(os.path.dirname(trustme.__file__))")
pytest -W error -ra -s ../tests --cov="$INSTALLDIR" --cov=../tests --cov-config="../.coveragerc"

pip install codecov
codecov -F $(uname | tr A-Z a-z)
