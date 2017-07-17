#!/bin/bash

set -exu -o pipefail

pip install -U pip setuptools wheel

python setup.py sdist --formats=zip
pip install dist/*.zip

pip install -Ur test-requirements.txt
mkdir empty
pushd empty
INSTALLDIR=$(python -c "import os, faketlscerts; print(os.path.dirname(faketlscerts))")
pytest ../tests --cov="$INSTALLDIR" --cov=../tests --cov-config="../.coveragerc"

pip install codecov
codecov
