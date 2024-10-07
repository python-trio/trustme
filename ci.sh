#!/bin/bash

set -exu -o pipefail

python -c "import sys, struct, ssl; print('#' * 70); print('python:', sys.version); print('version_info:', sys.version_info); print('bits:', struct.calcsize('P') * 8); print('openssl:', ssl.OPENSSL_VERSION, ssl.OPENSSL_VERSION_INFO); print('#' * 70)"

python -m pip install -U pip build
python -m pip --version

python -m build --sdist
python -m pip install dist/*.tar.gz

# Actual tests

python -m pip install -Ur test-requirements.txt
if [ -n "${OLD_CRYPTOGRAPHY:-}" ]; then
  python -m pip install cryptography=="${OLD_CRYPTOGRAPHY}"
fi

coverage run --parallel-mode -m pytest -W error -ra -s tests
