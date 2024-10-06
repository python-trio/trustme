#!/bin/bash

set -exu -o pipefail

python -c "import sys, struct, ssl; print('#' * 70); print('python:', sys.version); print('version_info:', sys.version_info); print('bits:', struct.calcsize('P') * 8); print('openssl:', ssl.OPENSSL_VERSION, ssl.OPENSSL_VERSION_INFO); print('#' * 70)"

python -m pip install -U pip
python -m pip --version

# Dependencies

python -m pip install -Ur lint-requirements.txt

# Linting
black --check src/trustme tests
isort --profile black src/trustme tests
mypy src/trustme tests
