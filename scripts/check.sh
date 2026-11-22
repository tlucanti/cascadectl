#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$PROJECT_DIR"
export PYTHONDONTWRITEBYTECODE=1
bash -n bootstrap.sh scripts/check.sh
python3 -m unittest discover -s tests -v
python3 - <<'PY'
from pathlib import Path
import ast
for p in [Path('bootstrap.py'), Path('bin/cascadectl'), *Path('lib').glob('*.py')]:
    ast.parse(p.read_text(), filename=str(p))
print('Python syntax verified')
PY
python3 scripts/check_units.py
./bootstrap.sh --config examples/cascade.example.json --plan > /dev/null
./bin/cascadectl --help > /dev/null
