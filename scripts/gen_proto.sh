#!/usr/bin/env bash
# Regenerates the Python protobuf stubs under src/sigsig/_proto/.
# Run from the repo root after changing anything in proto/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/src/sigsig/_proto"

mkdir -p "$OUT"
touch "$OUT/__init__.py"

python -m grpc_tools.protoc \
    --proto_path="$ROOT/proto" \
    --python_out="$OUT" \
    "$ROOT"/proto/*.proto

# Rewrite absolute imports so the generated stubs live inside sigsig._proto.
for f in "$OUT"/*_pb2.py; do
    python - "$f" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1])
s = p.read_text()
s = re.sub(r'^import (\w+_pb2) as', r'from . import \1 as', s, flags=re.M)
p.write_text(s)
PY
done

echo "Generated stubs in $OUT"
