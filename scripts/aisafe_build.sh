#!/usr/bin/env bash
# Build the image for the DefCamp 2026 Agentic CTF (AISafe platform) and save
# the file to upload. The upload limit is 1 GiB, plain or gzipped; only the
# core tier fits.
#
#   scripts/aisafe_build.sh                      -> ~/my-harness.tar.gz (core tier)
#   BASE=ctf-harness:base-apk scripts/aisafe_build.sh my-harness-apk
#
# The image is tagged with the name given (default my-harness), which is the
# name the kit's compose.yaml uses, so the kit can test it without rebuilding:
#
#   cd <aisafe-starter-kit> && docker compose up --no-build --exit-code-from harness
#   docker compose down -v
#
# Expect `gateway-1 | flag ACCEPTED: flag{0123...}` there before uploading.
set -euo pipefail

name="${1:-my-harness}"
base="${BASE:-ctf-harness:base-core}"
out="${OUT:-$HOME}/$name.tar.gz"
cd "$(dirname "$0")/.."

if ! ls knowledge/ctf-notes/*.md >/dev/null 2>&1; then
  echo "warning: knowledge/ctf-notes is empty: the image will have no notes." >&2
  echo "         python scripts/sync_knowledge.py ../ctf-notes --ref harness" >&2
fi

docker build --platform linux/amd64 -f Dockerfile.contest --build-arg BASE="$base" -t "$name" .

echo "--- image check (critical failures stop the build) ---"
docker run --rm "$name" python scripts/check_image.py | grep -E 'FAIL|miss\]|passed;|image tier' || true
docker run --rm "$name" python scripts/check_image.py >/dev/null

echo "--- saving to $out ---"
if command -v pigz >/dev/null; then
  docker save "$name" | pigz -9 > "$out"
else
  docker save "$name" | gzip -9 > "$out"
fi
size=$(wc -c < "$out" | tr -d ' ')
echo "wrote $out ($((size / 1048576)) MiB of 1024)"
if [ "$size" -gt 1073741824 ]; then
  echo "ERROR: over the 1 GiB upload limit." >&2
  exit 1
fi
echo "Next: test it with the kit's compose (see the top of this script), then upload."
