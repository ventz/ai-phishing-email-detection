#!/usr/bin/env bash
# Build the Lambda package into build/lambda (Terraform zips it). Linux arm64 (manylinux_2_28;
# the python3.13 runtime is Amazon Linux 2023, glibc 2.34), Python 3.13.
set -euo pipefail
cd "$(dirname "$0")/.."

out=build/lambda
command rm -rf "$out"
mkdir -p "$out"

# Exact versions + hashes from uv.lock; any tampered or unexpected wheel fails the build.
uv export --locked --no-dev --no-emit-project -o build/requirements.txt >/dev/null
uv pip install --quiet --target "$out" --requirement build/requirements.txt --require-hashes \
  --python-platform aarch64-manylinux_2_28 --python-version 3.13 --only-binary :all:

cp -R src/phishing_detector "$out/"
cp lambda_function.py "$out/"
find "$out" -name '__pycache__' -type d -prune -exec rm -rf {} +
# boto3/botocore ship with the Lambda runtime but are pinned here for reproducibility; keep them.
du -sh "$out" | awk '{print "built " $2 " (" $1 ")"}'
