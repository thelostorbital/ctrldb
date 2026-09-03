#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_dir="$repo_root/internal/architecture_rule_fixture"
fixture_file="$fixture_dir/violations.go"
allowed_fixture="$repo_root/rules/ast-grep/testdata/allowed.go.txt"
violation_fixture="$repo_root/rules/ast-grep/testdata/violations.go.txt"
qlty_bin="${QLTY_BIN:-qlty}"

cleanup() {
  rm -f "$fixture_file"
  rmdir "$fixture_dir" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -e $fixture_file ]]; then
  echo "refusing to overwrite existing architecture rule fixture" >&2
  exit 1
fi

mkdir -p "$fixture_dir"
cp "$allowed_fixture" "$fixture_file"

if ! QLTY_TELEMETRY=off "$qlty_bin" check \
  --no-fix \
  --no-cache \
  --filter=ast-grep \
  --level=low \
  --fail-level=low \
  "$fixture_file"; then
  echo "architecture rules rejected safe non-import string literals" >&2
  exit 1
fi

cp "$violation_fixture" "$fixture_file"

set +e
output=$(
  QLTY_TELEMETRY=off "$qlty_bin" check \
    --no-fix \
    --no-cache \
    --filter=ast-grep \
    --level=low \
    --fail-level=low \
    "$fixture_file" 2>&1
)
exit_code=$?
set -e

printf '%s\n' "$output"

if [[ $exit_code -eq 0 ]]; then
  echo "architecture rules accepted the violation fixture" >&2
  exit 1
fi

expected_rules=(
  bubble-tea-import-boundary
  no-production-test-imports
  no-raw-process-apis
  no-shell-launchers
  os-exec-import-boundary
)

for rule_id in "${expected_rules[@]}"; do
  if ! grep -Fq "$rule_id" <<<"$output"; then
    echo "architecture rule did not report: $rule_id" >&2
    exit 1
  fi
done

echo "all architecture rules rejected their fixture violations"
