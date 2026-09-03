#!/usr/bin/env bash

# Copyright 2026 CtrlBoard.dev
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_source_dir="$repo_root/rules/ast-grep/testdata"
architecture_fixture_dir="$repo_root/internal/architecture_rule_fixture"
architecture_fixture="$architecture_fixture_dir/fixture.go"
adapter_fixture_dir="$repo_root/internal/gcp"
adapter_fixture="$adapter_fixture_dir/architecture_rule_fixture.go"
test_helper_fixture_dir="$architecture_fixture_dir/testutil"
test_helper_fixture="$test_helper_fixture_dir/fixture.go"
root_fixture="$repo_root/architecture_rule_fixture.go"
qlty_bin="${QLTY_BIN:-qlty}"
architecture_fixture_dir_created=false
adapter_fixture_dir_created=false
test_helper_fixture_dir_created=false

cleanup() {
  rm -f "$architecture_fixture" "$adapter_fixture" "$test_helper_fixture" "$root_fixture"
  if [[ $test_helper_fixture_dir_created == true ]]; then
    rmdir "$test_helper_fixture_dir" 2>/dev/null || true
  fi
  if [[ $architecture_fixture_dir_created == true ]]; then
    rmdir "$architecture_fixture_dir" 2>/dev/null || true
  fi
  if [[ $adapter_fixture_dir_created == true ]]; then
    rmdir "$adapter_fixture_dir" 2>/dev/null || true
  fi
}

run_qlty() {
  QLTY_TELEMETRY=off "$qlty_bin" check \
    --no-fix \
    --no-cache \
    --filter=ast-grep \
    --level=low \
    --fail-level=low \
    "$1"
}

assert_accepted() {
  local source_file=$1
  local target_file=$2

  cp "$source_file" "$target_file"
  if ! run_qlty "$target_file"; then
    echo "architecture rules rejected safe fixture: $source_file" >&2
    exit 1
  fi
  rm -f "$target_file"
}

assert_rejected() {
  local source_file=$1
  local target_file=$2
  local expected_rule=$3

  cp "$source_file" "$target_file"

  set +e
  output=$(run_qlty "$target_file" 2>&1)
  exit_code=$?
  set -e

  rm -f "$target_file"

  if [[ $exit_code -eq 0 ]]; then
    echo "architecture rules accepted forbidden fixture: $source_file" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_rule" <<<"$output"; then
    printf '%s\n' "$output" >&2
    echo "architecture rule did not report $expected_rule for $source_file" >&2
    exit 1
  fi

  echo "verified $expected_rule rejects $(basename "$source_file")"
}

for target_file in "$architecture_fixture" "$adapter_fixture" "$test_helper_fixture" "$root_fixture"; do
  if [[ -e $target_file ]]; then
    echo "refusing to overwrite existing architecture rule fixture: $target_file" >&2
    exit 1
  fi
done

trap cleanup EXIT

if [[ ! -d $architecture_fixture_dir ]]; then
  mkdir "$architecture_fixture_dir"
  architecture_fixture_dir_created=true
fi
if [[ ! -d $adapter_fixture_dir ]]; then
  mkdir "$adapter_fixture_dir"
  adapter_fixture_dir_created=true
fi
if [[ ! -d $test_helper_fixture_dir ]]; then
  mkdir "$test_helper_fixture_dir"
  test_helper_fixture_dir_created=true
fi

assert_accepted "$fixture_source_dir/allowed.go.txt" "$architecture_fixture"
assert_accepted "$fixture_source_dir/unrelated-start-process.go.txt" "$architecture_fixture"
assert_accepted "$fixture_source_dir/test-infrastructure-import.go.txt" "$test_helper_fixture"

assert_rejected "$fixture_source_dir/bubble-tea-import.go.txt" "$architecture_fixture" bubble-tea-import-boundary
assert_rejected "$fixture_source_dir/raw-bubble-tea-import.go.txt" "$architecture_fixture" bubble-tea-import-boundary
assert_rejected "$fixture_source_dir/legacy-bubble-tea-import.go.txt" "$architecture_fixture" bubble-tea-import-boundary
assert_rejected "$fixture_source_dir/test-infrastructure-import.go.txt" "$architecture_fixture" no-production-test-imports
assert_rejected "$fixture_source_dir/raw-test-infrastructure-import.go.txt" "$architecture_fixture" no-production-test-imports
assert_rejected "$fixture_source_dir/os-exec-import.go.txt" "$architecture_fixture" os-exec-import-boundary
assert_rejected "$fixture_source_dir/raw-os-exec-import.go.txt" "$architecture_fixture" os-exec-import-boundary
assert_rejected "$fixture_source_dir/os-exec-import.go.txt" "$root_fixture" os-exec-import-boundary
assert_rejected "$fixture_source_dir/os-exec-import.go.txt" "$adapter_fixture" os-exec-import-boundary
assert_rejected "$fixture_source_dir/escaped-os-exec-import.go.txt" "$architecture_fixture" no-escaped-import-paths
assert_rejected "$fixture_source_dir/os-start-process.go.txt" "$architecture_fixture" no-os-start-process
assert_rejected "$fixture_source_dir/indirect-os-start-process.go.txt" "$architecture_fixture" no-os-start-process
assert_rejected "$fixture_source_dir/aliased-os-start-process.go.txt" "$architecture_fixture" no-os-start-process
assert_rejected "$fixture_source_dir/indirect-aliased-os-start-process.go.txt" "$architecture_fixture" no-os-start-process
assert_rejected "$fixture_source_dir/raw-aliased-os-start-process.go.txt" "$architecture_fixture" no-os-start-process
assert_rejected "$fixture_source_dir/indirect-raw-aliased-os-start-process.go.txt" "$architecture_fixture" no-os-start-process
assert_rejected "$fixture_source_dir/aliased-syscall-import.go.txt" "$architecture_fixture" no-low-level-process-imports
assert_rejected "$fixture_source_dir/raw-aliased-syscall-import.go.txt" "$architecture_fixture" no-low-level-process-imports
assert_rejected "$fixture_source_dir/aliased-unix-import.go.txt" "$architecture_fixture" no-low-level-process-imports
assert_rejected "$fixture_source_dir/aliased-windows-import.go.txt" "$architecture_fixture" no-low-level-process-imports
assert_rejected "$fixture_source_dir/execabs-import.go.txt" "$architecture_fixture" no-low-level-process-imports
assert_rejected "$fixture_source_dir/raw-execabs-import.go.txt" "$architecture_fixture" no-low-level-process-imports

echo "all architecture rule acceptance and rejection cases passed"
