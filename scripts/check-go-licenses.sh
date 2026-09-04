#!/usr/bin/env bash

# Copyright 2026 CtrlBoard.dev
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
go_licenses_bin="${GO_LICENSES_BIN:-go-licenses}"
report=$(mktemp "${TMPDIR:-/tmp}/ctrldb-go-licenses.XXXXXX")

cleanup() {
  rm -f "$report"
}
trap cleanup EXIT

check_report() {
  local report_file=$1
  local package_name license_name remainder
  local rows=0

  while IFS=, read -r package_name _ license_name remainder; do
    [[ -z $package_name && -z $license_name ]] && continue
    rows=$((rows + 1))
    license_name=${license_name%$'\r'}
    if [[ -n $remainder ]]; then
      echo "malformed go-licenses CSV row for $package_name" >&2
      return 1
    fi
    case "$license_name" in
      Apache-2.0 | MIT | BSD-* | ISC | MPL-2.0)
        ;;
      "" | Unknown)
        echo "dependency $package_name has an unknown license" >&2
        return 1
        ;;
      *)
        echo "dependency $package_name has disallowed license $license_name" >&2
        return 1
        ;;
    esac
  done < "$report_file"

  if [[ $rows -eq 0 ]]; then
    echo "go-licenses produced an empty report" >&2
    return 1
  fi
}

assert_rejected() {
  local fixture=$1
  local expected=$2
  local output exit_code

  set +e
  output=$(check_report "$fixture" 2>&1)
  exit_code=$?
  set -e

  if [[ $exit_code -eq 0 ]]; then
    echo "license policy accepted forbidden fixture: $fixture" >&2
    return 1
  fi
  if [[ $output != *"$expected"* ]]; then
    printf '%s\n' "$output" >&2
    echo "license policy did not identify $expected in $fixture" >&2
    return 1
  fi
}

cd "$repo_root"
"$go_licenses_bin" report --include_tests ./... > "$report"
check_report "$report"

fixture_root="$repo_root/test/license-fixtures"
check_report "$fixture_root/allowed.csv"
assert_rejected "$fixture_root/gpl.csv" "GPL-3.0-only"
assert_rejected "$fixture_root/agpl.csv" "AGPL-3.0-only"
assert_rejected "$fixture_root/unknown.csv" "unknown license"

echo "Go dependency licenses satisfy the D-084 allowlist; rejection fixtures passed"
