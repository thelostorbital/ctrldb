#!/usr/bin/env bash

# Copyright 2026 CtrlBoard.dev
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
go_licenses_bin="${GO_LICENSES_BIN:-go-licenses}"
combined_report=$(mktemp "${TMPDIR:-/tmp}/ctrldb-go-licenses-combined.XXXXXX")
temporary_reports=()
license_targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

cleanup() {
  rm -f "$combined_report" "${temporary_reports[@]}"
}
trap cleanup EXIT

check_report() {
  local report_file=$1
  local line package_name license_file license_name comma_markers
  local rows=0

  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -z $line ]] && continue
    rows=$((rows + 1))
    comma_markers=${line//[^,]/}
    if [[ $comma_markers != ",," ]]; then
      echo "malformed go-licenses CSV row" >&2
      return 1
    fi
    IFS=, read -r package_name license_file license_name <<< "$line"
    if [[ -z $package_name || -z $license_file || -z $license_name ]]; then
      echo "malformed go-licenses CSV row" >&2
      return 1
    fi
    case "$license_name" in
      Apache-2.0 | MIT | BSD-2-Clause | BSD-3-Clause | ISC | MPL-2.0)
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

append_report() {
  local source=$1
  local line

  while IFS= read -r line || [[ -n $line ]]; do
    printf '%s\n' "$line" >> "$combined_report"
  done < "$source"
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
for target in "${license_targets[@]}"; do
  IFS=/ read -r goos goarch <<< "$target"
  target_report=$(mktemp "${TMPDIR:-/tmp}/ctrldb-go-licenses-${goos}-${goarch}.XXXXXX")
  temporary_reports+=("$target_report")
  if ! env GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 GOWORK=off \
    "$go_licenses_bin" report --include_tests ./... > "$target_report"; then
    echo "go-licenses failed for $target" >&2
    exit 1
  fi
  if [[ ! -s $target_report ]]; then
    echo "go-licenses produced an empty report for $target" >&2
    exit 1
  fi
  check_report "$target_report"
  append_report "$target_report"
done
check_report "$combined_report"

fixture_root="$repo_root/test/license-fixtures"
check_report "$fixture_root/allowed.csv"
assert_rejected "$fixture_root/gpl.csv" "GPL-3.0-only"
assert_rejected "$fixture_root/agpl.csv" "AGPL-3.0-only"
assert_rejected "$fixture_root/unknown.csv" "unknown license"
assert_rejected "$fixture_root/future-bsd.csv" "BSD-4-Clause"
assert_rejected "$fixture_root/malformed.csv" "malformed"

: > "$combined_report"
for target in "${license_targets[@]}"; do
  append_report "$fixture_root/targets/${target//\//-}.csv"
done
assert_rejected "$combined_report" "GPL-3.0-only"

echo "Go dependency licenses satisfy the D-084 allowlist for linux/darwin amd64/arm64; rejection fixtures passed"
