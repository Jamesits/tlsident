#!/usr/bin/env bash

set -euo pipefail

local_dir="${1:?usage: compare-sub2api.sh <local-results-dir> <upstream-json> <artifact-dir>}"
upstream_json="${2:?usage: compare-sub2api.sh <local-results-dir> <upstream-json> <artifact-dir>}"

mapfile -d '' -t local_files < <(find "$local_dir" -maxdepth 1 -type f -name '*.sub2api.json' -print0 | sort -z -V)
if [ "${#local_files[@]}" -eq 0 ]; then
  echo "no local .sub2api.json captures were produced" >&2
  exit 1
fi

local_count="${#local_files[@]}"
upstream_count="$(jq -r '.count // 0' "$upstream_json")"
if [ "$upstream_count" -lt "$local_count" ]; then
  echo "upstream reported $upstream_count fingerprints, but local run produced $local_count" >&2
  exit 1
fi

normalize_fingerprint='def normalize_fingerprint: {
  model,
  ja3_raw,
  ja3_hash,
  ja4,
  http2,
  user_agent,
  cipher_suites,
  curves,
  point_formats,
  extensions,
  signature_algorithms,
  alpn_protocols,
  supported_versions,
  key_share_groups,
  psk_modes,
  compress_cert_algos,
  enable_grease,
  stainless_os,
  stainless_arch,
  stainless_runtime,
  stainless_runtime_version,
  stainless_lang,
  stainless_package_version
}; normalize_fingerprint'

for i in "${!local_files[@]}"; do
  local_file="${local_files[$i]}"
  position=$((i + 1))

  local_normalized_json="$(jq '.fingerprints[0] | '"$normalize_fingerprint" "$local_file")"
  upstream_normalized_json="$(jq --argjson index "$i" '.fingerprints[$index] | '"$normalize_fingerprint" "$upstream_json")"

  if [ "$local_normalized_json" != "$upstream_normalized_json" ]; then
    echo "fingerprint mismatch at position $position: $local_file" >&2
    echo "local result:" >&2
    printf '%s\n' "$local_normalized_json" >&2
    echo "upstream result:" >&2
    printf '%s\n' "$upstream_normalized_json" >&2
    echo "diff:" >&2
    diff -u <(printf '%s\n' "$local_normalized_json") <(printf '%s\n' "$upstream_normalized_json") >&2 || true
    exit 1
  fi
done
