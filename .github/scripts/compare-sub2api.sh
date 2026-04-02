#!/usr/bin/env bash

set -euo pipefail

local_dir="${1:?usage: compare-sub2api.sh <local-results-dir> <upstream-json> <artifact-dir>}"
upstream_json="${2:?usage: compare-sub2api.sh <local-results-dir> <upstream-json> <artifact-dir>}"
artifact_dir="${3:?usage: compare-sub2api.sh <local-results-dir> <upstream-json> <artifact-dir>}"

mkdir -p "$artifact_dir"

mapfile -t local_files < <(find "$local_dir" -maxdepth 1 -type f -name '*.sub2api.json' | sort)
if [ "${#local_files[@]}" -eq 0 ]; then
  echo "no local .sub2api.json captures were produced" >&2
  exit 1
fi

local_raw="$artifact_dir/local-sub2api.json"
upstream_raw="$artifact_dir/upstream-sub2api.json"
local_normalized="$artifact_dir/local-normalized.json"
upstream_normalized="$artifact_dir/upstream-normalized.json"

jq -s '{count: length, fingerprints: map(.fingerprints[0])}' "${local_files[@]}" > "$local_raw"

local_count="$(jq -r '.count' "$local_raw")"
upstream_count="$(jq -r '.count // 0' "$upstream_json")"
if [ "$upstream_count" -lt "$local_count" ]; then
  echo "upstream reported $upstream_count fingerprints, but local run produced $local_count" >&2
  exit 1
fi

jq --argjson count "$local_count" '{count: ($count), fingerprints: (.fingerprints[0:$count] // [])}' "$upstream_json" > "$upstream_raw"

normalize_payload='def normalize_fingerprint: {
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
};
{
  count,
  fingerprints: (
    .fingerprints
    | map(normalize_fingerprint)
    | sort_by([
        .model,
        .ja3_hash,
        .ja4,
        .http2,
        ((.extensions // []) | map(tostring) | join(",")),
        ((.signature_algorithms // []) | map(tostring) | join(",")),
        ((.compress_cert_algos // []) | map(tostring) | join(","))
      ])
  )
}'

jq "$normalize_payload" "$local_raw" > "$local_normalized"
jq "$normalize_payload" "$upstream_raw" > "$upstream_normalized"

diff -u "$local_normalized" "$upstream_normalized"
