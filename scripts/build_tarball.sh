#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
component_dir="${repo_root}/custom_components/resmed_myair"
output="${repo_root}/resmed_air.tar.gz"

if [[ ! -d "${component_dir}" ]]; then
  echo "Missing integration directory: ${component_dir}" >&2
  exit 1
fi

tar \
  --create \
  --gzip \
  --file "${output}" \
  --directory "${repo_root}/custom_components" \
  --sort=name \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --exclude="*/__pycache__" \
  --exclude="*.pyc" \
  resmed_myair

echo "Wrote ${output}"
