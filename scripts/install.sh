#!/bin/sh
set -eu

prefix="${MISCONFIG_INSTALL_PREFIX:-/usr/local}"
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
target_dir="${prefix}/bin"
target="${target_dir}/misconfig-provider-aws"

case "$prefix" in
  /*) ;;
  *) echo "MISCONFIG_INSTALL_PREFIX must be an absolute path" >&2; exit 2 ;;
esac

if [ ! -x "${source_dir}/misconfig-provider-aws" ]; then
  echo "misconfig-provider-aws is missing from the release archive" >&2
  exit 2
fi
if [ -e "$target" ]; then
  echo "$target already exists; remove it explicitly before installing another release" >&2
  exit 2
fi

mkdir -p "$target_dir"
temporary="${target}.tmp.$$"
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cp "${source_dir}/misconfig-provider-aws" "$temporary"
chmod 0755 "$temporary"
mv "$temporary" "$target"
trap - EXIT HUP INT TERM
echo "Installed $target"
