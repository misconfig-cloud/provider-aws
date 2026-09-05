#!/bin/sh
set -eu

prefix="${MISCONFIG_INSTALL_PREFIX:-/usr/local}"
confirm="${1:-}"
case "$prefix" in
  /*) ;;
  *) echo "MISCONFIG_INSTALL_PREFIX must be an absolute path" >&2; exit 2 ;;
esac
if [ "$confirm" != "--yes" ]; then
  echo "Usage: MISCONFIG_INSTALL_PREFIX=/path $0 --yes" >&2
  exit 2
fi

target="${prefix}/bin/misconfig-provider-aws"
if [ -e "$target" ]; then
  rm -f "$target"
  echo "Removed $target"
else
  echo "$target is not installed"
fi
