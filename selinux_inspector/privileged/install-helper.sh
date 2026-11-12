#!/usr/bin/env bash
set -euo pipefail

TARGET="/usr/libexec/linspectacles-selinux-helper"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE="$HERE/linspectacles-selinux-helper"
PKEXEC=""
for p in /usr/bin/pkexec /bin/pkexec; do
  if [[ -x "$p" && ! -L "$p" ]]; then PKEXEC="$p"; break; fi
done
if [[ -z "$PKEXEC" ]]; then
  echo "pkexec is required." >&2
  exit 1
fi
if [[ ! -f "$SOURCE" || -L "$SOURCE" ]]; then
  echo "Helper source is missing or is a symbolic link." >&2
  exit 1
fi

case "${1:-}" in
  --uninstall)
    exec "$PKEXEC" /usr/bin/rm -f -- "$TARGET"
    ;;
  "")
    exec "$PKEXEC" /usr/bin/install -o root -g root -m 0755 -- "$SOURCE" "$TARGET"
    ;;
  *)
    echo "Usage: $0 [--uninstall]" >&2
    exit 2
    ;;
esac
