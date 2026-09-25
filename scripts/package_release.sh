#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

PACKAGE_NAME=${PACKAGE_NAME:-ghostlock-PD2339FA-Neo9SPro-Root}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || printf 'dev')}
VERSION_LABEL=${VERSION//\//-}
OUTPUT_DIR=${OUTPUT_DIR:-$REPO_ROOT/dist}
PACKAGE_DIR="$OUTPUT_DIR/$PACKAGE_NAME-$VERSION_LABEL"
ARCHIVE_BASE="$OUTPUT_DIR/$PACKAGE_NAME-$VERSION_LABEL"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

copy_file() {
  local relative=$1
  local source="$REPO_ROOT/$relative"
  local destination="$PACKAGE_DIR/$relative"
  [ -f "$source" ] || fail "required package input is missing: $relative"
  mkdir -p "$(dirname "$destination")"
  cp -p "$source" "$destination"
}

rm -rf "$PACKAGE_DIR"
rm -f "${ARCHIVE_BASE}.tar.gz" "${ARCHIVE_BASE}.zip" "${ARCHIVE_BASE}.sha256"
mkdir -p "$PACKAGE_DIR"

# The archive is a runnable folder, not a source checkout. Keep the host-side
# KO patcher and its input modules: the runtime TEXT address is measured on
# each boot, so the device-ready KO must be generated from these assets.
for file in \
  LICENSE \
  scripts/r830_autofire.sh \
  scripts/r821a_command.txt \
  scripts/r776b_command.txt \
  ksu/make_device_ko.sh \
  ksu/make_device_ko.py \
  ksu/kernelsu-android14-6.1-local.ko \
  tools/kallsyms.new \
  tools/hijtest \
  tools/slot_restore \
  tools/psl2 \
  tools/r829_bandscan \
  payloads/preload.so; do
  copy_file "$file"
done

# Preserve all tracked KO variants when present, but never accidentally ship a
# stale device-ready module produced by an earlier local run.
ko_count=0
for source in "$REPO_ROOT"/ksu/*.ko; do
  [ -f "$source" ] || continue
  name=${source##*/}
  [ "$name" = "kernelsu-device-ready.ko" ] && continue
  copy_file "ksu/$name"
  ko_count=$((ko_count + 1))
done
[ "$ko_count" -gt 0 ] || fail "no KO asset found under ksu/"

chmod 0755 \
  "$PACKAGE_DIR/scripts/r830_autofire.sh" \
  "$PACKAGE_DIR/ksu/make_device_ko.sh" \
  "$PACKAGE_DIR/ksu/make_device_ko.py" \
  "$PACKAGE_DIR/tools/hijtest" \
  "$PACKAGE_DIR/tools/slot_restore" \
  "$PACKAGE_DIR/tools/psl2" \
  "$PACKAGE_DIR/tools/r829_bandscan"

printf '%s\n' "$VERSION" > "$PACKAGE_DIR/VERSION"

(
  cd "$PACKAGE_DIR"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

PACKAGE_BASENAME=$(basename "$PACKAGE_DIR")
# Keep one top-level directory in both formats so extraction produces the
# expected standard runnable folder.
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -czf "${ARCHIVE_BASE}.tar.gz" -C "$OUTPUT_DIR" "$PACKAGE_BASENAME"
(
  cd "$OUTPUT_DIR"
  zip -qr -X "${ARCHIVE_BASE}.zip" "$PACKAGE_BASENAME"
)
sha256sum "${ARCHIVE_BASE}.tar.gz" "${ARCHIVE_BASE}.zip" \
  > "${ARCHIVE_BASE}.sha256"

printf 'package_dir=%s\n' "$PACKAGE_DIR"
printf 'tar=%s\n' "${ARCHIVE_BASE}.tar.gz"
printf 'zip=%s\n' "${ARCHIVE_BASE}.zip"
printf 'checksums=%s\n' "${ARCHIVE_BASE}.sha256"
