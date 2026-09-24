#!/bin/sh
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KO=${KO:-$DIR/kernelsu-android14-6.1-local.ko}
KALLSYMS=${KALLSYMS:-$DIR/../tools/kallsyms.new}
OUT=${OUT:-kernelsu-device-ready.ko}

[ -n "$1" ] || { echo "usage: $0 [--dry-run] <runtime_text_hex>"; exit 2; }
[ -f "$KO" ]       || { echo "ERROR: base ko not found: $KO" >&2; exit 1; }
[ -f "$KALLSYMS" ] || { echo "ERROR: kallsyms not found: $KALLSYMS" >&2; \
                        echo "       set KALLSYMS=/path/to/kallsyms.new" >&2; exit 1; }
[ -f "$DIR/make_device_ko.py" ] || { echo "ERROR: $DIR/make_device_ko.py missing" >&2; exit 1; }

if [ "$1" = "--dry-run" ]; then
    shift
    exec python3 "$DIR/make_device_ko.py" --dry-run --ko "$KO" --kallsyms "$KALLSYMS" --text "$1"
fi
exec python3 "$DIR/make_device_ko.py" --ko "$KO" --kallsyms "$KALLSYMS" --text "$1" --out "$OUT"
