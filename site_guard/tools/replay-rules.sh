#!/bin/sh
# Offline replay of site_guard rules against sanitized historical logs.
#
# Usage: replay-rules.sh [-x EXCLUDED_PREFIX]... <rules-file> <log>...
#
# Classifies every GET/HEAD request exactly as the module would: requests
# without a Referer pass, excluded URI prefixes pass, malformed Referers
# fail open, and rules are matched after the same canonical normalization.
# Passing two wave logs prints per-wave coverage so rule stability across
# waves can be judged before any production shadow run. Exit 0 on success,
# 1 on missing input, 2 on usage error.
set -eu

EXCL=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -x) EXCL="$EXCL$2
"; shift 2 ;;
        --) shift; break ;;
        -*) echo "replay-rules.sh: unknown option: $1" >&2; exit 2 ;;
        *) break ;;
    esac
done

[ "$#" -ge 2 ] || {
    echo "Usage: replay-rules.sh [-x EXCLUDED_PREFIX]... <rules-file> <log>..." >&2
    exit 2
}
RULES=$1
shift
[ -r "$RULES" ] || { echo "replay-rules.sh: cannot read rules: $RULES" >&2; exit 1; }
for f in "$@"; do
    [ -r "$f" ] || { echo "replay-rules.sh: cannot read log: $f" >&2; exit 1; }
done

DIR=$(dirname "$0")
TAB=$(printf '\t')
TMP_OUT=$(mktemp "${TMPDIR:-/tmp}/sg-replay.XXXXXX")
trap 'rm -f "$TMP_OUT"' EXIT

for f in "$@"; do
    echo "== wave: $f"
    SG_EXCL="$EXCL" awk -f "$DIR/sg-normalize.awk" -f "$DIR/replay-rules.awk" \
        -v rules_file="$RULES" "$f" > "$TMP_OUT"
    # Prose stays in order; only the trailing "top blocked referers" list,
    # whose lines contain a tab, is ranked by hit count.
    awk 'BEGIN{shown=0} /\t/{if(!shown){shown=1}; if(shown) next} {print}' "$TMP_OUT"
    grep "$TAB" "$TMP_OUT" | sort -t "$TAB" -k1,1 -nr || true
done
