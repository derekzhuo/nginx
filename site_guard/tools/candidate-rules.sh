#!/bin/sh
# Offline candidate-rule extraction from sanitized nginx combined logs.
#
# Usage: candidate-rules.sh [--rules] [--min-hits N] [--top N] <log>...
#
# Default output is a tab-separated report ranked by hit count:
#   hits  distinct_ips  distinct_clusters  distinct_hosts  canonical_referer
#
# --rules emits at most 64 canonical full-URL rules, one per line, suitable
# for piping into site-guard-ctl add. Only sanitized log files belong here:
# this tool never reads cookies or credentials, and raw production logs must
# not leave the origin.
set -eu

MODE=report
MIN_HITS=1
TOP=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rules) MODE=rules; shift ;;
        --min-hits) MIN_HITS=$2; shift 2 ;;
        --top) TOP=$2; shift 2 ;;
        --) shift; break ;;
        -*) echo "candidate-rules.sh: unknown option: $1" >&2; exit 2 ;;
        *) break ;;
    esac
done

[ "$#" -ge 1 ] || {
    echo "Usage: candidate-rules.sh [--rules] [--min-hits N] [--top N] <log>..." >&2
    exit 2
}
for f in "$@"; do
    [ -r "$f" ] || { echo "candidate-rules.sh: cannot read: $f" >&2; exit 1; }
done

DIR=$(dirname "$0")
TAB=$(printf '\t')

awk -f "$DIR/sg-normalize.awk" -f "$DIR/candidate-rules.awk" \
    -v mode="$MODE" -v min_hits="$MIN_HITS" "$@" \
    | sort -t "$TAB" -k1,1 -nr \
    | if [ "$TOP" -gt 0 ]; then head -n "$TOP"; else cat; fi \
    | if [ "$MODE" = "rules" ]; then
        awk -F '\t' '{ print $2 }' | head -n 64
    else
        {
            printf 'hits\tdistinct_ips\tdistinct_clusters\tdistinct_hosts\tcanonical_referer\n'
            cat
        }
    fi
