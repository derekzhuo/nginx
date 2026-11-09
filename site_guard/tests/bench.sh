#!/bin/sh
# Isolated latency benchmark for the site_guard access-phase overhead.
#
# Usage: NGINX_BIN=$PWD/objs-normal/nginx sh site_guard/tests/bench.sh
#
# ab cannot cap request rate, so scenarios are defined by concurrency
# sweeps and the achieved rps is reported honestly next to the latency
# percentiles. NFR targets: P95 <= 1 ms, P99 <= 3 ms on loopback. Each
# scenario is compared against an otherwise identical guard-off config so
# the measured difference is module overhead, not nginx baseline cost.
set -eu

NGINX_BIN="${NGINX_BIN:-$PWD/objs-normal/nginx}"
PORT="${PORT:-18091}"
TOTAL="${TOTAL:-20000}"
LEVELS="${LEVELS:-1 4 16}"

if [ ! -x "$NGINX_BIN" ]; then
    echo "nginx binary not found: $NGINX_BIN" >&2
    exit 2
fi
command -v ab >/dev/null || { echo "ab (ApacheBench) not found" >&2; exit 2; }
if command -v lsof >/dev/null && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $PORT already in use; set PORT=<free port>" >&2
    exit 2
fi

PREFIX=$(mktemp -d /tmp/site-guard-bench.XXXXXX)
cleanup() {
    "$NGINX_BIN" -p "$PREFIX" -s stop >/dev/null 2>&1 || true
    pkill -f "nginx.*-p $PREFIX" >/dev/null 2>&1 || true
    rm -rf "$PREFIX"
}
trap cleanup EXIT INT TERM
mkdir -p "$PREFIX/logs" "$PREFIX/html" "$PREFIX/data"
printf '<html>ok</html>\n' > "$PREFIX/html/index.html"

# 64 full-URL rules exercise the bounded linear scan; rule 64 is the
# matching one for the hit scenario, giving worst-position lookup.
i=1
while [ "$i" -le 63 ]; do
    printf 'https://example.com/nn/beginner/rule-%02d\n' "$i"
    i=$((i + 1))
done > "$PREFIX/data/referers.rules"
printf 'https://example.com/nn/beginner/rule-64\n' >> "$PREFIX/data/referers.rules"

write_conf() {
    mode=$1
    cat > "$PREFIX/conf.nginx" <<CONF
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 256; }
http {
    access_log off;
    # ab -k leaves idle keepalive connections; the default 65s timeout would
    # stall graceful shutdown between scenarios, so keep the window short.
    keepalive_timeout 1s;
    site_guard $mode;
    site_guard_mode enforce;
    site_guard_status 444;
    site_guard_zone guard 1m;
    site_guard_rules_file $PREFIX/data/referers.rules;
    site_guard_excluded_prefix /nn/;
    server {
        listen 127.0.0.1:$PORT;
        root html;
    }
}
CONF
}

start() {
    write_conf "$1"
    "$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx" -t >/dev/null
    "$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx"
    n=0
    while ! curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -gt 50 ] && { echo "nginx did not start" >&2; exit 1; }
        sleep 0.1
    done
}

stop() {
    # -c is required: without it nginx looks for the default conf path and
    # the stop signal is never sent to the running master.
    "$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx" -s stop >/dev/null 2>&1 || true
    n=0
    while pgrep -f "nginx.*-p $PREFIX" >/dev/null 2>&1; do
        n=$((n + 1)); [ "$n" -gt 30 ] && break
        sleep 0.1
    done
    # The process can exit while the listening socket is still being released.
    n=0
    while lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; do
        n=$((n + 1)); [ "$n" -gt 50 ] && { echo "port $PORT did not free" >&2; exit 1; }
        sleep 0.1
    done
}

# Extract the metrics that map to the NFR from ab's output.
summarize() {
    label=$1; c=$2; log=$3
    rps=$(awk -F ':' '/Requests per second/ {print $2}' "$log" | grep -oE '[0-9.]+' | head -1)
    p95=$(awk '/^[[:space:]]*95%/ {print $2}' "$log")
    p99=$(awk '/^[[:space:]]*99%/ {print $2}' "$log")
    mean=$(awk '/Time per request:.*mean/ {print $4}' "$log" | head -1)
    printf '%-28s c=%-2s rps=%-9s mean=%-8s p95=%-8s p99=%s ms\n' \
        "$label" "$c" "$rps" "$mean" "$p95" "$p99"
}

run_sweep() {
    label=$1; shift
    for c in $LEVELS; do
        log="$PREFIX/ab-$label-c$c.txt"
        ab -n "$TOTAL" -c "$c" -k "$@" "http://127.0.0.1:$PORT/chip-design/x" > "$log" 2>&1
        summarize "$label" "$c" "$log"
    done
}

echo "== baseline: site_guard off, no Referer"
start off
run_sweep off
stop

echo "== guard enforce: no Referer (fast pass before rule matching)"
start on
run_sweep noref
stop

echo "== guard enforce: 64 rules, non-matching Referer (full linear scan)"
start on
run_sweep miss -H 'Referer: https://example.com/other/page'
stop

echo "== guard enforce: excluded-prefix request carrying a blocked Referer"
start on
for c in $LEVELS; do
    log="$PREFIX/ab-excl-c$c.txt"
    ab -n "$TOTAL" -c "$c" -k \
        -H 'Referer: https://example.com/nn/beginner/rule-64' \
        "http://127.0.0.1:$PORT/nn/beginner/x" > "$log" 2>&1
    summarize "excluded" "$c" "$log"
done
stop

echo "== raw percentile table for the highest-concurrency full-scan run"
grep -E 'Requests per second|^[[:space:]]*(50|95|99|100)%' "$PREFIX/ab-miss-c16.txt" || true
echo "BENCH DONE (NFR: P95 <= 1 ms, P99 <= 3 ms)"
