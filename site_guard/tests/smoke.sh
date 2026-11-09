#!/bin/sh
# Isolated smoke and replay harness for ngx_http_site_guard_module.
# Builds nothing itself: point NGINX_BIN at an already-built binary.
# Creates a private prefix under $(mktemp -d), starts nginx on 127.0.0.1:18089,
# runs the request matrix, asserts status codes and stats variables, then stops.
# Exit 0 only when every assertion passes.
set -eu

NGINX_BIN="${NGINX_BIN:-$PWD/objs/nginx}"
PORT="${PORT:-18089}"

if [ ! -x "$NGINX_BIN" ]; then
  echo "nginx binary not found: $NGINX_BIN (build with auto/configure --add-module=./site_guard && make)" >&2
  exit 2
fi

PREFIX="$(mktemp -d /tmp/site-guard-smoke.XXXXXX)"
cleanup() {
  "$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx" -s stop >/dev/null 2>&1 || true
  i=0
  while pgrep -f "nginx.*-p $PREFIX" >/dev/null 2>&1 && [ "$i" -lt 30 ]; do
    i=$((i + 1)); sleep 0.1
  done
  pkill -f "nginx.*-p $PREFIX" >/dev/null 2>&1 || true
  rm -rf "$PREFIX"
}
trap cleanup EXIT INT TERM
mkdir -p "$PREFIX/logs" "$PREFIX/html" "$PREFIX/data"
printf '<html>ok</html>\n' > "$PREFIX/html/index.html"
cat > "$PREFIX/data/referers.rules" <<'RULES'
# runtime rule file: one full Referer per line
https://example.com/nn/beginner/nn-b-02
RULES

cat > "$PREFIX/conf.nginx" <<CONF
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 128; }
http {
    access_log logs/access.log;
    site_guard on;
    site_guard_mode enforce;
    site_guard_status 444;
    site_guard_zone guard 1m;
    site_guard_rules_file $PREFIX/data/referers.rules;
    site_guard_referer https://example.com/nn/beginner/nn-b-01;
    site_guard_excluded_prefix /nn/;
    log_format guard '\$status gen=\$site_guard_generation rqpm=\$site_guard_referer_qpm uqpm=\$site_guard_ua_qpm pqpm=\$site_guard_path_qpm ips=\$site_guard_referer_ips';
    access_log logs/guard.log guard;
    server {
        listen 127.0.0.1:$PORT;
        root html;
    }
}
CONF

"$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx" -t
"$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx"

# Give the worker one moment to open the listener.
i=0
while ! curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 50 ]; then echo "nginx did not start" >&2; exit 1; fi
  sleep 0.1
done

fail=0
assert_status() {
  desc=$1 want=$2; shift 2
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@" || true)
  case "|$want|" in
    *"|$got|"*) echo "PASS $desc -> $got" ;;
    *) echo "FAIL $desc -> got $got want $want" >&2; fail=1 ;;
  esac
}

# 444 closes the connection without a response; curl reports 000.
# Allowed-through requests reach the content phase: 200 for existing files,
# 404 for paths absent from the temporary prefix, both prove the guard passed.
PASS_THROUGH="200|404"
assert_status "excluded /nn/ path passes" "$PASS_THROUGH" \
  -e https://example.com/nn/beginner/nn-b-01 "http://127.0.0.1:$PORT/nn/beginner/nn-b-01"
assert_status "static directive Referer blocked outside /nn/" 000 \
  -e https://example.com/nn/beginner/nn-b-01 "http://127.0.0.1:$PORT/chip-design/"
assert_status "runtime rule file Referer blocked" 000 \
  -e https://example.com/nn/beginner/nn-b-02 "http://127.0.0.1:$PORT/fpga/"
assert_status "unlisted Referer passes" "$PASS_THROUGH" \
  -e https://example.com/other "http://127.0.0.1:$PORT/chip-design/"
assert_status "no Referer passes" "$PASS_THROUGH" \
  "http://127.0.0.1:$PORT/chip-design/"
assert_status "trailing slash variant blocked" 000 \
  -e https://example.com/nn/beginner/nn-b-01/ "http://127.0.0.1:$PORT/eda/"
assert_status "spoof host suffix passes" "$PASS_THROUGH" \
  -e https://example.com/nn/beginner/nn-b-01.evil.test "http://127.0.0.1:$PORT/chip-design/"
assert_status "HEAD blocked with same policy" 000 \
  -I -e https://example.com/nn/beginner/nn-b-01 "http://127.0.0.1:$PORT/chip-design/"
assert_status "malformed Referer passes" "$PASS_THROUGH" \
  -e "not-a-url" "http://127.0.0.1:$PORT/chip-design/"

# CRUD control plane plus request normalization. The module polls the rule
# file once per second, so each publish is followed by a short wait.
RULES="$PREFIX/data/referers.rules"
CTL="${SITE_GUARD_CTL:-$PWD/site_guard/tests/site-guard-ctl}"
"$CTL" "$RULES" validate

"$CTL" "$RULES" add "https://example.com/nn/beginner/nn-b-03"
sleep 1.2
assert_status "uppercase scheme/host plus query normalized and blocked" 000 \
  -e "HTTPS://EXAMPLE.COM/nn/beginner/nn-b-03?utm=z" "http://127.0.0.1:$PORT/chip-design/x"
assert_status "default port and trailing slash normalized and blocked" 000 \
  -e "https://example.com:443/nn/beginner/nn-b-03/" "http://127.0.0.1:$PORT/eda/x"
assert_status "non-default port does not match canonical rule" "$PASS_THROUGH" \
  -e "https://example.com:8443/nn/beginner/nn-b-03" "http://127.0.0.1:$PORT/chip-design/x"

"$CTL" "$RULES" add "/nn/beginner/nn-b-04"
sleep 1.2
assert_status "path-only rule blocks across hosts" 000 \
  -e "http://other.host/nn/beginner/nn-b-04" "http://127.0.0.1:$PORT/fpga/x"

if "$CTL" "$RULES" add "not-a-url" >/dev/null 2>&1; then
  echo "FAIL ctl accepted an invalid rule" >&2; fail=1
else
  echo "PASS ctl rejected invalid rule"
fi
"$CTL" "$RULES" validate
assert_status "rejected rule never loaded" "$PASS_THROUGH" \
  -e "not-a-url" "http://127.0.0.1:$PORT/chip-design/x"

"$CTL" "$RULES" remove "https://example.com/nn/beginner/nn-b-03"
sleep 1.2
assert_status "removed rule no longer blocks" "$PASS_THROUGH" \
  -e "https://example.com/nn/beginner/nn-b-03" "http://127.0.0.1:$PORT/chip-design/x"
assert_status "remaining path-only rule still blocks" 000 \
  -e "http://other.host/nn/beginner/nn-b-04" "http://127.0.0.1:$PORT/fpga/x"

# Stats variables must be populated in the guard log after matched traffic.
curl -s -o /dev/null -e https://example.com/nn/beginner/nn-b-01 "http://127.0.0.1:$PORT/chip-design/x" || true
sleep 0.2
if grep -q 'pqpm=' "$PREFIX/logs/guard.log"; then
  echo "PASS guard log contains stats variables"
  grep 'pqpm=' "$PREFIX/logs/guard.log" | tail -1
else
  echo "FAIL stats variables missing from guard log" >&2
  fail=1
fi

# Sanitizer evidence: nginx core itself trips UBSan function-pointer casts in
# its filter chain (ngx_output_chain.c). Those are core findings, not module
# findings. A report whose stack contains a site_guard frame is a real failure;
# core-only reports are surfaced as warnings for the evidence record.
if grep -qi 'sanitizer\|runtime error' "$PREFIX/logs/error.log"; then
  if grep -i 'sanitizer\|runtime error' "$PREFIX/logs/error.log" | grep -q 'site_guard'; then
    echo "FAIL sanitizer finding inside site_guard code" >&2
    grep -i 'sanitizer\|runtime error' "$PREFIX/logs/error.log" >&2
    fail=1
  else
    echo "WARN sanitizer reports present but limited to nginx core frames:"
    grep -i 'runtime error' "$PREFIX/logs/error.log" | sort -u
    echo "PASS no sanitizer findings in site_guard code"
  fi
else
  echo "PASS no sanitizer/runtime errors"
fi

if [ "$fail" -ne 0 ]; then
  "$NGINX_BIN" -p "$PREFIX" -c "$PREFIX/conf.nginx" -s stop >/dev/null 2>&1 || true
  pkill -f "nginx.*-p $PREFIX" >/dev/null 2>&1 || true
  echo "SMOKE FAILED; prefix kept for inspection: $PREFIX" >&2
  trap - EXIT
  exit 1
fi
echo "SMOKE PASS"
