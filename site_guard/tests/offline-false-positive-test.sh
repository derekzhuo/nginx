#!/bin/sh
# False-positive replay for FR-05 (whitelist and误伤保护). A synthetic day of
# real-reader traffic is replayed against the incident fingerprint rules. Only
# the exact incident fingerprints may be blocked; every legitimate navigation,
# feed, static asset, cert renewal, and search referer must pass. Uses the same
# offline awk replay as offline-tools-test.sh, so no nginx binary, network, or
# real log data is needed. Exit 0 only when every assertion passes.
set -eu

HERE=$(dirname "$0")
TOOLS=$(cd "$HERE/../tools" && pwd)
WORK=$(mktemp -d /tmp/sg-fp.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
fail=0

check() {
    desc=$1; want=$2; got=$3
    if [ "$want" = "$got" ]; then
        echo "PASS $desc"
    else
        echo "FAIL $desc: want [$want] got [$got]" >&2
        fail=1
    fi
}

NN1="https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor"
ATTN="https://geek-doc.cn/nn/beginner/attention-transformer"

# Representative incident rules: two full-URL fingerprints and one path-only
# fingerprint. Excluded prefixes mirror the production guard (/nn/ same-cluster
# navigation and ACME certificate renewal).
cat > "$WORK/rules" <<RULES
$NN1
$ATTN
/nn/beginner/flops-params
RULES

# Synthetic real-reader day. Combined log: ip - - [time] "request" status bytes
# "referer" "ua". Classification targets are counted explicitly in comments.
cat > "$WORK/readers.log" <<LOG
# --- pass (no referer): 7 ---
203.0.113.1 - - [09/Nov/2026:09:00:01 +0800] "GET /chip-design/direct HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
203.0.113.2 - - [09/Nov/2026:09:00:02 +0800] "GET /feed.xml HTTP/1.1" 200 9001 "-" "Feedly/1.0"
203.0.113.3 - - [09/Nov/2026:09:00:03 +0800] "GET /sitemap.xml HTTP/1.1" 200 50022 "-" "Mozilla/5.0"
203.0.113.4 - - [09/Nov/2026:09:00:04 +0800] "GET /robots.txt HTTP/1.1" 200 140 "-" "Mozilla/5.0"
203.0.113.5 - - [09/Nov/2026:09:00:05 +0800] "GET /favicon.ico HTTP/1.1" 200 1150 "-" "Mozilla/5.0"
203.0.113.6 - - [09/Nov/2026:09:00:06 +0800] "GET /assets/style.css HTTP/1.1" 200 8421 "-" "Mozilla/5.0"
203.0.113.7 - - [09/Nov/2026:09:00:07 +0800] "GET /shots/wave.png HTTP/1.1" 200 73210 "-" "Mozilla/5.0"
# --- pass (excluded prefix): 2 ---
203.0.113.8 - - [09/Nov/2026:09:01:01 +0800] "GET /nn/beginner/nn-b-01-neuron-perceptron-tensor HTTP/1.1" 200 1234 "$NN1" "Mozilla/5.0"
203.0.113.9 - - [09/Nov/2026:09:01:02 +0800] "GET /.well-known/acme-challenge/abc123 HTTP/1.1" 200 87 "$NN1" "certbot/2.0"
# --- pass (malformed referer fails open): 1 ---
203.0.113.10 - - [09/Nov/2026:09:02:01 +0800] "GET /chip-design/malformed HTTP/1.1" 200 1234 "not-a-url" "Mozilla/5.0"
# --- pass (no rule hit): 6 ---
203.0.113.11 - - [09/Nov/2026:09:03:01 +0800] "GET /chip-design/from-bing HTTP/1.1" 200 1234 "https://www.bing.com/search?q=mp2307" "Mozilla/5.0"
203.0.113.12 - - [09/Nov/2026:09:03:02 +0800] "GET /eda/from-google HTTP/1.1" 200 1234 "https://www.google.com/search?q=vivado" "Mozilla/5.0"
203.0.113.13 - - [09/Nov/2026:09:03:03 +0800] "GET /chip-design/internal-cross-cluster HTTP/1.1" 200 1234 "https://geek-doc.cn/concepts/cache/mesi" "Mozilla/5.0"
203.0.113.14 - - [09/Nov/2026:09:03:04 +0800] "GET /fpga/mobile-reader HTTP/1.1" 200 1234 "https://geek-doc.cn/tools/perf" "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"
203.0.113.15 - - [09/Nov/2026:09:03:05 +0800] "GET /chip-design/query-referer HTTP/1.1" 200 1234 "https://geek-doc.cn/concepts/something?utm_source=newsletter" "Mozilla/5.0"
203.0.113.16 - - [09/Nov/2026:09:03:06 +0800] "GET /chip-design/friendly-external HTTP/1.1" 200 1234 "https://juejin.cn/post/1234567890" "Mozilla/5.0"
# --- would block: 4 exact incident fingerprints ---
198.51.100.1 - - [09/Nov/2026:10:00:01 +0800] "GET /chip-design/a HTTP/1.1" 200 1234 "$NN1" "Mozilla/5.0"
198.51.100.2 - - [09/Nov/2026:10:00:02 +0800] "GET /eda/b HTTP/1.1" 200 1234 "HTTPS://GEEK-DOC.CN:443/nn/beginner/nn-b-01-neuron-perceptron-tensor/?utm=x" "Mozilla/5.0"
198.51.100.3 - - [09/Nov/2026:10:00:03 +0800] "GET /fpga/c HTTP/1.1" 200 1234 "$ATTN" "Mozilla/5.0"
198.51.100.4 - - [09/Nov/2026:10:00:04 +0800] "GET /chip-design/d HTTP/1.1" 200 1234 "https://other.example/nn/beginner/flops-params" "Mozilla/5.0"
# --- non GET/HEAD must be ignored by the replay classifier ---
198.51.100.5 - - [09/Nov/2026:10:00:05 +0800] "POST /chip-design/e HTTP/1.1" 200 1234 "$NN1" "Mozilla/5.0"
LOG

"$TOOLS/replay-rules.sh" -x /nn/ -x /.well-known/ "$WORK/rules" "$WORK/readers.log" > "$WORK/out.txt"
cat "$WORK/out.txt"

total=$(awk -F ': ' '/total GET\/HEAD/ {print $2}' "$WORK/out.txt" | awk '{print $1}')
block=$(awk -F ': ' '/would block/ {print $2}' "$WORK/out.txt" | awk '{print $1}')
noref=$(awk -F ': ' '/pass \(no referer\)/ {print $2}' "$WORK/out.txt" | awk '{print $1}')
excl=$(awk -F ': ' '/pass \(excluded\)/ {print $2}' "$WORK/out.txt" | awk '{print $1}')
mal=$(awk -F ': ' '/pass \(malformed\)/ {print $2}' "$WORK/out.txt" | awk '{print $1}')
norule=$(awk -F ': ' '/pass \(no rule hit\)/ {print $2}' "$WORK/out.txt" | awk '{print $1}')
same=$(awk -F ': ' '/same-cluster blocks/ {print $2}' "$WORK/out.txt" | awk '{print $1}')

# 20 GET/HEAD: the POST line is excluded from the classifier total.
check "classifier counts only GET/HEAD" 20 "$total"
check "only the four exact fingerprints are blocked" 4 "$block"
check "seven no-referer reader/asset requests pass" 7 "$noref"
check "two excluded-prefix requests pass (same-cluster, ACME)" 2 "$excl"
check "malformed referer fails open" 1 "$mal"
check "six legitimate referers pass without a rule hit" 6 "$norule"
check "incident cross-cluster rules raise no same-cluster indicator" 0 "$same"

# The blocked list aggregates each canonical key on one line with a hit-count
# prefix; the cosmetic uppercase/port/query variant must collapse onto NN1.
blocked_nn1=$(awk -v k="$NN1" '$0 ~ k {print $1}' "$WORK/out.txt")
blocked_attn=$(awk -v k="$ATTN" '$0 ~ k {print $1}' "$WORK/out.txt")
blocked_path=$(awk '$0 ~ /other\.example\/nn\/beginner\/flops-params/ {print $1}' "$WORK/out.txt")
check "canonical NN1 fingerprint blocked including its variant" 2 "$blocked_nn1"
check "attention-transformer fingerprint blocked" 1 "$blocked_attn"
check "path-only rule matches across hosts" 1 "$blocked_path"

if [ "$fail" -ne 0 ]; then
    echo "FALSE-POSITIVE REPLAY FAILED" >&2
    exit 1
fi
echo "FALSE-POSITIVE REPLAY PASS"
