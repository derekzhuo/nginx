#!/bin/sh
# Offline tests for candidate-rules.sh and replay-rules.sh using synthetic
# combined-format logs. No nginx binary, network access, or real log data is
# required. Exit 0 only when every assertion passes.
set -eu

HERE=$(dirname "$0")
TOOLS=$(cd "$HERE/../tools" && pwd)
WORK=$(mktemp -d /tmp/sg-offline.XXXXXX)
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

# Combined log: ip - - [time] "request" status bytes "referer" "ua"
cat > "$WORK/wave1.log" <<'LOG'
10.0.0.1 - - [09/Nov/2026:10:00:01 +0800] "GET /chip-design/a HTTP/1.1" 200 1234 "https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor" "Mozilla/5.0"
10.0.0.2 - - [09/Nov/2026:10:00:02 +0800] "GET /eda/b HTTP/1.1" 200 1234 "HTTPS://GEEK-DOC.CN:443/nn/beginner/nn-b-01-neuron-perceptron-tensor/?utm=x" "Mozilla/5.0"
10.0.0.3 - - [09/Nov/2026:10:00:03 +0800] "GET /fpga/c HTTP/1.1" 200 1234 "https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor" "curl/8"
10.0.0.4 - - [09/Nov/2026:10:00:04 +0800] "GET /nn/beginner/nn-b-01-neuron-perceptron-tensor HTTP/1.1" 200 1234 "https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor" "Mozilla/5.0"
10.0.0.5 - - [09/Nov/2026:10:00:05 +0800] "GET /chip-design/d HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.6 - - [09/Nov/2026:10:00:06 +0800] "POST /chip-design/e HTTP/1.1" 200 1234 "https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor" "Mozilla/5.0"
10.0.0.7 - - [09/Nov/2026:10:00:07 +0800] "GET /chip-design/f HTTP/1.1" 200 1234 "not-a-url" "Mozilla/5.0"
10.0.0.8 - - [09/Nov/2026:10:00:08 +0800] "GET /fpga/g HTTP/1.1" 200 1234 "https://other.example/nn/beginner/nn-b-02" "Mozilla/5.0"
10.0.0.9 - - [09/Nov/2026:10:00:09 +0800] "GET /chip-design/h HTTP/1.1" 200 1234 "http://other.host/chip-design/" "Mozilla/5.0"
LOG

cat > "$WORK/wave2.log" <<'LOG'
10.1.0.1 - - [09/Nov/2026:11:00:01 +0800] "GET /chip-design/h HTTP/1.1" 200 1234 "https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor" "Mozilla/5.0"
10.1.0.2 - - [09/Nov/2026:11:00:02 +0800] "GET /eda/i HTTP/1.1" 200 1234 "https://other.example/nn/beginner/nn-b-02" "Mozilla/5.0"
10.1.0.3 - - [09/Nov/2026:11:00:03 +0800] "GET /chip-design/j HTTP/1.1" 200 1234 "https://geek-doc.cn:8443/nn/beginner/nn-b-01-neuron-perceptron-tensor" "Mozilla/5.0"
LOG

# --- candidate extraction -------------------------------------------------
"$TOOLS/candidate-rules.sh" "$WORK/wave1.log" > "$WORK/cand.tsv"
cat "$WORK/cand.tsv"

# Four cosmetic variants of one referer collapse to one canonical key.
n_keys=$(awk 'NR>1' "$WORK/cand.tsv" | wc -l | tr -d ' ')
check "candidate collapses normalized variants to one key" 3 "$n_keys"

top_hits=$(awk -F '\t' 'NR==2 {print $1}' "$WORK/cand.tsv")
check "canonical key aggregates four variant hits" 4 "$top_hits"

top_ips=$(awk -F '\t' 'NR==2 {print $2}' "$WORK/cand.tsv")
check "distinct IPs counted across variants" 4 "$top_ips"

top_clusters=$(awk -F '\t' 'NR==2 {print $3}' "$WORK/cand.tsv")
check "distinct target clusters counted" 4 "$top_clusters"

"$TOOLS/candidate-rules.sh" --rules "$WORK/wave1.log" > "$WORK/cand.rules"
grep -qFx "https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor" "$WORK/cand.rules" \
    && echo "PASS --rules emits canonical full-URL rule" \
    || { echo "FAIL --rules output wrong" >&2; fail=1; }
grep -q '?' "$WORK/cand.rules" && { echo "FAIL rules contain query" >&2; fail=1; } \
    || echo "PASS rules contain no query string"

# --- replay ---------------------------------------------------------------
cat > "$WORK/rules" <<'RULES'
# full-URL rule
https://geek-doc.cn/nn/beginner/nn-b-01-neuron-perceptron-tensor
# path-only rule
/nn/beginner/nn-b-02
# path-only rule whose referer and target share one cluster (false-positive shape)
/chip-design
RULES

"$TOOLS/replay-rules.sh" -x /nn/ "$WORK/rules" "$WORK/wave1.log" "$WORK/wave2.log" > "$WORK/replay.txt"
cat "$WORK/replay.txt"

w1_block=$(sed -n '/wave1/,/wave2/p' "$WORK/replay.txt" | awk -F ': ' '/would block/ {print $2}' | awk '{print $1}')
check "wave1 blocks cross-cluster variants plus both path-only rules" 5 "$w1_block"

w1_same=$(sed -n '/wave1/,/wave2/p' "$WORK/replay.txt" | awk -F ': ' '/same-cluster blocks/ {print $2}' | awk '{print $1}')
check "wave1 flags one same-cluster block as false-positive indicator" 1 "$w1_same"

w1_excl=$(sed -n '/wave1/,/wave2/p' "$WORK/replay.txt" | awk -F ': ' '/pass \(excluded\)/ {print $2}' | awk '{print $1}')
check "wave1 same-cluster /nn/ request excluded" 1 "$w1_excl"

w1_noref=$(sed -n '/wave1/,/wave2/p' "$WORK/replay.txt" | awk -F ': ' '/no referer/ {print $2}' | awk '{print $1}')
check "wave1 missing referer passes" 1 "$w1_noref"

w1_malformed=$(sed -n '/wave1/,/wave2/p' "$WORK/replay.txt" | awk -F ': ' '/malformed/ {print $2}' | awk '{print $1}')
check "wave1 malformed referer fails open" 1 "$w1_malformed"

w2_block=$(sed -n '/wave2/,$p' "$WORK/replay.txt" | awk -F ': ' '/would block/ {print $2}' | awk '{print $1}')
check "wave2 blocks full and path-only rules" 2 "$w2_block"

w2_port=$(sed -n '/wave2/,$p' "$WORK/replay.txt" | grep -c '8443' || true)
check "wave2 non-default port does not match" 0 "$w2_port"

if [ "$fail" -ne 0 ]; then
    echo "OFFLINE TOOLS FAILED" >&2
    exit 1
fi
echo "OFFLINE TOOLS PASS"
