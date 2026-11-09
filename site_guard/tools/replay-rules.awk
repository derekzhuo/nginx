# Offline replay program; requires sg-normalize.awk loaded first.
# Inputs: rules_file via -v, excluded prefixes via SG_EXCL environment value
# (newline-separated, because awk -v cannot carry raw newlines portably).
BEGIN {
    n_path = 0; n_full = 0
    while ((getline line < rules_file) > 0) {
        sub(/\r$/, "", line)
        if (line ~ /^[[:space:]]*($|#)/) { continue }
        if (sg_normalize(line) == "") {
            print "WARN skipped unnormalizable rule: " line > "/dev/stderr"
            continue
        }
        if (substr(line, 1, 1) == "/") {
            path_rules[++n_path] = SG_CANON
        } else {
            full_rules[SG_CANON] = 1
            n_full++
        }
    }
    close(rules_file)
    n_excl = split(ENVIRON["SG_EXCL"], excl_arr, "\n")
}

function is_excluded(uri,    i, p) {
    for (i = 1; i <= n_excl; i++) {
        p = excl_arr[i]
        if (p != "" && length(uri) >= length(p) && substr(uri, 1, length(p)) == p) {
            return 1
        }
    }
    return 0
}

{
    request = sg_quoted($0, 1)
    referer = sg_quoted($0, 2)
    if (request == "") { next }
    method = request
    sub(/ .*$/, "", method)
    if (method != "GET" && method != "HEAD") { next }
    total++

    if (referer == "" || referer == "-") { pass_noref++; next }
    uri = request
    sub(/^[^ ]+ /, "", uri)
    sub(/ HTTP\/[0-9.]+$/, "", uri)
    sub(/\?.*$/, "", uri)
    if (is_excluded(uri)) { pass_excluded++; next }
    if (sg_normalize(referer) == "") { pass_malformed++; next }

    matched = 0
    if (SG_CANON in full_rules) { matched = 1 }
    if (!matched) {
        for (i = 1; i <= n_path; i++) {
            if (path_rules[i] == SG_PATH) { matched = 1; break }
        }
    }

    if (matched) {
        blocked++
        blocked_ref[SG_CANON]++
        # Same-cluster navigation is the main false-positive shape:
        # the reader moves between pages inside one content cluster.
        if (sg_cluster(uri) == sg_cluster(SG_PATH) && sg_cluster(uri) != "-") {
            same_cluster++
            if (same_cluster <= 5) {
                same_samples[same_cluster] = sg_cluster(uri) " <= " SG_CANON
            }
        }
    } else {
        passed++
    }
}

END {
    printf "  total GET/HEAD:      %d\n", total
    printf "  would block:         %d\n", blocked
    printf "  pass (no referer):   %d\n", pass_noref
    printf "  pass (excluded):     %d\n", pass_excluded
    printf "  pass (malformed):    %d\n", pass_malformed
    printf "  pass (no rule hit):  %d\n", passed
    if (total > 0) {
        printf "  block ratio:         %.2f%%\n", 100.0 * blocked / total
    }
    printf "  same-cluster blocks: %d (false-positive indicator)\n", same_cluster + 0
    for (i = 1; i <= same_cluster && i <= 5; i++) {
        printf "    sample: %s\n", same_samples[i]
    }
    print "  top blocked referers:"
    n = 0
    for (k in blocked_ref) { print blocked_ref[k] "\t" k; n++ }
    if (n == 0) { print "    (none)" }
}
