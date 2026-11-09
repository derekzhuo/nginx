# Candidate-rule extraction program; requires sg-normalize.awk loaded first.
# Inputs: mode ("report"|"rules"), min_hits via -v.
function host_of(canon,    rest, i, c) {
    rest = substr(canon, index(canon, "://") + 3)
    for (i = 1; i <= length(rest); i++) {
        c = substr(rest, i, 1)
        if (c == "/" || c == "?" || c == "#") {
            return substr(rest, 1, i - 1)
        }
    }
    return rest
}

{
    ip = $1
    request = sg_quoted($0, 1)
    referer = sg_quoted($0, 2)
    if (request == "" || referer == "" || referer == "-") {
        next
    }
    method = request
    sub(/ .*$/, "", method)
    if (method != "GET" && method != "HEAD") {
        next
    }
    uri = request
    sub(/^[^ ]+ /, "", uri)
    sub(/ HTTP\/[0-9.]+$/, "", uri)

    if (sg_normalize(referer) == "") {
        next
    }
    key = SG_CANON
    hits[key]++
    ip_seen[key SUBSEP ip] = 1
    cl_seen[key SUBSEP sg_cluster(uri)] = 1
    ho_seen[key SUBSEP host_of(key)] = 1
}

END {
    for (k in hits) {
        if (hits[k] < min_hits) {
            continue
        }
        d_ip = 0; d_cl = 0; d_ho = 0
        prefix = k SUBSEP
        plen = length(prefix)
        for (combo in ip_seen) {
            if (substr(combo, 1, plen) == prefix) { d_ip++ }
        }
        for (combo in cl_seen) {
            if (substr(combo, 1, plen) == prefix) { d_cl++ }
        }
        for (combo in ho_seen) {
            if (substr(combo, 1, plen) == prefix) { d_ho++ }
        }
        if (mode == "rules") {
            # site-guard-ctl rejects whitespace; normalized URLs still carry
            # any literal space that appeared inside the path component.
            if (index(k, " ") == 0 && index(k, "\t") == 0) {
                print hits[k] "\t" k
            }
        } else {
            print hits[k] "\t" d_ip "\t" d_cl "\t" d_ho "\t" k
        }
    }
}
