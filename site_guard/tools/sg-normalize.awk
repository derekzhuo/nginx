# Shared awk implementation of the module's Referer normalization.
# It must stay semantically identical to ngx_http_site_guard_normalize() in
# ngx_http_site_guard_module.c: lowercased scheme/host, query/fragment
# removal, trailing-slash collapse (root stays "/"), default-port stripping,
# path-only inputs, and an empty string result for malformed values.

function sg_lower(s) {
    return tolower(s)
}

# Returns the canonical string in SG_CANON and its path part in SG_PATH.
# Returns "" for malformed input (the module fails open on such values).
function sg_normalize(url,    p, scheme, rest, auth, host, port, path,
                      hp, bracket, q, i, c) {
    SG_CANON = ""
    SG_PATH = ""
    if (url == "" || url == "-") {
        return ""
    }

    p = index(url, "://")
    if (p == 0) {
        if (substr(url, 1, 1) != "/") {
            return ""
        }
        path = url
        return sg_path_only(path)
    }

    scheme = substr(url, 1, p - 1)
    if (length(scheme) == 0 || length(scheme) > 16) {
        return ""
    }
    rest = substr(url, p + 3)
    if (rest == "") {
        return ""
    }

    auth = rest
    for (i = 1; i <= length(rest); i++) {
        c = substr(rest, i, 1)
        if (c == "/" || c == "?" || c == "#") {
            auth = substr(rest, 1, i - 1)
            break
        }
    }
    if (auth == "") {
        return ""
    }

    host = auth
    port = ""
    if (substr(auth, 1, 1) == "[") {
        bracket = index(auth, "]")
        if (bracket == 0) {
            return ""
        }
        # Match the C behavior: host keeps the brackets, a port is parsed
        # only when the character after "]" is ":"; other trailing text is
        # ignored rather than treated as malformed input.
        host = substr(auth, 1, bracket)
        if (bracket < length(auth) && substr(auth, bracket + 1, 1) == ":") {
            port = substr(auth, bracket + 2)
        }
    } else {
        q = index(auth, ":")
        if (q != 0) {
            host = substr(auth, 1, q - 1)
            port = substr(auth, q + 1)
            if (host == "" || port == "") {
                return ""
            }
        }
    }

    if (port != "") {
        if ((scheme == "https" || scheme == "HTTPS") && port == "443") {
            port = ""
        } else if ((scheme == "http" || scheme == "HTTP") && port == "80") {
            port = ""
        }
    }

    i = index(rest, "/")
    q = index(rest, "?")
    p = index(rest, "#")
    if (i == 0 || (q != 0 && q < i) || (p != 0 && p < i)) {
        path = "/"
    } else {
        path = substr(rest, i)
    }

    path = sg_cut_path(path)
    host = tolower(host)
    scheme = tolower(scheme)
    SG_PATH = path
    SG_CANON = scheme "://" host (port != "" ? ":" port : "") path
    return SG_CANON
}

function sg_path_only(path) {
    path = sg_cut_path(path)
    SG_PATH = path
    SG_CANON = path
    return SG_CANON
}

# Strip query/fragment and collapse repeated trailing slashes, keeping "/".
function sg_cut_path(path,    i, c) {
    for (i = 1; i <= length(path); i++) {
        c = substr(path, i, 1)
        if (c == "?" || c == "#") {
            path = substr(path, 1, i - 1)
            break
        }
    }
    while (length(path) > 1 && substr(path, length(path), 1) == "/") {
        path = substr(path, 1, length(path) - 1)
    }
    if (path == "") {
        path = "/"
    }
    return path
}

# Extract the nth bare double-quoted field from an nginx combined log line.
# Nginx writes embedded quotes as \x22, so bare quotes only delimit fields.
function sg_quoted(line, n,    i, c, seen, buf, state) {
    seen = 0
    buf = ""
    state = 0
    for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (c == "\"") {
            if (state == 0) {
                state = 1
                seen++
                if (seen == n) {
                    buf = ""
                }
            } else {
                if (seen == n) {
                    return buf
                }
                state = 0
            }
        } else if (state == 1 && seen == n) {
            buf = buf c
        }
    }
    return ""
}

# First path segment of a request URI, used as the content-cluster key.
function sg_cluster(uri,    s, a) {
    sub(/\?.*$/, "", uri)
    if (uri == "" || substr(uri, 1, 1) != "/") {
        return "-"
    }
    s = substr(uri, 2)
    if (s == "") {
        return "/"
    }
    a = index(s, "/")
    if (a != 0) {
        s = substr(s, 1, a - 1)
    }
    return s == "" ? "/" : s
}
