# Site Guard module

`ngx_http_site_guard_module` is an access-phase HTTP module for exact
Referer policies on static sites. It does not modify the Nginx core.

This is the M2 implementation: configuration-driven matching, shadow mode,
enforce mode, shared-memory runtime rules, and bounded behavior statistics.
Automatic enforcement from statistical signals is intentionally disabled.

## Directives

```nginx
site_guard on;
site_guard_mode shadow;              # shadow (default) or enforce
site_guard_status 403;               # 400-599, including 444
site_guard_referer https://example.com/source/page;
site_guard_referer https://example.com/source/other;
site_guard_excluded_prefix /source/;
```

- Directives inherit through `http`, `server`, and `location` scopes.
- Matching is limited to main GET and HEAD requests.
- Referer matching uses the complete value; one trailing slash is optional.
- URI exclusions use Nginx's normalized `r->uri`.
- A match returns `site_guard_status` in enforce mode and continues without
  changing the response in shadow mode.
- Every match is logged at notice level. Do not enable this M0 implementation
  on a high-volume production rule without evaluating log volume.

The `$site_guard_status` variable is `PASSED`, `MATCHED`,
`MATCHED_DRY_RUN`, or `DISABLED`. `$site_guard_generation` reports the current
runtime-rule generation, or zero when no shared zone is configured.

## Runtime rules

Configure a shared zone and a local rule file:

```nginx
site_guard_zone site_guard 1m;
site_guard_rules_file /data/site-guard/referers.rules;
```

The file contains one complete Referer per line. Blank lines and lines beginning
with `#` are ignored. M1 accepts at most 64 rules, 2048 bytes per rule, and
131072 bytes per file.

Replace the file atomically so its inode changes:

```bash
cp referers.rules /data/site-guard/referers.rules.tmp
# Edit referers.rules.tmp, then publish it in one operation.
mv /data/site-guard/referers.rules.tmp /data/site-guard/referers.rules
```

One worker checks the file at most once per second. A changed file is parsed
completely before the shared generation is replaced. Workers keep using the
previous generation if reading, parsing, or allocation fails. An empty valid
file clears runtime rules. Static `site_guard_referer` directives remain active
independently.

No Nginx reload is required. Runtime files must be local, and their parent
directory must be writable only by trusted operators.

## Behavior statistics

A configured shared zone also aggregates enabled main requests by complete
Referer, User-Agent, and the first URI path segment. Referer and User-Agent keys
are capped at 255 bytes. Statistics use at most 256 nodes with least-recently-used
eviction and linear lookup. This deliberately simple index is suitable for M2
validation; it needs a performance review before increasing the capacity.

Thirty 10-second buckets retain request counts for approximately five minutes.
The `*_qpm` variables sum buckets from the latest 60 seconds. Approximate unique
IPs use 64-register HyperLogLog with a small-range linear-count correction over
a five-minute tumbling window.

```nginx
log_format guard "$pid $status $site_guard_referer_qpm "
                 "$site_guard_ua_qpm $site_guard_path_qpm "
                 "$site_guard_referer_ips";
```

- `site_guard_referer_qpm`: requests for the current Referer;
- `site_guard_ua_qpm`: requests for the current User-Agent;
- `site_guard_path_qpm`: requests for the current first path segment;
- `site_guard_referer_ips`: approximate distinct client IPs for the Referer.

Missing dimensions report zero. Statistics are observability signals only: they
must not be interpreted as proof that an individual request is malicious.

## Isolated build

Use the same Nginx release as the target runtime. Do not load a module built
from another release into a production binary.

```bash
auto/configure \
  --prefix=/tmp/site-guard-build \
  --add-module=./site_guard
make -j1
```

The resulting binary is `objs/nginx`. Installation is not required for
isolated tests.

## Isolated smoke test

Create a temporary prefix with a minimal `conf/nginx.conf`:

```nginx
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 64; }
http {
    access_log logs/access.log combined;
    site_guard on;
    site_guard_mode enforce;
    site_guard_status 403;
    site_guard_referer https://example.com/nn/beginner/nn-b-01;
    site_guard_excluded_prefix /nn/;
    server {
        listen 18089;
        root html;
    }
}
```

Run the test binary with that private prefix and verify:

```bash
# Excluded URI: 200
curl -i -e https://example.com/nn/beginner/nn-b-01 \
  http://127.0.0.1:18089/nn/beginner/nn-b-01

# Matched Referer outside the excluded prefix: 403
curl -i -e https://example.com/nn/beginner/nn-b-01 \
  http://127.0.0.1:18089/chip-design/

# Unmatched Referer: normal response
curl -i -e https://example.com/other \
  http://127.0.0.1:18089/chip-design/
```

Production installation, configuration changes, and process replacement are
outside this module's build and smoke-test procedure.
