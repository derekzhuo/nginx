# Site Guard module

`ngx_http_site_guard_module` is an access-phase HTTP module for exact
Referer policies on static sites. It does not modify the Nginx core.

This is the M0 implementation: configuration-driven matching, shadow mode,
enforce mode, and a logging variable. Runtime rule updates and shared-memory
behavior aggregation are intentionally left for later milestones.

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
`MATCHED_DRY_RUN`, or `DISABLED`.

## Isolated build

Use the same Nginx release as the target runtime. Do not load a module built
from another release into a production binary.

```bash
./configure \
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
