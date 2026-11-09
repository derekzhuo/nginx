/*
 * Copyright (C) 2026 Derek Zhuo
 * Static-request guard for exact Referer and URI policies.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_site_guard_stats.h"

#define NGX_HTTP_SITE_GUARD_PASSED   0
#define NGX_HTTP_SITE_GUARD_MATCHED  1
#define NGX_HTTP_SITE_GUARD_DRY_RUN  2
#define NGX_HTTP_SITE_GUARD_DISABLED 3
#define NGX_HTTP_SITE_GUARD_SHADOW   0
#define NGX_HTTP_SITE_GUARD_ENFORCE  1
#define NGX_HTTP_SITE_GUARD_MAX_RULE_LEN 2048
#define NGX_HTTP_SITE_GUARD_MAX_FILE 131072
#define NGX_HTTP_SITE_GUARD_REFRESH 1000

typedef struct {
    ngx_flag_t    enabled;
    ngx_uint_t    mode;
    ngx_uint_t    status;
    ngx_array_t  *referers;
    ngx_array_t  *excluded_prefixes;
    ngx_str_t     rules_file;
    ngx_shm_zone_t *shm_zone;
} ngx_http_site_guard_loc_conf_t;

typedef struct {
    ngx_uint_t  status;
} ngx_http_site_guard_request_ctx_t;

static ngx_int_t ngx_http_site_guard_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_site_guard_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_site_guard_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_site_guard_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_site_guard_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_site_guard_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_site_guard_add_value(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_site_guard_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_site_guard_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_site_guard_refresh(ngx_http_request_t *r,
    ngx_http_site_guard_loc_conf_t *lrcf);
static ngx_uint_t ngx_http_site_guard_match(ngx_str_t *rule,
    ngx_str_t *referer, ngx_str_t *referer_path);
static ngx_int_t ngx_http_site_guard_normalize(ngx_pool_t *pool,
    ngx_str_t *input, ngx_str_t *canonical, ngx_str_t *path_part);

static ngx_conf_enum_t ngx_http_site_guard_modes[] = {
    { ngx_string("shadow"), NGX_HTTP_SITE_GUARD_SHADOW },
    { ngx_string("enforce"), NGX_HTTP_SITE_GUARD_ENFORCE },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_site_guard_commands[] = {
    { ngx_string("site_guard"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_site_guard_loc_conf_t, enabled), NULL },
    { ngx_string("site_guard_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_site_guard_loc_conf_t, mode),
      &ngx_http_site_guard_modes },
    { ngx_string("site_guard_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_site_guard_loc_conf_t, status), NULL },
    { ngx_string("site_guard_zone"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_site_guard_zone, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("site_guard_rules_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_site_guard_loc_conf_t, rules_file), NULL },
    { ngx_string("site_guard_referer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_site_guard_add_value, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_site_guard_loc_conf_t, referers), NULL },
    { ngx_string("site_guard_excluded_prefix"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_site_guard_add_value, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_site_guard_loc_conf_t, excluded_prefixes), NULL },
      ngx_null_command
};

static ngx_http_module_t ngx_http_site_guard_module_ctx = {
    ngx_http_site_guard_add_variables, ngx_http_site_guard_init,
    NULL, NULL, NULL, NULL,
    ngx_http_site_guard_create_loc_conf,
    ngx_http_site_guard_merge_loc_conf
};

ngx_module_t ngx_http_site_guard_module = {
    NGX_MODULE_V1, &ngx_http_site_guard_module_ctx,
    ngx_http_site_guard_commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_site_guard_vars[] = {
    { ngx_string("site_guard_status"), NULL, ngx_http_site_guard_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("site_guard_generation"), NULL, ngx_http_site_guard_variable,
      1, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("site_guard_referer_qpm"), NULL, ngx_http_site_guard_variable,
      2, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("site_guard_ua_qpm"), NULL, ngx_http_site_guard_variable,
      3, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("site_guard_path_qpm"), NULL, ngx_http_site_guard_variable,
      4, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("site_guard_referer_ips"), NULL, ngx_http_site_guard_variable,
      5, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("site_guard_once"), NULL, ngx_http_site_guard_variable, 6,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },
      ngx_http_null_variable
};

static ngx_str_t ngx_http_site_guard_status_names[] = {
    ngx_string("PASSED"), ngx_string("MATCHED"),
    ngx_string("MATCHED_DRY_RUN"), ngx_string("DISABLED")
};

static ngx_uint_t ngx_http_site_guard_once_index = NGX_CONF_UNSET_UINT;
static ngx_str_t ngx_http_site_guard_once_name = ngx_string("site_guard_once");

static ngx_int_t
ngx_http_site_guard_handler(ngx_http_request_t *r)
{
    ngx_uint_t                       i;
    ngx_str_t                        *prefix, *rule, referer;
    ngx_http_site_guard_loc_conf_t     *lrcf;
    ngx_http_site_guard_request_ctx_t  *rctx;
    ngx_http_variable_value_t        *vv;

    if (r != r->main || !(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }
    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_site_guard_module);
    rctx = ngx_http_get_module_ctx(r, ngx_http_site_guard_module);
    if (rctx == NULL) {
        rctx = ngx_pcalloc(r->pool, sizeof(ngx_http_site_guard_request_ctx_t));
        if (rctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, rctx, ngx_http_site_guard_module);
    }

    if (!lrcf->enabled) {
        rctx->status = NGX_HTTP_SITE_GUARD_DISABLED;
        return NGX_DECLINED;
    }
    vv = &r->variables[ngx_http_site_guard_once_index];
    if (!vv->valid) {
        ngx_http_site_guard_stats_record(r, lrcf->shm_zone);
        vv->valid = 1;
        vv->no_cacheable = 1;
        vv->not_found = 0;
        vv->len = 1;
        vv->data = (u_char *) "1";
    }
    if (r->headers_in.referer == NULL) {
        return NGX_DECLINED;
    }

    if (lrcf->excluded_prefixes != NULL) {
        prefix = lrcf->excluded_prefixes->elts;
        for (i = 0; i < lrcf->excluded_prefixes->nelts; i++) {
            if (r->uri.len >= prefix[i].len
                && ngx_strncmp(r->uri.data, prefix[i].data, prefix[i].len) == 0)
            {
                return NGX_DECLINED;
            }
        }
    }
    referer = r->headers_in.referer->value;

    {
        ngx_str_t  ref_canon, ref_path;

        if (ngx_http_site_guard_normalize(r->pool, &referer,
                                          &ref_canon, &ref_path)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }

        if (lrcf->shm_zone != NULL && lrcf->rules_file.len != 0) {
            ngx_http_site_guard_zone_ctx_t  *zctx;
            ngx_uint_t                       matched;

            (void) ngx_http_site_guard_refresh(r, lrcf);
            zctx = lrcf->shm_zone->data;
            matched = 0;

            ngx_shmtx_lock(&zctx->shpool->mutex);
            for (i = 0; i < zctx->sh->count; i++) {
                ngx_str_t  rrule;

                rrule.len = zctx->sh->rules[i].len;
                rrule.data = zctx->sh->rules[i].data;
                if (ngx_http_site_guard_match(&rrule, &ref_canon, &ref_path)) {
                    matched = 1;
                    break;
                }
            }
            ngx_shmtx_unlock(&zctx->shpool->mutex);

            if (matched) {
                goto matched;
            }
        }

        if (lrcf->referers != NULL) {
            rule = lrcf->referers->elts;
            for (i = 0; i < lrcf->referers->nelts; i++) {
                if (ngx_http_site_guard_match(&rule[i], &ref_canon,
                                              &ref_path))
                {
                    goto matched;
                }
            }
        }
    }

    return NGX_DECLINED;

matched:

    rctx->status = lrcf->mode == NGX_HTTP_SITE_GUARD_ENFORCE
                   ? NGX_HTTP_SITE_GUARD_MATCHED
                   : NGX_HTTP_SITE_GUARD_DRY_RUN;
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "site_guard matched uri=\"%V\" referer=\"%V\"%s",
                  &r->uri, &referer,
                  lrcf->mode == NGX_HTTP_SITE_GUARD_ENFORCE
                  ? "" : ", dry run");
    if (lrcf->mode == NGX_HTTP_SITE_GUARD_ENFORCE) {
        return lrcf->status;
    }
    return NGX_DECLINED;
}

/*
 * Canonicalize a rule or Referer value once, so matching is a byte compare.
 * Full-URL form: lowercased scheme and host, default port (https:443,
 * http:80) dropped, query/fragment removed, repeated trailing slashes
 * trimmed. Path-only form (begins with '/'): same path treatment.
 * Malformed input returns NGX_DECLINED; path_part points inside canonical at
 * the path for path-only rules.
 */
static ngx_int_t
ngx_http_site_guard_normalize(ngx_pool_t *pool, ngx_str_t *input,
    ngx_str_t *canonical, ngx_str_t *path_part)
{
    u_char  *p, *scheme_end = NULL, *rest, *auth_end, *host = NULL, *path,
            *out, *port = NULL;
    size_t   len, scheme_len = 0, host_len = 0, path_len, port_len = 0,
             copy_len;
    ngx_str_t scheme;

    if (input->len == 0) {
        return NGX_DECLINED;
    }

    p = ngx_strnstr(input->data, "://", input->len);

    if (p == NULL) {
        if (input->data[0] != '/') {
            return NGX_DECLINED;
        }

        path = input->data;
        path_len = input->len;
        goto path_only;
    }

    scheme_end = p;
    scheme.data = input->data;
    scheme_len = scheme_end - input->data;

    if (scheme_len == 0 || scheme_len > 16) {
        return NGX_DECLINED;
    }

    rest = scheme_end + 3;
    len = input->len - (size_t) (rest - input->data);
    if (len == 0) {
        return NGX_DECLINED;
    }

    auth_end = rest;
    while (auth_end < input->data + input->len
           && *auth_end != '/' && *auth_end != '?' && *auth_end != '#')
    {
        auth_end++;
    }

    if (auth_end == rest) {
        return NGX_DECLINED;
    }

    host = rest;
    host_len = (size_t) (auth_end - rest);
    port = NULL;
    port_len = 0;

    if (host[0] == '[') {
        p = ngx_strlchr(host, auth_end, ']');
        if (p == NULL) {
            return NGX_DECLINED;
        }
        if (p + 1 < auth_end && *(p + 1) == ':') {
            port = p + 2;
            port_len = (size_t) (auth_end - port);
            host_len = (size_t) (p + 1 - host);
        }
    } else {
        p = ngx_strlchr(host, auth_end, ':');
        if (p != NULL) {
            port = p + 1;
            port_len = (size_t) (auth_end - port);
            host_len = (size_t) (p - host);
            if (host_len == 0 || port_len == 0) {
                return NGX_DECLINED;
            }
        }
    }

    if (port_len != 0) {
        if ((scheme_len == 5
             && ngx_strncasecmp(scheme.data, (u_char *) "https", 5) == 0
             && port_len == 3 && ngx_strncmp(port, "443", 3) == 0)
            || (scheme_len == 4
                && ngx_strncasecmp(scheme.data, (u_char *) "http", 4) == 0
                && port_len == 2 && ngx_strncmp(port, "80", 2) == 0))
        {
            port_len = 0;
        }
    }

    path = auth_end;
    path_len = (size_t) (input->data + input->len - auth_end);
    if (path_len == 0 || path[0] != '/') {
        path = (u_char *) "/";
        path_len = 1;
    }

path_only:

    p = path;
    while (p < path + path_len && *p != '?' && *p != '#') {
        p++;
    }
    path_len = (size_t) (p - path);

    while (path_len > 1 && path[path_len - 1] == '/') {
        path_len--;
    }

    if (scheme_end == NULL) {
        out = ngx_palloc(pool, path_len);
        if (out == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(out, path, path_len);
        canonical->data = out;
        canonical->len = path_len;
        path_part->data = out;
        path_part->len = path_len;
        return NGX_OK;
    }

    copy_len = scheme_len + 3 + host_len + (port_len ? port_len + 1 : 0)
               + path_len;
    out = ngx_palloc(pool, copy_len);
    if (out == NULL) {
        return NGX_ERROR;
    }

    p = out;
    ngx_memcpy(p, scheme.data, scheme_len);
    ngx_strlow(p, p, scheme_len);
    p += scheme_len;
    ngx_memcpy(p, "://", 3);
    p += 3;
    ngx_memcpy(p, host, host_len);
    ngx_strlow(p, p, host_len);
    p += host_len;
    if (port_len) {
        *p++ = ':';
        ngx_memcpy(p, port, port_len);
        p += port_len;
    }
    ngx_memcpy(p, path, path_len);

    canonical->data = out;
    canonical->len = copy_len;
    path_part->data = p;
    path_part->len = path_len;
    return NGX_OK;
}

static ngx_uint_t
ngx_http_site_guard_match(ngx_str_t *rule, ngx_str_t *referer,
    ngx_str_t *referer_path)
{
    /* Path-only rules compare against the path part of the Referer. */
    if (rule->len > 0 && rule->data[0] == '/') {
        return rule->len == referer_path->len
               && ngx_strncmp(rule->data, referer_path->data, rule->len) == 0;
    }

    return rule->len == referer->len
           && ngx_strncmp(rule->data, referer->data, rule->len) == 0;
}

static ngx_int_t
ngx_http_site_guard_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    uintptr_t  status;

    if (data == 6) {
        v->valid = 0;
        v->no_cacheable = 1;
        v->not_found = 1;
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    if (data >= 2) {
        ngx_http_site_guard_loc_conf_t  *lrcf;

        lrcf = ngx_http_get_module_loc_conf(r, ngx_http_site_guard_module);
        return ngx_http_site_guard_stats_variable(r, v, data, lrcf->shm_zone);
    }

    if (data == 1) {
        ngx_uint_t                       generation;
        ngx_http_site_guard_loc_conf_t  *lrcf;
        ngx_http_site_guard_zone_ctx_t  *zctx;

        generation = 0;
        lrcf = ngx_http_get_module_loc_conf(r, ngx_http_site_guard_module);
        if (lrcf->shm_zone != NULL) {
            zctx = lrcf->shm_zone->data;
            ngx_shmtx_lock(&zctx->shpool->mutex);
            generation = zctx->sh->generation;
            ngx_shmtx_unlock(&zctx->shpool->mutex);
        }

        v->data = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        v->len = ngx_sprintf(v->data, "%ui", generation) - v->data;
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        return NGX_OK;
    }

    {
        ngx_http_site_guard_request_ctx_t  *rctx;

        rctx = ngx_http_get_module_ctx(r->main, ngx_http_site_guard_module);
        status = rctx == NULL ? NGX_HTTP_SITE_GUARD_PASSED : rctx->status;
    }
    if (status > NGX_HTTP_SITE_GUARD_DISABLED) {
        status = NGX_HTTP_SITE_GUARD_PASSED;
    }
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = ngx_http_site_guard_status_names[status].len;
    v->data = ngx_http_site_guard_status_names[status].data;
    return NGX_OK;
}

static void *
ngx_http_site_guard_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_site_guard_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_site_guard_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enabled = NGX_CONF_UNSET;
    conf->mode = NGX_CONF_UNSET_UINT;
    conf->status = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *
ngx_http_site_guard_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_site_guard_loc_conf_t  *prev = parent;
    ngx_http_site_guard_loc_conf_t  *conf = child;
    ngx_uint_t                       i;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_uint_value(conf->mode, prev->mode,
                              NGX_HTTP_SITE_GUARD_SHADOW);
    ngx_conf_merge_uint_value(conf->status, prev->status, 403);
    if (conf->status < 400 || conf->status > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "site_guard_status must be between 400 and 599");
        return NGX_CONF_ERROR;
    }
    if (conf->referers == NULL) {
        conf->referers = prev->referers;
    } else {
        ngx_array_t  *norm;
        ngx_str_t    *items, *item, canonical, cpath;

        items = conf->referers->elts;
        norm = ngx_array_create(cf->pool, conf->referers->nelts,
                                sizeof(ngx_str_t));
        if (norm == NULL) {
            return NGX_CONF_ERROR;
        }
        for (i = 0; i < conf->referers->nelts; i++) {
            if (ngx_http_site_guard_normalize(cf->pool, &items[i],
                                              &canonical, &cpath) != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "site_guard_referer has invalid value "
                                   "\"%V\"", &items[i]);
                return NGX_CONF_ERROR;
            }
            item = ngx_array_push(norm);
            if (item == NULL) {
                return NGX_CONF_ERROR;
            }
            *item = canonical;
        }
        conf->referers = norm;
    }
    if (conf->excluded_prefixes == NULL) {
        conf->excluded_prefixes = prev->excluded_prefixes;
    }
    ngx_conf_merge_str_value(conf->rules_file, prev->rules_file, "");
    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }
    if (conf->rules_file.len != 0 && conf->shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "site_guard_rules_file requires site_guard_zone");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_site_guard_add_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *p = conf;
    ngx_str_t   *value, *item;
    ngx_array_t **array;

    value = cf->args->elts;
    array = (ngx_array_t **) (p + cmd->offset);
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty value in \"%V\" directive", &cmd->name);
        return NGX_CONF_ERROR;
    }
    if (*array == NULL) {
        *array = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (*array == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    item = ngx_array_push(*array);
    if (item == NULL) {
        return NGX_CONF_ERROR;
    }
    *item = value[1];
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_site_guard_refresh(ngx_http_request_t *r,
    ngx_http_site_guard_loc_conf_t *lrcf)
{
    off_t                             file_size;
    time_t                            mtime;
    size_t                            size;
    ssize_t                           n;
    ngx_err_t                         err;
    ngx_file_t                        file;
    ngx_file_info_t                   fi;
    ngx_file_uniq_t                   uniq;
    ngx_msec_t                        now;
    ngx_uint_t                        count, i, j;
    u_char                           *base, *p, *end, *line, *start, *stop;
    u_char                           *allocated[NGX_HTTP_SITE_GUARD_MAX_RULES];
    ngx_http_site_guard_shrule_t      parsed[NGX_HTTP_SITE_GUARD_MAX_RULES];
    ngx_http_site_guard_zone_ctx_t   *zctx;

    zctx = lrcf->shm_zone->data;
    now = ngx_current_msec;

    ngx_shmtx_lock(&zctx->shpool->mutex);
    if (zctx->sh->last_check != 0
        && (ngx_msec_int_t) (now - zctx->sh->last_check)
           < NGX_HTTP_SITE_GUARD_REFRESH)
    {
        ngx_shmtx_unlock(&zctx->shpool->mutex);
        return NGX_OK;
    }
    zctx->sh->last_check = now;
    if (zctx->sh->loading) {
        ngx_shmtx_unlock(&zctx->shpool->mutex);
        return NGX_OK;
    }
    ngx_shmtx_unlock(&zctx->shpool->mutex);

    if (ngx_file_info(lrcf->rules_file.data, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
                      "site_guard cannot stat rules \"%V\"", &lrcf->rules_file);
        return NGX_ERROR;
    }

    mtime = ngx_file_mtime(&fi);
    file_size = ngx_file_size(&fi);
    uniq = ngx_file_uniq(&fi);

    ngx_shmtx_lock(&zctx->shpool->mutex);
    if (zctx->sh->loading) {
        ngx_shmtx_unlock(&zctx->shpool->mutex);
        return NGX_OK;
    }
    if (zctx->sh->generation != 0
        && zctx->sh->mtime == mtime && zctx->sh->size == file_size
        && zctx->sh->uniq == uniq)
    {
        ngx_shmtx_unlock(&zctx->shpool->mutex);
        return NGX_OK;
    }
    zctx->sh->loading = 1;
    ngx_shmtx_unlock(&zctx->shpool->mutex);

    if (file_size < 0 || file_size > NGX_HTTP_SITE_GUARD_MAX_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "site_guard rules \"%V\" exceed size limit",
                      &lrcf->rules_file);
        goto failed;
    }

    size = (size_t) file_size;
    base = ngx_palloc(r->pool, size == 0 ? 1 : size);
    if (base == NULL) {
        goto failed;
    }

    ngx_memzero(&file, sizeof(file));
    file.name = lrcf->rules_file;
    file.log = r->connection->log;
    file.fd = ngx_open_file(lrcf->rules_file.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
                      "site_guard cannot open rules \"%V\"", &lrcf->rules_file);
        goto failed;
    }

    n = ngx_read_file(&file, base, size, 0);
    err = ngx_errno;
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
                      "site_guard cannot close rules \"%V\"", &lrcf->rules_file);
    }
    if (n == NGX_ERROR || n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                      "site_guard cannot read rules \"%V\"", &lrcf->rules_file);
        goto failed;
    }

    count = 0;
    p = base;
    end = base + size;

    while (p < end) {
        line = p;
        while (p < end && *p != '\n') {
            p++;
        }
        start = line;
        stop = p;
        if (p < end) {
            p++;
        }
        while (start < stop && (*start == ' ' || *start == '\t')) {
            start++;
        }
        while (stop > start
               && (stop[-1] == '\r' || stop[-1] == ' ' || stop[-1] == '\t'))
        {
            stop--;
        }
        if (start == stop || *start == '#') {
            continue;
        }
        if ((size_t) (stop - start) > NGX_HTTP_SITE_GUARD_MAX_RULE_LEN
            || count >= NGX_HTTP_SITE_GUARD_MAX_RULES)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "site_guard rules \"%V\" exceed rule limits",
                          &lrcf->rules_file);
            goto failed;
        }
        parsed[count].data = start;
        parsed[count].len = stop - start;
        count++;
    }

    for (i = 0; i < count; i++) {
        ngx_str_t  raw, canonical, cpath;

        raw.len = parsed[i].len;
        raw.data = parsed[i].data;
        if (ngx_http_site_guard_normalize(r->pool, &raw,
                                          &canonical, &cpath) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "site_guard invalid rule \"%V\" in \"%V\"",
                          &raw, &lrcf->rules_file);
            goto failed;
        }
        parsed[i].len = canonical.len;
        parsed[i].data = canonical.data;
    }

    ngx_shmtx_lock(&zctx->shpool->mutex);
    for (i = 0; i < count; i++) {
        allocated[i] = ngx_slab_alloc_locked(zctx->shpool, parsed[i].len);
        if (allocated[i] == NULL) {
            for (j = 0; j < i; j++) {
                ngx_slab_free_locked(zctx->shpool, allocated[j]);
            }
            ngx_shmtx_unlock(&zctx->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "site_guard zone is full while loading \"%V\"",
                          &lrcf->rules_file);
            goto failed;
        }
        ngx_memcpy(allocated[i], parsed[i].data, parsed[i].len);
    }

    for (i = 0; i < zctx->sh->count; i++) {
        ngx_slab_free_locked(zctx->shpool, zctx->sh->rules[i].data);
    }
    for (i = 0; i < count; i++) {
        zctx->sh->rules[i].data = allocated[i];
        zctx->sh->rules[i].len = parsed[i].len;
    }
    zctx->sh->count = count;
    zctx->sh->generation++;
    zctx->sh->mtime = mtime;
    zctx->sh->size = file_size;
    zctx->sh->uniq = uniq;
    zctx->sh->loading = 0;
    j = zctx->sh->generation;
    ngx_shmtx_unlock(&zctx->shpool->mutex);

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "site_guard loaded %ui rules, generation %ui", count, j);
    return NGX_OK;

failed:

    ngx_shmtx_lock(&zctx->shpool->mutex);
    zctx->sh->mtime = mtime;
    zctx->sh->size = file_size;
    zctx->sh->uniq = uniq;
    zctx->sh->loading = 0;
    ngx_shmtx_unlock(&zctx->shpool->mutex);
    return NGX_ERROR;
}

static char *
ngx_http_site_guard_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_http_site_guard_loc_conf_t  *lrcf = conf;
    ssize_t                          size;
    ngx_str_t                       *value;
    ngx_http_site_guard_zone_ctx_t  *ctx;

    if (lrcf->shm_zone != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR || size < 65536) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "site_guard_zone size must be at least 64k");
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_site_guard_zone_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    lrcf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
                                           &ngx_http_site_guard_module);
    if (lrcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    if (lrcf->shm_zone->data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "site_guard_zone \"%V\" is already bound", &value[1]);
        return NGX_CONF_ERROR;
    }

    lrcf->shm_zone->init = ngx_http_site_guard_init_zone;
    lrcf->shm_zone->data = ctx;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_site_guard_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_site_guard_zone_ctx_t  *octx = data;
    ngx_http_site_guard_zone_ctx_t  *ctx = shm_zone->data;

    if (octx != NULL) {
        ctx->shpool = octx->shpool;
        ctx->sh = octx->sh;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool,
                             sizeof(ngx_http_site_guard_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(ctx->sh, sizeof(ngx_http_site_guard_shctx_t));
    ngx_http_site_guard_stats_init(ctx->sh);
    ctx->shpool->data = ctx->sh;
    return NGX_OK;
}

static ngx_int_t
ngx_http_site_guard_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_site_guard_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    ngx_http_site_guard_once_index = ngx_http_get_variable_index(cf,
        &ngx_http_site_guard_once_name);
    if (ngx_http_site_guard_once_index == (ngx_uint_t) NGX_ERROR) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_site_guard_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_site_guard_handler;
    return NGX_OK;
}
