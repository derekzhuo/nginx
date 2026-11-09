/*
 * Copyright (C) 2026 Derek Zhuo
 * Static-request guard for exact Referer and URI policies.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SITE_GUARD_PASSED   0
#define NGX_HTTP_SITE_GUARD_MATCHED  1
#define NGX_HTTP_SITE_GUARD_DRY_RUN  2
#define NGX_HTTP_SITE_GUARD_DISABLED 3
#define NGX_HTTP_SITE_GUARD_SHADOW   0
#define NGX_HTTP_SITE_GUARD_ENFORCE  1

typedef struct {
    ngx_flag_t    enabled;
    ngx_uint_t    mode;
    ngx_uint_t    status;
    ngx_array_t  *referers;
    ngx_array_t  *excluded_prefixes;
} ngx_http_site_guard_loc_conf_t;

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
      ngx_http_null_variable
};

static ngx_str_t ngx_http_site_guard_status_names[] = {
    ngx_string("PASSED"), ngx_string("MATCHED"),
    ngx_string("MATCHED_DRY_RUN"), ngx_string("DISABLED")
};

static ngx_int_t
ngx_http_site_guard_handler(ngx_http_request_t *r)
{
    ngx_uint_t                       i;
    ngx_str_t                       *prefix, *rule, referer;
    ngx_http_site_guard_loc_conf_t  *lrcf;

    if (r != r->main || !(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }
    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_site_guard_module);
    if (!lrcf->enabled) {
        ngx_http_set_ctx(r, (void *) NGX_HTTP_SITE_GUARD_DISABLED,
                         ngx_http_site_guard_module);
        return NGX_DECLINED;
    }
    ngx_http_set_ctx(r, (void *) NGX_HTTP_SITE_GUARD_PASSED,
                     ngx_http_site_guard_module);
    if (r->headers_in.referer == NULL || lrcf->referers == NULL) {
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
    rule = lrcf->referers->elts;

    for (i = 0; i < lrcf->referers->nelts; i++) {
        size_t  rule_len, referer_len;

        rule_len = rule[i].len;
        referer_len = referer.len;
        if (rule_len > 1 && rule[i].data[rule_len - 1] == '/') {
            rule_len--;
        }
        if (referer_len > 1 && referer.data[referer_len - 1] == '/') {
            referer_len--;
        }
        if (rule_len == referer_len
            && ngx_strncmp(rule[i].data, referer.data, rule_len) == 0)
        {
            ngx_http_set_ctx(r,
                             lrcf->mode == NGX_HTTP_SITE_GUARD_ENFORCE
                             ? (void *) NGX_HTTP_SITE_GUARD_MATCHED
                             : (void *) NGX_HTTP_SITE_GUARD_DRY_RUN,
                             ngx_http_site_guard_module);
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
    }
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_site_guard_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    uintptr_t  status;

    status = (uintptr_t) ngx_http_get_module_ctx(r->main,
                                                 ngx_http_site_guard_module);
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
    }
    if (conf->excluded_prefixes == NULL) {
        conf->excluded_prefixes = prev->excluded_prefixes;
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
ngx_http_site_guard_add_variables(ngx_conf_t *cf)
{
    return ngx_http_add_variables(cf, ngx_http_site_guard_vars,
                                  NGX_HTTP_VAR_CHANGEABLE);
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
