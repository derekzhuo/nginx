#ifndef _NGX_HTTP_SITE_GUARD_STATS_H_INCLUDED_
#define _NGX_HTTP_SITE_GUARD_STATS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SITE_GUARD_MAX_RULES 64
#define NGX_HTTP_SITE_GUARD_STATS_BUCKETS 30
#define NGX_HTTP_SITE_GUARD_STATS_BUCKET_MSEC 10000
#define NGX_HTTP_SITE_GUARD_STATS_MAX_NODES 256
#define NGX_HTTP_SITE_GUARD_STATS_HLL_REGISTERS 64

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_http_site_guard_shrule_t;

typedef struct {
    ngx_msec_t    start;
    ngx_uint_t    count;
} ngx_http_site_guard_bucket_t;

typedef struct {
    u_char                         color;
    u_char                         type;
    u_short                        len;
    ngx_queue_t                    queue;
    ngx_msec_t                     hll_start;
    u_char                         hll[NGX_HTTP_SITE_GUARD_STATS_HLL_REGISTERS];
    ngx_http_site_guard_bucket_t   buckets[NGX_HTTP_SITE_GUARD_STATS_BUCKETS];
    u_char                         data[1];
} ngx_http_site_guard_stat_node_t;

typedef struct {
    ngx_rbtree_t                   rbtree;
    ngx_rbtree_node_t              sentinel;
    ngx_queue_t                    queue;
    ngx_uint_t                     nodes;
    ngx_uint_t                     generation;
    ngx_uint_t                     count;
    ngx_uint_t                     loading;
    ngx_msec_t                     last_check;
    time_t                         mtime;
    off_t                          size;
    ngx_file_uniq_t                uniq;
    ngx_http_site_guard_shrule_t   rules[NGX_HTTP_SITE_GUARD_MAX_RULES];
} ngx_http_site_guard_shctx_t;

typedef struct {
    ngx_slab_pool_t                *shpool;
    ngx_http_site_guard_shctx_t    *sh;
} ngx_http_site_guard_zone_ctx_t;

void ngx_http_site_guard_stats_init(ngx_http_site_guard_shctx_t *sh);
void ngx_http_site_guard_stats_record(ngx_http_request_t *r,
    ngx_shm_zone_t *shm_zone);
ngx_int_t ngx_http_site_guard_stats_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data, ngx_shm_zone_t *shm_zone);

#endif
