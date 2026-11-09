#include "ngx_http_site_guard_stats.h"

#define NGX_HTTP_SITE_GUARD_STAT_REFERER 1
#define NGX_HTTP_SITE_GUARD_STAT_UA      2
#define NGX_HTTP_SITE_GUARD_STAT_PATH    3
#define NGX_HTTP_SITE_GUARD_STAT_KEY_MAX 255

static const ngx_uint_t ngx_http_site_guard_linear_count[65] = {
    0, 266, 222, 196, 177, 163, 151, 142, 133, 126, 119, 113, 107,
    102, 97, 93, 89, 85, 81, 78, 74, 71, 68, 65, 63, 60, 58, 55,
    53, 51, 48, 46, 44, 42, 40, 39, 37, 35, 33, 32, 30, 28, 27, 25,
    24, 23, 21, 20, 18, 17, 16, 15, 13, 12, 11, 10, 9, 7, 6, 5, 4,
    3, 2, 1, 0
};

static uint64_t
ngx_http_site_guard_hash64(u_char *data, size_t len)
{
    uint64_t  hash;
    size_t    i;

    hash = 14695981039346656037ULL;
    for (i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void
ngx_http_site_guard_stats_init(ngx_http_site_guard_shctx_t *sh)
{
    ngx_queue_init(&sh->queue);
}

static ngx_http_site_guard_stat_node_t *
ngx_http_site_guard_stats_lookup_locked(ngx_http_site_guard_shctx_t *sh,
    ngx_uint_t type, ngx_str_t *key)
{
    ngx_queue_t                      *q;
    ngx_http_site_guard_stat_node_t  *sn;

    for (q = ngx_queue_head(&sh->queue);
         q != &sh->queue;
         q = ngx_queue_next(q))
    {
        sn = ngx_queue_data(q, ngx_http_site_guard_stat_node_t, queue);
        if (sn->type == type && sn->len == key->len
            && ngx_strncmp(sn->data, key->data, key->len) == 0)
        {
            return sn;
        }
    }
    return NULL;
}

static void
ngx_http_site_guard_stats_hll(ngx_http_site_guard_stat_node_t *sn,
    ngx_http_request_t *r, ngx_msec_t now)
{
    uint64_t  hash, bit;
    ngx_uint_t index, rank;

    if ((ngx_msec_int_t) (now - sn->hll_start) >= 300000) {
        ngx_memzero(sn->hll, sizeof(sn->hll));
        sn->hll_start = now;
    }
    hash = ngx_http_site_guard_hash64(r->connection->addr_text.data,
                                     r->connection->addr_text.len);
    index = hash & 63;
    rank = 1;
    for (bit = 1ULL << 63; (hash & bit) == 0 && rank <= 57; bit >>= 1) {
        rank++;
    }
    if (rank > sn->hll[index]) {
        sn->hll[index] = (u_char) rank;
    }
}

static void
ngx_http_site_guard_stats_evict_locked(ngx_http_site_guard_zone_ctx_t *zctx)
{
    ngx_queue_t                      *q;
    ngx_http_site_guard_stat_node_t  *sn;

    if (zctx->sh->nodes == 0) {
        return;
    }
    q = ngx_queue_last(&zctx->sh->queue);
    sn = ngx_queue_data(q, ngx_http_site_guard_stat_node_t, queue);
    ngx_queue_remove(q);
    ngx_slab_free_locked(zctx->shpool, sn);
    zctx->sh->nodes--;
}

static void
ngx_http_site_guard_stats_update_locked(ngx_http_site_guard_zone_ctx_t *zctx,
    ngx_uint_t type, ngx_str_t *key, ngx_http_request_t *r, ngx_msec_t now)
{
    size_t                            size, slot;
    ngx_http_site_guard_stat_node_t  *sn;

    sn = ngx_http_site_guard_stats_lookup_locked(zctx->sh, type, key);

    if (sn == NULL) {
        size = offsetof(ngx_http_site_guard_stat_node_t, data) + key->len;
        if (zctx->sh->nodes >= NGX_HTTP_SITE_GUARD_STATS_MAX_NODES) {
            ngx_http_site_guard_stats_evict_locked(zctx);
        }
        sn = ngx_slab_alloc_locked(zctx->shpool, size);
        if (sn == NULL && zctx->sh->nodes != 0) {
            ngx_http_site_guard_stats_evict_locked(zctx);
            sn = ngx_slab_alloc_locked(zctx->shpool, size);
        }
        if (sn == NULL) {
            return;
        }
        ngx_memzero(sn, size);
        sn->type = (u_char) type;
        sn->len = (u_short) key->len;
        sn->hll_start = now;
        ngx_queue_init(&sn->queue);
        ngx_memcpy(sn->data, key->data, key->len);
        zctx->sh->nodes++;
    }

    ngx_queue_remove(&sn->queue);
    ngx_queue_insert_head(&zctx->sh->queue, &sn->queue);
    slot = (now / NGX_HTTP_SITE_GUARD_STATS_BUCKET_MSEC)
           % NGX_HTTP_SITE_GUARD_STATS_BUCKETS;
    if (sn->buckets[slot].start
        != now - now % NGX_HTTP_SITE_GUARD_STATS_BUCKET_MSEC)
    {
        sn->buckets[slot].start = now - now % NGX_HTTP_SITE_GUARD_STATS_BUCKET_MSEC;
        sn->buckets[slot].count = 0;
    }
    sn->buckets[slot].count++;
    ngx_http_site_guard_stats_hll(sn, r, now);
}

void
ngx_http_site_guard_stats_record(ngx_http_request_t *r,
    ngx_shm_zone_t *shm_zone)
{
    ngx_str_t                       key;
    ngx_msec_t                      now;
    ngx_http_site_guard_zone_ctx_t  *zctx;

    if (shm_zone == NULL) {
        return;
    }
    zctx = shm_zone->data;
    now = ngx_current_msec;
    ngx_shmtx_lock(&zctx->shpool->mutex);

    if (r->headers_in.referer != NULL) {
        key = r->headers_in.referer->value;
        if (key.len > NGX_HTTP_SITE_GUARD_STAT_KEY_MAX) {
            key.len = NGX_HTTP_SITE_GUARD_STAT_KEY_MAX;
        }
        ngx_http_site_guard_stats_update_locked(zctx,
            NGX_HTTP_SITE_GUARD_STAT_REFERER, &key, r, now);
    }
    if (r->headers_in.user_agent != NULL) {
        key = r->headers_in.user_agent->value;
        if (key.len > NGX_HTTP_SITE_GUARD_STAT_KEY_MAX) {
            key.len = NGX_HTTP_SITE_GUARD_STAT_KEY_MAX;
        }
        ngx_http_site_guard_stats_update_locked(zctx,
            NGX_HTTP_SITE_GUARD_STAT_UA, &key, r, now);
    }
    if (r->uri.len > 1 && r->uri.data[0] == '/') {
        key.data = r->uri.data;
        key.len = 1;
        while (key.len < r->uri.len && r->uri.data[key.len] != '/') {
            key.len++;
        }
        if (key.len < r->uri.len) {
            key.len++;
        }
        ngx_http_site_guard_stats_update_locked(zctx,
            NGX_HTTP_SITE_GUARD_STAT_PATH, &key, r, now);
    }
    ngx_shmtx_unlock(&zctx->shpool->mutex);
}

static ngx_uint_t
ngx_http_site_guard_stats_key(ngx_http_request_t *r, ngx_uint_t type,
    ngx_str_t *key)
{
    if (type == NGX_HTTP_SITE_GUARD_STAT_REFERER) {
        if (r->headers_in.referer == NULL) {
            return 0;
        }
        *key = r->headers_in.referer->value;
    } else if (type == NGX_HTTP_SITE_GUARD_STAT_UA) {
        if (r->headers_in.user_agent == NULL) {
            return 0;
        }
        *key = r->headers_in.user_agent->value;
    } else {
        if (r->uri.len <= 1 || r->uri.data[0] != '/') {
            return 0;
        }
        key->data = r->uri.data;
        key->len = 1;
        while (key->len < r->uri.len && r->uri.data[key->len] != '/') {
            key->len++;
        }
        if (key->len < r->uri.len) {
            key->len++;
        }
        return 1;
    }
    if (key->len > NGX_HTTP_SITE_GUARD_STAT_KEY_MAX) {
        key->len = NGX_HTTP_SITE_GUARD_STAT_KEY_MAX;
    }
    return 1;
}

ngx_int_t
ngx_http_site_guard_stats_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data, ngx_shm_zone_t *shm_zone)
{
    double                            estimate, sum;
    ngx_uint_t                        i, type, value, zeros;
    ngx_str_t                         key;
    ngx_msec_t                        now;
    ngx_http_site_guard_zone_ctx_t  *zctx;
    ngx_http_site_guard_stat_node_t  *sn;

    value = 0;
    if (shm_zone == NULL) {
        goto done;
    }

    type = data == 3 ? NGX_HTTP_SITE_GUARD_STAT_UA
           : data == 4 ? NGX_HTTP_SITE_GUARD_STAT_PATH
           : NGX_HTTP_SITE_GUARD_STAT_REFERER;
    if (!ngx_http_site_guard_stats_key(r, type, &key)) {
        goto done;
    }

    zctx = shm_zone->data;
    now = ngx_current_msec;

    ngx_shmtx_lock(&zctx->shpool->mutex);
    sn = ngx_http_site_guard_stats_lookup_locked(zctx->sh, type, &key);
    if (sn != NULL && data == 5) {
        if ((ngx_msec_int_t) (now - sn->hll_start) < 300000) {
            sum = 0;
            zeros = 0;
            for (i = 0; i < NGX_HTTP_SITE_GUARD_STATS_HLL_REGISTERS; i++) {
                sum += 1.0 / (double) ((uint64_t) 1 << sn->hll[i]);
                if (sn->hll[i] == 0) {
                    zeros++;
                }
            }
            estimate = 0.7213 / (1 + 1.079 / 64) * 64 * 64 / sum;
            if (estimate < 160 && zeros != 0) {
                value = ngx_http_site_guard_linear_count[zeros];
            } else {
                value = (ngx_uint_t) estimate;
            }
        }
    } else if (sn != NULL) {
        for (i = 0; i < NGX_HTTP_SITE_GUARD_STATS_BUCKETS; i++) {
            if (sn->buckets[i].start != 0
                && (ngx_msec_int_t) (now - sn->buckets[i].start) >= 0
                && (ngx_msec_int_t) (now - sn->buckets[i].start) < 60000)
            {
                value += sn->buckets[i].count;
            }
        }
    }
    ngx_shmtx_unlock(&zctx->shpool->mutex);

done:

    v->data = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    v->len = ngx_sprintf(v->data, "%ui", value) - v->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}
