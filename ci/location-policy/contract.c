/* Actual connector code with inert WAF handles; no server or rules execute. */
#include "ngx_http_coraza_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *test_name = "arguments";
static int created, forwarded, finalized, request_result, allocation_failure;
static int connection_failure, value_failure, cleanup_failure, intervention_status;
static int audit_expected;
static void *allocations[256];
static size_t nalloc;
static struct { coraza_waf_t waf; int headers, bodies, responses, logs, frees, status; } tx[8];
static char last_id[64];

static void check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s: %s\n", test_name, message);
        exit(EXIT_FAILURE);
    }
}

ngx_module_t ngx_http_coraza_module = { .ctx_index = 0 };
ngx_module_t ngx_http_core_module = { .ctx_index = 1 };
ngx_http_output_header_filter_pt ngx_http_top_header_filter;
volatile ngx_str_t ngx_cached_http_time = ngx_string("Tue, 06 Oct 2026 12:00:00 GMT");

void *ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    if (allocation_failure) { return NULL; }
    check(nalloc < 256, "bounded fixture allocations");
    void *p = calloc(1, size ? size : 1);
    check(p != NULL, "fixture allocation");
    allocations[nalloc++] = p;
    return p;
}
void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { return ngx_palloc(pool, size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { return ngx_palloc(pool, size); }
u_char *ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *s)
{
    u_char *p = ngx_palloc(pool, s->len);
    if (p) { memcpy(p, s->data, s->len); }
    return p;
}
ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    check(size == 0, "cleanup has no auxiliary allocation");
    if (cleanup_failure) { return NULL; }
    ngx_pool_cleanup_t *cln = ngx_palloc(pool, sizeof(*cln));
    if (cln) { cln->next = pool->cleanup; pool->cleanup = cln; }
    return cln;
}
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{ (void) level; (void) log; (void) error; (void) format; }
ngx_int_t ngx_http_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *expression, ngx_str_t *value)
{
    (void) r;
    *value = expression->value;
    return value_failure ? NGX_ERROR : NGX_OK;
}
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port)
{ (void) c; (void) s; (void) port; return connection_failure ? NGX_ERROR : NGX_OK; }

coraza_transaction_t coraza_new_transaction(coraza_waf_t waf)
{
    check(created < 7, "bounded transaction count");
    tx[++created].waf = waf;
    return (coraza_transaction_t) created;
}
coraza_transaction_t coraza_new_transaction_with_id(coraza_waf_t waf, char *id)
{
    size_t len = strlen(id);
    check(len < sizeof(last_id), "valid fixture ID length");
    memcpy(last_id, id, len + 1);
    return coraza_new_transaction(waf);
}
static void live(coraza_transaction_t t)
{ check(t > 0 && t <= (coraza_transaction_t) created && !tx[t].frees, "live transaction"); }
int coraza_process_connection(coraza_transaction_t t, char *a, int ap, char *b, int bp)
{ live(t); (void) a; (void) ap; (void) b; (void) bp; return CORAZA_OK; }
int coraza_process_uri(coraza_transaction_t t, char *uri, char *method, char *proto)
{ live(t); check(!strcmp(uri, "/ordinary") && !strcmp(method, "GET") && !strcmp(proto, "HTTP/1.1"), "original request metadata"); return CORAZA_OK; }
int coraza_process_request_headers(coraza_transaction_t t)
{ live(t); tx[t].headers++; return request_result; }
int coraza_process_request_body(coraza_transaction_t t)
{ live(t); tx[t].bodies++; return CORAZA_OK; }
int coraza_process_response_headers(coraza_transaction_t t, int status, char *proto)
{ live(t); (void) status; (void) proto; tx[t].responses++; return CORAZA_OK; }
int coraza_process_logging(coraza_transaction_t t)
{ live(t); check(tx[t].logs++ == 0, "exactly one audit log per transaction"); return CORAZA_OK; }
int coraza_update_status_code(coraza_transaction_t t, int status)
{ live(t); tx[t].status = status; return CORAZA_OK; }
int coraza_free_transaction(coraza_transaction_t t)
{ live(t); tx[t].frees++; return NGX_OK; }
int ngx_http_coraza_is_request_body_accessible(coraza_transaction_t t)
{ live(t); return 0; }
int ngx_http_coraza_is_response_body_processable(coraza_transaction_t t)
{ live(t); return 0; }
ngx_int_t ngx_http_coraza_process_intervention(ngx_http_coraza_ctx_t *ctx,
    ngx_http_request_t *r, ngx_int_t early)
{
    live(ctx->coraza_transaction);
    check(!audit_expected, "audit-only mode must not apply interventions");
    check(early == 1 && intervention_status != 0, "only configured inert phase-1 intervention");
    if (intervention_status == 307) {
        static ngx_table_elt_t location;
        r->headers_out.location = &location;
    }
    return intervention_status;
}
int coraza_add_request_header(coraza_transaction_t t, char *n, int nl, char *v, int vl)
{ live(t); (void) n; (void) nl; (void) v; (void) vl; return CORAZA_OK; }
int coraza_add_response_header(coraza_transaction_t t, char *n, int nl, char *v, int vl)
{ live(t); (void) n; (void) nl; (void) v; (void) vl; return CORAZA_OK; }
int coraza_add_request_headers(coraza_transaction_t t, char *p, int len, int count)
{ live(t); (void) p; (void) len; (void) count; check(0, "unexpected request batch"); return CORAZA_ERROR; }
int coraza_add_response_headers(coraza_transaction_t t, char *p, int len, int count)
{ live(t); (void) p; (void) len; (void) count; check(0, "unexpected response batch"); return CORAZA_ERROR; }
int coraza_append_request_body(coraza_transaction_t t, unsigned char *p, int len)
{ live(t); (void) p; (void) len; check(0, "unexpected body append"); return CORAZA_ERROR; }
u_char *ngx_http_time(u_char *buf, time_t time)
{ (void) time; check(0, "unexpected date formatting"); return buf; }
u_char *ngx_sprintf(u_char *buf, const char *format, ...)
{ (void) format; check(0, "unexpected number formatting"); return buf; }
ngx_int_t ngx_strncasecmp(u_char *left, u_char *right, size_t len)
{ return strncasecmp((char *) left, (char *) right, len); }
in_port_t ngx_inet_get_port(struct sockaddr *address)
{ (void) address; check(0, "unexpected IP fixture"); return 0; }
size_t ngx_sock_ntop(struct sockaddr *address, socklen_t len, u_char *text,
    size_t size, ngx_uint_t port)
{ (void) address; (void) len; (void) text; (void) size; (void) port; check(0, "unexpected address formatting"); return 0; }
ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{ (void) p; (void) n; (void) size; return NULL; } /* Supported per-header fallback. */
void *ngx_array_push(ngx_array_t *a)
{ (void) a; check(0, "unexpected array push"); return NULL; }
ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt callback)
{ (void) r; (void) callback; check(0, "unexpected body read"); return NGX_ERROR; }
void ngx_http_core_run_phases(ngx_http_request_t *r)
{ (void) r; check(0, "unexpected asynchronous resume"); }
ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{ (void) file; (void) buf; (void) size; (void) offset; check(0, "unexpected file read"); return NGX_ERROR; }

static ngx_int_t downstream(ngx_http_request_t *r)
{ (void) r; forwarded++; return NGX_OK; }
ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_module_t *m,
    ngx_int_t status)
{
    check(m == &ngx_http_coraza_module && (status == 500 || status == 403), "header failure finalization");
    finalized++;
    /* nginx preserves the supplied context, marks filter finalization and
     * converts successful special-response generation into NGX_ERROR. */
    r->filter_finalize = 1;
    ngx_int_t rc = ngx_http_coraza_header_filter(r);
    return rc == NGX_OK || rc == NGX_DONE ? NGX_ERROR : rc;
}

#include "ddebug.h"
#include "location-lifecycle.inc"
#include "ngx_http_coraza_rewrite.c"
#include "ngx_http_coraza_pre_access.c"
#include "ngx_http_coraza_header_filter.c"
#include "ngx_http_coraza_log.c"
#include "ngx_http_coraza_utils.c"

int main(int argc, char **argv)
{
    check(argc == 2, "one test case required");
    test_name = argv[1];
    ngx_pool_t pool = {0};
    ngx_log_t log = {0};
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    ngx_connection_t connection = { .log = &log, .sockaddr = (struct sockaddr *) &address,
        .local_sockaddr = (struct sockaddr *) &address };
    ngx_http_coraza_main_conf_t main_conf = { .waf = 30 };
    ngx_http_coraza_conf_t first = { .waf = 10, .enable = 1 };
    ngx_http_coraza_conf_t final = { .waf = 20, .enable = 1 };
    ngx_http_core_loc_conf_t core = {0};
    ngx_http_complex_value_t first_id = { .value = ngx_string("initial-id") };
    ngx_http_complex_value_t final_id = { .value = ngx_string("final-id") };
    ngx_table_elt_t input_slot = {0}, output_slot = {0};
    void *contexts[2] = {0}, *locs[2] = { &first, &core }, *mains[2] = { &main_conf, NULL };
    ngx_http_request_t r = { .pool = &pool, .connection = &connection,
        .ctx = contexts, .loc_conf = locs, .main_conf = mains,
        .unparsed_uri = ngx_string("/ordinary"), .method_name = ngx_string("GET"),
        .method = NGX_HTTP_GET, .http_version = NGX_HTTP_VERSION_11, .keepalive = 1 };
    r.main = &r;
    /* ngx_list_init allocates storage even for an empty nginx header list. */
    r.headers_in.headers.part.elts = &input_slot;
    r.headers_out.headers.part.elts = &output_slot;
    r.headers_out.status = 200;
    r.headers_out.content_length_n = -1;
    r.headers_out.last_modified_time = -1;
    ngx_http_top_header_filter = downstream;
    check(ngx_http_coraza_header_filter_init() == NGX_OK, "filter registration");

    if (!strcmp(test_name, "same")) { final.waf = first.waf; }
    if (!strcmp(test_name, "on-off") || !strcmp(test_name, "off-off") || !strcmp(test_name, "early-off") || !strcmp(test_name, "log-off")) { final.enable = 0; }
    if (!strcmp(test_name, "off-on") || !strcmp(test_name, "off-off")) { first.enable = 0; }
    if (!strcmp(test_name, "main-waf") || strstr(test_name, "no-waf")) { final.waf = 0; }
    if (strstr(test_name, "no-waf")) { main_conf.waf = 0; }
    if (!strcmp(test_name, "id") || !strcmp(test_name, "id-error") || !strcmp(test_name, "log-id")) {
        first.transaction_id = &first_id; final.transaction_id = &final_id;
    }
    if (!strcmp(test_name, "id-error")) { value_failure = 1; }
    if (strstr(test_name, "allocation")) { allocation_failure = 1; }
    if (strstr(test_name, "connection")) { connection_failure = 1; }
    if (strstr(test_name, "cleanup")) { cleanup_failure = 1; }
    if (strstr(test_name, "engine-error")) { request_result = CORAZA_ERROR; }
    if (!strcmp(test_name, "log-interruption")) { request_result = CORAZA_INTERRUPTION; }
    if (!strcmp(test_name, "early-interruption") || !strcmp(test_name, "early-deny")
        || !strcmp(test_name, "early-special-deny") || !strcmp(test_name, "early-redirect")) {
        request_result = CORAZA_INTERRUPTION;
        intervention_status = !strcmp(test_name, "early-redirect") ? 307
            : strstr(test_name, "deny") ? 403 : 500;
    }
    if (!strcmp(test_name, "early-special-deny")) { r.err_status = 404; }
    if (!strcmp(test_name, "subrequest")) {
        static ngx_http_request_t parent;
        r.main = &parent;
    }

    /* Ordinary rewrite rematching changes loc_conf, retaining the ctx array.
     * No connector handler is registered there (separate source-contract lint). */
    locs[0] = &final;
    check(created == 0 && contexts[0] == NULL, "no transaction before stable phase");
    if (!strncmp(test_name, "log-", 4)) {
        audit_expected = 1;
        r.headers_out.status = 444;
        ngx_http_headers_out_t completed = r.headers_out;
        check(ngx_http_coraza_log_handler(&r) == NGX_OK, "headerless log always returns OK");
        check(ngx_http_coraza_log_handler(&r) == NGX_OK, "repeated headerless log is bounded");
        check(!memcmp(&completed, &r.headers_out, sizeof(completed))
            && !r.header_sent && !r.filter_finalize && !finalized && !forwarded,
            "audit fallback leaves completed response and transport untouched");
        if (!final.enable || allocation_failure || strstr(test_name, "no-waf")) {
            check(created == 0 && pool.cleanup == NULL, "no transaction after disabled or failed audit creation");
        } else if (cleanup_failure) {
            check(created == 1 && tx[1].frees == 1 && tx[1].logs == 0,
                "failed cleanup ownership never logs a freed handle");
        } else {
            check(created == 1 && tx[1].waf == 20 && tx[1].headers == 1
                && tx[1].logs == 1 && tx[1].status == 444,
                "headerless exit audits final policy and completed status once");
            check(tx[1].bodies == 0 && tx[1].responses == 0,
                "audit fallback does not synthesize body or response phases");
            if (!strcmp(test_name, "log-id")) {
                check(!strcmp(last_id, "final-id"), "headerless audit uses final configured ID");
            }
        }
        goto cleanup;
    }
    ngx_int_t result = !strncmp(test_name, "early", 5)
        ? ngx_http_coraza_header_filter(&r) : ngx_http_coraza_pre_access_handler(&r);
    ngx_http_coraza_ctx_t *ctx = contexts[0];
    if (!strcmp(test_name, "early-special-deny")) {
        check(result == NGX_ERROR && finalized == 1 && r.filter_finalize
            && forwarded == 1 && ctx && ctx->intervention_triggered,
            "special-response caller stops original output on NGX_ERROR");
        check(created == 1 && tx[1].waf == 20 && tx[1].headers == 1
            && tx[1].responses == 0,
            "special response retains final policy and guarded reentry");
        goto cleanup;
    }
    if (connection_failure || !strcmp(test_name, "early-engine-error")
        || !strcmp(test_name, "early-interruption") || !strcmp(test_name, "early-deny"))
    {
        check(result == (intervention_status ? intervention_status : 500),
            "early status returns to normal request finalization");
        check(created == 1 && ctx && tx[1].waf == 20
            && tx[1].headers == (connection_failure ? 0 : 1),
            "failed phase retains one settled-policy transaction");
        if (!strncmp(test_name, "early", 5)) {
            check(ctx && ctx->intervention_triggered && !finalized && !forwarded
                && !r.filter_finalize && !r.header_sent && r.keepalive && !connection.error,
                "early status leaves keepalive and unsent headers intact");
            /* Simulate the normal finalizer's response-header reentry. */
            check(ngx_http_coraza_header_filter(&r) == NGX_OK && forwarded == 1,
                "normal finalizer can forward the replacement headers once");
            check(created == 1 && tx[1].responses == 0
                && tx[1].headers == (connection_failure ? 0 : 1),
                "replacement response retains context without replaying inspection");
        }
        goto cleanup;
    }
    if (cleanup_failure) {
        check(result == NGX_ERROR && created == 1 && tx[1].frees == 1,
            "constructor cleanup-registration failure is bounded");
        check(finalized == 0 && forwarded == 0 && pool.cleanup == NULL,
            "unusable constructor result is never reentered");
    } else if (strstr(test_name, "no-waf") || strstr(test_name, "allocation") || value_failure) {
        check(result == (!strncmp(test_name, "early", 5) ? NGX_ERROR : 500), "initialization failure propagates");
        check(created == 0 && forwarded == 0 && finalized == 0, "failed initialization remains bounded");
    } else if (!final.enable) {
        check(created == 0 && ctx == NULL, "disabled final location owns no transaction");
        check(result == (!strncmp(test_name, "early", 5) ? NGX_OK : NGX_DECLINED), "disabled continuation");
    } else {
        check(created == 1, "one settled-policy transaction");
        if (ctx == NULL) {
            check(0, "settled context missing");
            return EXIT_FAILURE;
        }
        check(tx[1].waf == (final.waf ? final.waf : main_conf.waf), "transaction uses final effective WAF");
        {
            check(tx[1].headers == 1, "request headers processed exactly once");
            check(result == (!strncmp(test_name, "early", 5) ? NGX_OK : NGX_DECLINED), "normal continuation");
            if (!strcmp(test_name, "early-redirect")) {
                check(finalized == 0 && forwarded == 1 && r.headers_out.status == 307
                    && r.header_only && ctx->intervention_triggered,
                    "early redirect is prepared before forwarding");
                check(tx[1].responses == 0, "redirect does not replay phase-1 processing");
            } else if (!strncmp(test_name, "early", 5)) {
                check(tx[1].responses == 1 && forwarded == 1, "early response inspected and forwarded");
            } else {
                check(tx[1].bodies == 1, "body phase uses settled transaction");
            }
        }
        if (!strcmp(test_name, "id")) {
            check(!strcmp(last_id, "final-id"), "final transaction-ID expression selected");
            check(ctx->transaction_id.len == 8 && !memcmp(ctx->transaction_id.data, "final-id", 8), "configured ID retained for logging");
        }
        if (!strcmp(test_name, "resume")) {
            ctx->waiting_more_body = 1;
            check(ngx_http_coraza_pre_access_handler(&r) == NGX_DONE, "waiting resume yields");
            check(created == 1 && contexts[0] == ctx && tx[1].headers == 1, "resume retains transaction without replay");
        }
        if (!strncmp(test_name, "redirect", 8)) {
            ctx->processed = 1;
            contexts[0] = NULL; /* Actual nginx internal/named redirect contract. */
            locs[0] = &first;
            first.enable = strcmp(test_name, "redirect-off") != 0;
            check(ngx_http_coraza_pre_access_handler(&r) == NGX_DECLINED, "redirect destination continuation");
            check(created == (first.enable ? 2 : 1), "true redirect creates only enabled destination transaction");
            check(tx[1].frees == 0, "old transaction remains pool-owned");
            if (first.enable) {
                ngx_http_coraza_ctx_t *destination = contexts[0];
                if (destination == NULL) {
                    check(0, "redirect destination context missing");
                    return EXIT_FAILURE;
                }
                check(destination != ctx && tx[2].waf == 10 && tx[2].headers == 1,
                    "true redirect gets distinct final-policy context");
                check(ctx->processed && !destination->processed,
                    "redirect preserves old one-shot state without inheriting it");
            }
        }
        if (!strcmp(test_name, "logged")) {
            check(ngx_http_coraza_log_handler(&r) == NGX_OK, "normal log phase");
            check(ngx_http_coraza_log_handler(&r) == NGX_OK, "duplicate log phase guarded");
        }
        if (!strcmp(test_name, "header-once")) {
            check(ngx_http_coraza_header_filter(&r) == NGX_OK, "first response headers");
            check(ngx_http_coraza_header_filter(&r) == NGX_OK, "reentered response headers");
            check(created == 1 && tx[1].headers == 1 && tx[1].responses == 1 && forwarded == 2, "header one-shot retained");
        }
    }
cleanup:
    for (ngx_pool_cleanup_t *cln = pool.cleanup; cln; cln = cln->next) { cln->handler(cln->data); }
    for (int i = 1; i <= created; i++) {
        check(tx[i].logs == (cleanup_failure ? 0 : 1) && tx[i].frees == 1,
            "owned contexts audit once; all acquired transactions free once");
    }
    for (size_t i = 0; i < nalloc; i++) { free(allocations[i]); }
    return EXIT_SUCCESS;
}
