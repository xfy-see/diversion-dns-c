/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "request_metrics.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define BUCKETS 16
static const uint64_t bounds[BUCKETS-1] = {
    100,250,500,1000,2500,5000,10000,25000,50000,100000,250000,500000,1000000,2500000,5000000
};
typedef struct {
    uint64_t requests, completed, success, failed, noerror, nxdomain, servfail;
    uint64_t refused, other_rcode, no_response, send_errors, queue_rejected, udp, tcp;
    uint64_t latency_count, latency_sum_us, latest_latency_us, latest_completion_unix_ms;
    uint64_t latency_buckets[BUCKETS];
} totals;
struct md_request_metrics {
    pthread_mutex_t lock;
    md_engine *engine;
    char *path;
    uint64_t started, started_unix, last_write, sequence;
    totals t;
};
static uint64_t wall_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
md_request_metrics *md_request_metrics_new(md_engine *engine) {
    const char *path = getenv("DIVERSION_METRICS_FILE");
    if (!path || !*path) return NULL;
    if (*path != '/' || strlen(path) > 3500) {
        fprintf(stderr,"request metrics: absolute bounded path required\n"); return NULL;
    }
    md_request_metrics *m = calloc(1,sizeof(*m));
    if (!m) return NULL;
    m->path = strdup(path);
    if (!m->path || pthread_mutex_init(&m->lock,NULL)) { free(m->path); free(m); return NULL; }
    m->engine=engine; m->started=md_now_ms(); m->started_unix=wall_ms()/1000;
    return m;
}
uint64_t md_request_metrics_begin(md_request_metrics *m, bool tcp) {
    if (!m) return 0;
    uint64_t start=md_now_ns();
    pthread_mutex_lock(&m->lock);
    m->t.requests++; if (tcp) m->t.tcp++; else m->t.udp++;
    pthread_mutex_unlock(&m->lock);
    return start;
}
void md_request_metrics_end(md_request_metrics *m, uint64_t start,
                            const md_packet *response, bool sent, bool rejected) {
    if (!m || !start) return;
    uint64_t now=md_now_ns(), elapsed=now>=start ? (now-start)/1000 : 0;
    bool valid=response && response->len>=12;
    unsigned rc=valid ? response->data[3]&15u : 16;
    /* The OPT TTL carries the high RCODE bits: BADVERS has low bits zero
     * but must never become a successful NOERROR sample. Responses without
     * additional records cannot contain OPT and retain the cheap path. The
     * thread-local view avoids a large stack object or per-request allocation. */
    if (valid && md_read16(response->data+10)) {
        md_dns_view *view=md_dns_view_scratch();
        if (!view || md_dns_view_parse(response,view,NULL)) valid=false;
        else rc=md_dns_view_rcode(response,view);
    }
    pthread_mutex_lock(&m->lock);
    totals *t=&m->t;
    t->completed++; t->queue_rejected+=rejected;
    if (!valid) t->no_response++;
    else {
        if (!sent) t->send_errors++;
        if (rc==0) t->noerror++; else if (rc==3) t->nxdomain++;
        else if (rc==2) t->servfail++; else if (rc==5) t->refused++; else t->other_rcode++;
    }
    if (valid && sent && (rc==0 || rc==3)) t->success++; else t->failed++;
    t->latency_count++; t->latency_sum_us+=elapsed;
    t->latest_latency_us=elapsed; t->latest_completion_unix_ms=wall_ms();
    unsigned bucket=0; while (bucket<BUCKETS-1 && elapsed>bounds[bucket]) bucket++;
    t->latency_buckets[bucket]++;
    pthread_mutex_unlock(&m->lock);
}
/* Atomic, bounded snapshot: never truncate/follow the public path or a guessed
 * temporary path. Owner must supply a trusted directory, normally tmpfs. */
void md_request_metrics_write(md_request_metrics *m, bool final) {
    if (!m) return;
    uint64_t now=md_now_ms();
    if (!final && m->last_write && now-m->last_write<5000) return;
    m->last_write=now;
    struct stat st;
    if (lstat(m->path,&st)==0 && !S_ISREG(st.st_mode)) {
        fprintf(stderr,"request metrics: refusing non-regular destination\n"); return;
    }
    totals t;
    pthread_mutex_lock(&m->lock); t=m->t; pthread_mutex_unlock(&m->lock);
    md_cache_stats cache; md_engine_cache_snapshot(m->engine,&cache);
    size_t n=strlen(m->path)+32;
    char *tmp=malloc(n); if (!tmp) return;
    snprintf(tmp,n,"%s.tmp.XXXXXX",m->path);
    int fd=mkstemp(tmp);
    if (fd<0) { fprintf(stderr,"request metrics: cannot create snapshot: %s\n",strerror(errno)); free(tmp); return; }
    FILE *out=fdopen(fd,"w");
    if (!out) { close(fd); unlink(tmp); free(tmp); return; }
    fprintf(out,"{\"version\":1,\"pid\":%ld,\"started_unix\":%"PRIu64",\"sequence\":%"PRIu64",\"updated_unix_ms\":%"PRIu64",\"uptime_ms\":%"PRIu64",\"final\":%s,\"totals\":{",
            (long)getpid(),m->started_unix,++m->sequence,wall_ms(),now-m->started,final?"true":"false");
#define FIELD(name) fprintf(out,"\"" #name "\":%"PRIu64",",t.name)
    FIELD(requests); FIELD(completed); FIELD(success); FIELD(failed); FIELD(noerror); FIELD(nxdomain);
    FIELD(servfail); FIELD(refused); FIELD(other_rcode); FIELD(no_response); FIELD(send_errors);
    FIELD(queue_rejected); FIELD(udp); FIELD(tcp); FIELD(latency_count); FIELD(latency_sum_us);
    FIELD(latest_latency_us); FIELD(latest_completion_unix_ms);
#undef FIELD
    fputs("\"latency_buckets\":[",out);
    for (unsigned i=0;i<BUCKETS;i++) fprintf(out,"%s%"PRIu64,i?",":"",t.latency_buckets[i]);
    fputs("]},\"latency_bucket_upper_us\":[",out);
    for (unsigned i=0;i<BUCKETS-1;i++) fprintf(out,"%s%"PRIu64,i?",":"",bounds[i]);
    fputs(",null],\"cache\":{",out);
    for (unsigned g=0;g<2;g++) {
        fprintf(out,"%s\"%s\":{\"entries\":%zu,\"bytes\":%"PRIu64,g?",":"",g?"foreign":"cn",cache.entries[g],cache.bytes[g]);
        for (unsigned i=0;i<MD_CS_COUNT;i++) fprintf(out,",\"%s\":%"PRIu64,md_cache_stat_names[i],cache.v[g][i]);
        fputc('}',out);
    }
    fputs("}}\n",out);
    bool ok=!ferror(out); if (fclose(out)) ok=false;
    if (ok && rename(tmp,m->path)) ok=false;
    if (!ok) unlink(tmp);
    free(tmp);
}
void md_request_metrics_free(md_request_metrics *m) {
    if (!m) return;
    pthread_mutex_destroy(&m->lock); free(m->path); free(m);
}
