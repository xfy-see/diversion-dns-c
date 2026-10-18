/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "mosdns.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TOP_CAP 1024u
#define HASH_CAP 2048u
#define HISTORY 60u
#define BINS 32u
#define SCHEMA "{\"schema\":\"diversion-dns-stats-v1\""
static const uint64_t bounds[BINS] = {125,250,500,750,1000,1500,2000,3000,4000,6000,8000,12000,16000,24000,32000,48000,64000,96000,128000,192000,256000,384000,512000,768000,1000000,1500000,2000000,4000000,8000000,16000000,32000000,UINT64_MAX};
static const char *const errors[MD_SE_COUNT] = {"none","queue_full","queue_timeout","upstream_failure","upstream_timeout","nft_failure","execution_deadline","invalid_response","memory","send_failure","client_disconnected","shutdown"};
static const char *const events[MD_SV_COUNT] = {"invalid_udp","invalid_tcp","tcp_read_timeout","tcp_write_timeout","tcp_limit_rejected","tcp_evicted","allocation_failure"};
typedef struct { uint64_t n,sum,max,b[BINS];
     } hist;
typedef struct {
    uint64_t completed, delivered, success, noerror, nxdomain, truncated, coalesced;
    uint64_t cache[4], error[MD_SE_COUNT], rcode[17];
    hist rt, queue, service;
} metric;
typedef struct { char name[256];
     uint64_t count, error;
     unsigned heap, next;
     } top_entry;
typedef struct {
    metric total, split[2][3][2];
    uint64_t received, inflight, peak_inflight, event[MD_SV_COUNT];
    uint64_t top_replacements;
    top_entry top[TOP_CAP];
     unsigned heap[TOP_CAP], hash[HASH_CAP], used;
} counters;
typedef struct { uint64_t start_ns,end_ns;
     metric data;
     } period;
struct md_stats {
    char *path;
     unsigned interval;
    md_cache *cache;
    pthread_mutex_t lock;
     pthread_cond_t wake;
    pthread_t thread;
     bool started, stop;
    int lockfd;
    uint64_t start_ns, unix_start, interval_start, export_failures;
    counters c;
    metric interval_data;
    period history[HISTORY];
     unsigned history_used, history_next;
};
static int failure(char *err, const char *s) { if (err) snprintf(err,MD_ERROR_SIZE,"stats: %s",s);
     return -1;
     }
static unsigned hash_name(const char *s) { unsigned h=2166136261u;
     while (*s) h=(h^(unsigned char)*s++)*16777619u;
     return h&(HASH_CAP-1);
     }
static bool less(counters *c,unsigned a,unsigned b) { return c->top[a].count<c->top[b].count;
     }
static void heap_down(counters *c,unsigned at) {
    for (;;) {
        unsigned kid=at*2+1;
        if (kid>=c->used) break;
        if (kid+1<c->used && less(c,c->heap[kid+1],c->heap[kid])) kid++;
        if (!less(c,c->heap[kid],c->heap[at])) break;
        unsigned a=c->heap[at],b=c->heap[kid];
     c->heap[at]=b;
    c->heap[kid]=a;
        c->top[a].heap=kid;
    c->top[b].heap=at;
    at=kid;
    }
}
/* Space-Saving with min-heap + bounded hash chains: counts have explicit
 * [estimate-error, estimate] bounds. No unbounded per-domain allocation. */
static void top_add(counters *c,const char *name) {
    unsigned h=hash_name(name), id=c->hash[h];
    while (id && strcmp(c->top[id-1].name,name)) id=c->top[id-1].next;
    if (id) { c->top[id-1].count++;
     heap_down(c,c->top[id-1].heap);
     return;
     }
    unsigned i;
     uint64_t previous=0;
    if (c->used<TOP_CAP) { i=c->used++;
    c->heap[i]=i;
    c->top[i].heap=i;
     }
    else {
        i=c->heap[0];
     previous=c->top[i].count;
    c->top_replacements++;
        unsigned *link=&c->hash[hash_name(c->top[i].name)];
        while (*link && *link!=i+1) link=&c->top[*link-1].next;
        if (*link) *link=c->top[i].next;
    }
    top_entry *t=&c->top[i];
    snprintf(t->name,sizeof(t->name),"%s",name);
    t->count=previous+1;
    t->error=previous;
    t->next=c->hash[h];
    c->hash[h]=i+1;
    unsigned at = t->heap;
    while (at && less(c,c->heap[at],c->heap[(at-1)/2])) {
        unsigned parent=(at-1)/2, a=c->heap[at], b=c->heap[parent];
        c->heap[at]=b;
    c->heap[parent]=a;
    c->top[a].heap=parent;
    c->top[b].heap=at;
    at=parent;
    }
    heap_down(c,t->heap);
}
static void add_hist(hist *h,uint64_t us) {
    h->n++;
    h->sum+=us;
    if(us>h->max)h->max=us;
    unsigned i=0;
    while(i+1<BINS && us>bounds[i])i++;
    h->b[i]++;
}
static void add_metric(metric *m,const md_dns_query *v,bool delivered,bool tc,unsigned error,uint64_t rt,uint64_t queue,uint64_t service) {
    unsigned rc=v->stats_rcode;
    m->completed++;
    m->delivered+=delivered;
    m->truncated+=tc;
    m->coalesced+=v->stats_coalesced;
    bool success=delivered && !error && (rc==0 || rc==3);
    m->success+=success;
    m->noerror+=delivered && rc==0;
    m->nxdomain+=delivered && rc==3;
    m->cache[v->stats_cache<4?v->stats_cache:0]++;
    if(error<MD_SE_COUNT && error)m->error[error]++;
    if(delivered)m->rcode[rc<16?rc:16]++;
    add_hist(&m->rt,rt);
    add_hist(&m->queue,queue);
    add_hist(&m->service,service);
}
uint64_t md_stats_begin(md_stats *s) {
    if(!s)return 0;
    uint64_t now=md_now_ns();
    pthread_mutex_lock(&s->lock);
    s->c.received++;
    s->c.inflight++;
    if(s->c.inflight>s->c.peak_inflight)s->c.peak_inflight=s->c.inflight;
    pthread_mutex_unlock(&s->lock);
    return now;
}
void md_stats_event(md_stats *s,unsigned event) {
    if(!s || event>=MD_SV_COUNT)return;
    pthread_mutex_lock(&s->lock);
    s->c.event[event]++;
    pthread_mutex_unlock(&s->lock);
}
void md_stats_done(md_stats *s,const md_dns_query *v,bool tcp,uint64_t start,uint64_t queue,uint64_t service,bool delivered,bool tc,unsigned error) {
    if(!s || !start)return;
    uint64_t now=md_now_ns(),rt=now>=start?(now-start)/1000:0;
    pthread_mutex_lock(&s->lock);
    if(s->c.inflight)s->c.inflight--;
    add_metric(&s->c.total,v,delivered,tc,error,rt,queue,service);
    add_metric(&s->interval_data,v,delivered,tc,error,rt,queue,service);
    if(v->route>=0) add_metric(&s->c.split[v->route==1?0:1][v->q.type==1?0:v->q.type==28?1:2][tcp],v,delivered,tc,error,rt,queue,service);
    top_add(&s->c,v->q.name);
    pthread_mutex_unlock(&s->lock);
}
static void json_string(FILE *f,const char *s) {
    fputc('"',f);
    for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
        if(*p=='"'||*p=='\\')fprintf(f,"\\%c",*p);
        else if(*p<32 || *p>=127)fprintf(f,"\\u%04x",*p);
        else fputc(*p,f);
    }fputc('"',f);
}
static void percentile(FILE *f,const hist *h,unsigned percent) {
    if(!h->n){fputs("null",f);
    return;
    }
    uint64_t target=h->n/100*percent+(h->n%100*percent+99)/100,seen=0;
    for(unsigned i=0;i<BINS;i++){seen+=h->b[i];
    if(seen>=target){
        if(bounds[i]==UINT64_MAX)fputs("null",f);
    else fprintf(f,"%.3f",bounds[i]/1000.0);
    return;
    }}fputs("null",f);
}
static void print_hist(FILE *f,const hist *h) {
    fprintf(f,"{\"samples\":%llu,\"avg_ms\":",(unsigned long long)h->n);
    if(h->n)fprintf(f,"%.6f",h->sum/(double)h->n/1000);
    else fputs("null",f);
    fprintf(f,",\"max_ms\":%.3f,\"p50_upper_ms\":",h->max/1000.0);
    percentile(f,h,50);
    fputs(",\"p90_upper_ms\":",f);
    percentile(f,h,90);
    fputs(",\"p95_upper_ms\":",f);
    percentile(f,h,95);
    fputs(",\"p99_upper_ms\":",f);
    percentile(f,h,99);
    fputs(",\"histogram\":[",f);
    for(unsigned i=0;i<BINS;i++)fprintf(f,"%s%llu",i?",":"",(unsigned long long)h->b[i]);
    fputs("]}",f);
}
static void ratio(FILE *f,uint64_t n,uint64_t d) { if(d)fprintf(f,"%.6f",n/(double)d);
    else fputs("null",f);
     }
static void print_metric(FILE *f,const metric *m) {
    fprintf(f,"{\"completed\":%llu,\"delivered_to_kernel\":%llu,\"success\":%llu,\"noerror\":%llu,\"nxdomain\":%llu,\"truncated\":%llu,\"coalesced\":%llu,\"success_rate\":",
        (unsigned long long)m->completed,(unsigned long long)m->delivered,(unsigned long long)m->success,(unsigned long long)m->noerror,(unsigned long long)m->nxdomain,(unsigned long long)m->truncated,(unsigned long long)m->coalesced);
    ratio(f,m->success,m->completed);
    fputs(",\"cache_hit_rate\":",f);
    ratio(f,m->cache[2]+m->cache[3],m->completed);
    fprintf(f,",\"cache\":{\"disabled_or_unchecked\":%llu,\"miss\":%llu,\"fresh\":%llu,\"stale\":%llu},\"errors\":{",
        (unsigned long long)m->cache[0],(unsigned long long)m->cache[1],(unsigned long long)m->cache[2],(unsigned long long)m->cache[3]);
    for(unsigned i=1;i<MD_SE_COUNT;i++)fprintf(f,"%s\"%s\":%llu",i>1?",":"",errors[i],(unsigned long long)m->error[i]);
    fputs("},\"rcode\":{",f);
    for(unsigned i=0;i<17;i++){if(i)fputc(',',f);
    if(i<16)fprintf(f,"\"%u\":",i);
    else fputs("\"extended\":",f);
    fprintf(f,"%llu",(unsigned long long)m->rcode[i]);
    }
    fputs("},\"rt\":",f);
    print_hist(f,&m->rt);
    fputs(",\"queue\":",f);
    print_hist(f,&m->queue);
    fputs(",\"service\":",f);
    print_hist(f,&m->service);
    fputc('}',f);
}
static int compare_top(const void *a,const void *b) {
    const top_entry *x=a,*y=b;
    return x->count<y->count?1:x->count>y->count?-1:strcmp(x->name,y->name);
}
/* Only replace this schema, never an arbitrary pre-existing user file.
 * Parent directory is administrator-selected; tempfile/lock are 0600, links
 * and nonregular files are rejected. All disk I/O is outside query locks. */
static int existing_ok(const char *path) {
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return errno==ENOENT?0:-1;
    struct stat st;
    char head[sizeof(SCHEMA)]={0};
    int ok=!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_nlink==1 && st.st_uid==geteuid();
    ssize_t n=ok?read(fd,head,sizeof(SCHEMA)-1):-1;
    close(fd);
    return n==(ssize_t)sizeof(SCHEMA)-1 && !memcmp(head,SCHEMA,sizeof(SCHEMA)-1)?0:-1;
}
static int snapshot(md_stats *s,bool final) {
    counters *c=malloc(sizeof(*c));
    period *history=malloc(sizeof(s->history));
    if(!c || !history){free(c);
    free(history);
    return -1;
    }
    uint64_t now=md_now_ns(),begin;
    unsigned used;
    pthread_mutex_lock(&s->lock);
    begin=s->interval_start;
    period *p=&s->history[s->history_next];
    *p=(period){begin,now,s->interval_data};
    s->history_next=(s->history_next+1)%HISTORY;
    if(s->history_used<HISTORY)s->history_used++;
    used=s->history_used;
    for(unsigned i=0;i<used;i++)history[i]=s->history[(s->history_next+HISTORY-used+i)%HISTORY];
    memset(&s->interval_data,0,sizeof(s->interval_data));
    s->interval_start=now;
    *c=s->c;
    pthread_mutex_unlock(&s->lock);
    char *tmp=malloc(strlen(s->path)+16);
    if(!tmp){free(c);
    free(history);
    return -1;
    }
    sprintf(tmp,"%s.tmp.XXXXXX",s->path);
    int fd=mkstemp(tmp);
    FILE *f=fd<0?NULL:fdopen(fd,"w");
    if(!f){if(fd>=0){close(fd);
    unlink(tmp);
    }free(tmp);
    free(c);
    free(history);
    return -1;
    }
    fprintf(f,SCHEMA ",\"pid\":%ld,\"started_unix\":%llu,\"snapshot_unix\":%llu,\"uptime_seconds\":%.3f,\"final\":%s,\"interval_seconds\":%u,\"export_failures\":%llu,",
        (long)getpid(),(unsigned long long)s->unix_start,(unsigned long long)time(NULL),(now-s->start_ns)/1e9,final?"true":"false",s->interval,(unsigned long long)s->export_failures);
    fprintf(f,"\"received_valid\":%llu,\"inflight\":%llu,\"peak_inflight\":%llu,\"qps_lifetime\":%.6f,",
        (unsigned long long)c->received,(unsigned long long)c->inflight,(unsigned long long)c->peak_inflight,now>s->start_ns?c->received/((now-s->start_ns)/1e9):0);
    fputs("\"histogram_upper_ms\":[",f);
    for(unsigned i=0;i<BINS;i++){if(i)fputc(',',f);
    if(bounds[i]==UINT64_MAX)fputs("null",f);
    else fprintf(f,"%.3f",bounds[i]/1000.0);
    }fputs("],\"total\":",f);
    print_metric(f,&c->total);
    fputs(",\"breakdown\":[",f);
    bool comma=false;
    for(unsigned g=0;g<2;g++)for(unsigned t=0;t<3;t++)for(unsigned tcp=0;tcp<2;tcp++) {
        fprintf(f,"%s{\"group\":\"%s\",\"qtype\":\"%s\",\"transport\":\"%s\",\"metrics\":",comma?",":"",g?"foreign":"cn",t==0?"A":t==1?"AAAA":"other",tcp?"tcp":"udp");
    comma=true;
    print_metric(f,&c->split[g][t][tcp]);
    fputc('}',f);
    }
    fputs("],\"recent_intervals\":[",f);
    for(unsigned i=0;i<used;i++){
        double secs=(history[i].end_ns-history[i].start_ns)/1e9;
        fprintf(f,"%s{\"start_uptime_seconds\":%.3f,\"duration_seconds\":%.6f,\"completed_qps\":%.6f,\"metrics\":",i?",":"",(history[i].start_ns-s->start_ns)/1e9,secs,secs?history[i].data.completed/secs:0);
    print_metric(f,&history[i].data);
    fputc('}',f);
    }
    fputs("],\"events\":{",f);
    for(unsigned i=0;i<MD_SV_COUNT;i++)fprintf(f,"%s\"%s\":%llu",i?",":"",events[i],(unsigned long long)c->event[i]);
    fputc('}',f);
    md_cache_stats cache;
    md_cache_get_stats(s->cache,&cache);
    fputs(",\"cache_engine\":{",f);
    for(unsigned g=0;g<2;g++){
        fprintf(f,"%s\"%s\":{\"entries\":%zu,\"bytes\":%llu",g?",":"",g?"foreign":"cn",cache.entries[g],(unsigned long long)cache.bytes[g]);
        for(unsigned i=0;i<MD_CS_COUNT;i++)fprintf(f,",\"%s\":%llu",md_cache_stat_names[i],(unsigned long long)cache.v[g][i]);
    fputc('}',f);
    }fputc('}',f);
    md_nft_stats nft;
    md_nft_get_stats(&nft);
    fprintf(f,",\"nft\":{\"applies\":%llu,\"skipped\":%llu,\"transactions\":%llu}",(unsigned long long)nft.applies,(unsigned long long)nft.skipped,(unsigned long long)nft.transactions);
    struct rusage ru;
    if(!getrusage(RUSAGE_SELF,&ru)) {
#ifdef __APPLE__
        long peak=ru.ru_maxrss/1024;
#else
        long peak=ru.ru_maxrss;
#endif
        fprintf(f,",\"process\":{\"peak_rss_kib\":%ld,\"cpu_user_seconds\":%.6f,\"cpu_system_seconds\":%.6f}",peak,ru.ru_utime.tv_sec+ru.ru_utime.tv_usec/1e6,ru.ru_stime.tv_sec+ru.ru_stime.tv_usec/1e6);
    }
    qsort(c->top,c->used,sizeof(c->top[0]),compare_top);
    fprintf(f,",\"top50\":{\"algorithm\":\"space-saving\",\"capacity\":%u,\"replacements\":%llu,\"exact\":%s,\"domains\":[",TOP_CAP,(unsigned long long)c->top_replacements,c->top_replacements?"false":"true");
    for(unsigned i=0;i<c->used && i<50;i++){
        if(i)fputc(',',f);
    fputs("{\"domain\":",f);
    json_string(f,c->top[i].name);
        fprintf(f,",\"count_estimate\":%llu,\"count_lower_bound\":%llu,\"error_bound\":%llu}",(unsigned long long)c->top[i].count,(unsigned long long)(c->top[i].count-c->top[i].error),(unsigned long long)c->top[i].error);
    }
    fputs("]}}\n",f);
    int rc=ferror(f)?-1:0;
    if(fclose(f))rc=-1;
    if(!rc && (existing_ok(s->path) || rename(tmp,s->path)))rc=-1;
    if(rc)unlink(tmp);
    free(tmp);
    free(c);
    free(history);
    return rc;
}
static void *writer(void *opaque) {
    md_stats *s=opaque;
    for(;;){
        struct timespec until;
    clock_gettime(CLOCK_REALTIME,&until);
    until.tv_sec+=s->interval;
        pthread_mutex_lock(&s->lock);
    int rc=0;
        while(!s->stop && rc!=ETIMEDOUT)rc=pthread_cond_timedwait(&s->wake,&s->lock,&until);
        bool stop=s->stop;
    pthread_mutex_unlock(&s->lock);
    if(stop)break;
        if(snapshot(s,false)){s->export_failures++;
    fprintf(stderr,"stats: snapshot failed (%llu failures)\n",(unsigned long long)s->export_failures);
    }
    }return NULL;
}
md_stats *md_stats_new(const char *path,unsigned interval,md_cache *cache,char *err) {
    md_stats *s=calloc(1,sizeof(*s));
    if(!s){failure(err,"out of memory");
    return NULL;
    }
    s->lockfd=-1;
    s->path=strdup(path);
    s->interval=interval;
    s->cache=cache;
    if(!s->path || pthread_mutex_init(&s->lock,NULL)){free(s->path);
    free(s);
    failure(err,"initialization failed");
    return NULL;
    }
    if(pthread_cond_init(&s->wake,NULL)){pthread_mutex_destroy(&s->lock);
    free(s->path);
    free(s);
    failure(err,"condition failed");
    return NULL;
    }
    return s;
}
int md_stats_start(md_stats *s,char *err) {
    if(!s || s->started)return 0;
    if(existing_ok(s->path))return failure(err,"snapshot target is not an owned stats file");
    char *lock=malloc(strlen(s->path)+6);
    if(!lock)return failure(err,"out of memory");
    sprintf(lock,"%s.lock",s->path);
    s->lockfd=open(lock,O_CREAT|O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    free(lock);
    struct stat st;
    struct flock fl={.l_type=F_WRLCK,.l_whence=SEEK_SET};
    if(s->lockfd<0 || fstat(s->lockfd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 || fcntl(s->lockfd,F_SETLK,&fl))return failure(err,"cannot acquire exclusive snapshot lock");
    s->start_ns=s->interval_start=md_now_ns();
    s->unix_start=(uint64_t)time(NULL);
    if(snapshot(s,false))return failure(err,"initial snapshot failed");
    if(md_thread_create(&s->thread,writer,s))return failure(err,"writer thread failed");
    s->started=true;
    return 0;
}
void md_stats_free(md_stats *s) {
    if(!s)return;
    if(s->started){pthread_mutex_lock(&s->lock);
    s->stop=true;
    pthread_cond_signal(&s->wake);
    pthread_mutex_unlock(&s->lock);
    pthread_join(s->thread,NULL);
    if(snapshot(s,true))fprintf(stderr,"stats: final snapshot failed\n");
    }
    if(s->lockfd>=0)close(s->lockfd);
    pthread_cond_destroy(&s->wake);
    pthread_mutex_destroy(&s->lock);
    free(s->path);
    free(s);
}
int md_stats_show(const char *path) {
    if(existing_ok(path)){fprintf(stderr,"stats: invalid or unreadable snapshot\n");
    return 1;
    }
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    struct stat st;
    if(fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size>4*1024*1024){if(fd>=0)close(fd);
    fputs("stats: snapshot unavailable\n",stderr);
    return 1;
    }
    char buf[4096];
    ssize_t n;
    size_t total=0;
    int rc=0;
    while((n=read(fd,buf,sizeof(buf)))>0){total+=(size_t)n;
    if(total>4*1024*1024 || fwrite(buf,1,(size_t)n,stdout)!=(size_t)n){rc=1;
    break;
    }}
    if(n<0)rc=1;
    close(fd);
    return rc;
}
