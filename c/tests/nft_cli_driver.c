/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Compile the portable Linux subprocess branch to test its real argv/stdin
 * boundary with a grammar-checking child. This does not emulate the kernel. */
#define _POSIX_C_SOURCE 200809L
/* Test-only compatibility for compiling the Linux subprocess branch on macOS.
 * This driver exercises add_target grammar; it does not prove Linux FIFO or
 * kernel behavior. Relative waits explicitly use the monotonic clock. */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
static int __attribute__((unused)) cli_condattr_setclock(pthread_condattr_t *attr, clockid_t clock) {
    return attr && clock == CLOCK_MONOTONIC ? 0 : EINVAL;
}
static int __attribute__((unused)) cli_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                                    const struct timespec *deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return errno;
    int64_t ns = ((int64_t)deadline->tv_sec - (int64_t)now.tv_sec) * 1000000000 + deadline->tv_nsec - now.tv_nsec;
    if (ns <= 0) return ETIMEDOUT;
    struct timespec relative = {(time_t)(ns / 1000000000), (long)(ns % 1000000000)};
    return pthread_cond_timedwait_relative_np(cond, mutex, &relative);
}
#define pthread_condattr_setclock cli_condattr_setclock
#define pthread_cond_timedwait cli_cond_timedwait
#endif
#ifndef __linux__
#define __linux__ 1
#endif
#ifndef NFT_SOURCE
#define NFT_SOURCE "../plugin/nftset.c"
#endif

#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/netlink.h>
#include "nft_netlink.h"
#ifndef ERESTART
#define ERESTART 85 /* macOS test-only Linux transport double */
#endif
/* 仅替换 netlink 传输和时钟；CLI 子进程仍接收真实参数，便于核验接口边界。 */
static unsigned fast_gen=7,metadata_reads,element_reads;
static bool fast_mode(void){const char *m=getenv("FAKE_MODE");return m&&!strncmp(m,"fast-",5);}
static const int fake_fd=2147483646;
static uint8_t fake_reply[MD_NL_BUFFER_SIZE];static size_t fake_length;
static unsigned opens,closes,sends,generations,batches,key_count,post_receive_clocks;static uint64_t late_ms;static bool batch_received;
static const char *fake_mode(void){const char *s=getenv("FAKE_MODE");return s?s:"normal";}
static int __attribute__((unused)) fake_clock(clockid_t id,struct timespec *t){if(batch_received&&!strcmp(fake_mode(),"late-parse")&&++post_receive_clocks==2)late_ms=6000;int rc=clock_gettime(id,t);if(!rc&&id==CLOCK_MONOTONIC){t->tv_sec+=(time_t)(late_ms/1000);t->tv_nsec+=(long)(late_ms%1000)*1000000;if(t->tv_nsec>=1000000000){++t->tv_sec;t->tv_nsec-=1000000000;}}return rc;}
static int __attribute__((unused)) fake_socket(int family,int type,int protocol){assert(family==16&&type==(SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK)&&protocol==12);++opens;return fake_fd;}
static int __attribute__((unused)) fake_bind(int fd,const struct sockaddr *p,socklen_t n){assert(fd==fake_fd&&n==sizeof(struct sockaddr_nl));const struct sockaddr_nl *s=(const struct sockaddr_nl *)p;assert(s->nl_family==16&&!s->nl_pid&&!s->nl_groups);return 0;}
static int __attribute__((unused)) fake_name(int fd,struct sockaddr *p,socklen_t *n){assert(fd==fake_fd&&*n==sizeof(struct sockaddr_nl));struct sockaddr_nl *s=(struct sockaddr_nl *)p;s->nl_pid=41771;return 0;}
static int __attribute__((unused)) fake_uname(struct utsname *u) {
    memset(u, 0, sizeof(*u));
    strcpy(u->release, !strcmp(fake_mode(), "fast-old-kernel") ? "6.6.99" : "6.12.94");
    return 0;
}
static int __attribute__((unused)) fake_getsockopt(int fd, int level, int opt, void *v, socklen_t *len) {
    assert(fd == fake_fd && level == SOL_SOCKET && opt == SO_SNDBUF && *len == sizeof(int));
    *(int *)v = !strcmp(fake_mode(), "fast-small-buffer") ? 2048 : 180224;
    return 0;
}
static int __attribute__((unused)) fake_close(int fd){if(fd==fake_fd){++closes;return 0;}return close(fd);}
static int __attribute__((unused)) fake_poll(struct pollfd *p,nfds_t n,int ms){if(n==1&&p->fd==fake_fd){assert(ms>0&&ms<=5000);if(!strcmp(fake_mode(),"late-wake")||(!strcmp(fake_mode(),"late-add-wake")&&batches))late_ms=6000;p->revents=p->events;return 1;}return poll(p,n,ms);}
static size_t __attribute__((unused)) fake_ack(const uint8_t *q,uint8_t *out,int error){memset(out,0,36);md_nl_put32(out,36);md_nl_put16(out+4,2);if(error)md_nl_put16(out+6,0x100);md_nl_put32(out+8,md_nl_u32(q+8));md_nl_put32(out+12,41771);int32_t e=error;memcpy(out+16,&e,4);memcpy(out+20,q,16);return 36;}
static ssize_t __attribute__((unused)) fake_send(int fd,const void *data,size_t n,int flags,const struct sockaddr *peer,socklen_t size){
    assert(fd==fake_fd&&!flags&&size==sizeof(struct sockaddr_nl));const struct sockaddr_nl *k=(const struct sockaddr_nl *)peer;assert(k->nl_family==16&&!k->nl_pid&&!k->nl_groups);++sends;fake_length=0;const uint8_t *p=data;
    if(md_nl_u16(p+4)==0xA10){++generations;assert(n==20&&md_nl_u16(p+6)==1&&md_nl_u32(p+12)==41771);
        if(!strcmp(fake_mode(),"gen-error")){fake_length=fake_ack(p,fake_reply,-EPERM);return (ssize_t)n;}
        if (fast_mode() && ((!strcmp(fake_mode(), "fast-reset") && generations == 5) ||
            (!strcmp(fake_mode(), "fast-permanent-reset") && generations == 4) ||
            (!strcmp(fake_mode(), "fast-race-before") && generations == 3) ||
            ((!strcmp(fake_mode(), "fast-race-after") || !strcmp(fake_mode(), "fast-race-flush")) && generations == 4) ||
            !strcmp(fake_mode(), "fast-race-forever"))) ++fast_gen;
        uint32_t gen=fast_mode()?fast_gen:!strcmp(fake_mode(),"zero-gen")?0:(!strcmp(fake_mode(),"changed-gen")&&generations==2)?8:7;
        memset(fake_reply,0,28);md_nl_put32(fake_reply,28);md_nl_put16(fake_reply+4,0xA0F);md_nl_put32(fake_reply+8,md_nl_u32(p+8));md_nl_put32(fake_reply+12,41771);fake_reply[19]=(uint8_t)gen;md_nl_put16(fake_reply+20,8);md_nl_put16(fake_reply+22,1);md_nl_be32(fake_reply+24,gen);fake_length=28;return (ssize_t)n;
    }
    if(fast_mode()&&md_nl_u16(p+4)==0xA0A){
        ++metadata_reads;md_nl_requests q={0};q.port=41771;md_nl_writer w={fake_reply,sizeof(fake_reply),0};size_t at;
        assert(!md_nl_message_start(&w,&q,0xA09,0,md_nl_u32(p+8),p[16],0,&at));
        size_t a=20;for(unsigned i=1;i<=2;i++){size_t z=md_nl_u16(p+a);assert(!md_nl_attr(&w,(uint16_t)i,p+a+4,z-4));a+=md_nl_align(z);}
        uint8_t val[4];md_nl_be32(val,!strcmp(fake_mode(),"fast-interval")?20:16);assert(!md_nl_attr(&w,3,val,4));
        bool v6=getenv("FAST_V6")!=NULL;md_nl_be32(val,v6?8:7);assert(!md_nl_attr(&w,4,val,4));md_nl_be32(val,v6?16:4);assert(!md_nl_attr(&w,5,val,4));
        md_nl_message_end(&w,at);fake_length=w.length;return (ssize_t)n;
    }
    if(fast_mode()&&md_nl_u16(p+4)==0xA0D){
        ++element_reads;
        if(strcmp(fake_mode(),"fast-existing") && strcmp(fake_mode(),"fast-permanent") && strcmp(fake_mode(),"fast-permanent-reset") && !(batches && !strcmp(fake_mode(),"fast-race-after"))){fake_length=fake_ack(p,fake_reply,-ENOENT);return (ssize_t)n;}
        md_nl_requests q={0};q.port=41771;md_nl_writer w={fake_reply,sizeof(fake_reply),0};size_t at,es,el,key;
        assert(!md_nl_message_start(&w,&q,0xA0C,0,md_nl_u32(p+8),p[16],0,&at));size_t a=20;
        for(unsigned i=1;i<=2;i++){size_t z=md_nl_u16(p+a);assert(!md_nl_attr(&w,(uint16_t)i,p+a+4,z-4));a+=md_nl_align(z);}
        unsigned bytes=getenv("FAST_V6")?16:4;const uint8_t *address=p+a+16;
        assert(!md_nl_nested_start(&w,3,&es)&&!md_nl_nested_start(&w,1,&el)&&!md_nl_nested_start(&w,1,&key)&&!md_nl_attr(&w,1,address,bytes)&&!md_nl_nested_end(&w,key));
        uint8_t ttl[8]={0};md_nl_be32(ttl+4,300000);
        if (strncmp(fake_mode(), "fast-permanent", 14)) assert(!md_nl_attr(&w,5,ttl,8));
        assert(!md_nl_nested_end(&w,el)&&!md_nl_nested_end(&w,es));if(!getenv("FAST_V6")){md_nl_put16(fake_reply+es+2,3);md_nl_put16(fake_reply+el+2,1);md_nl_put16(fake_reply+key+2,1);}
        md_nl_message_end(&w,at);fake_length=w.length;return (ssize_t)n;
    }
    if (fast_mode()) assert(n <= (!strcmp(fake_mode(), "fast-small-buffer") ? 2048u : 180224u) - 32);
    ++batches;size_t off=0;unsigned frames=0;bool poison=false;
    while(off<n){const uint8_t *m=p+off;size_t len=md_nl_u32(m);assert(len<=n-off&&len>=20&&md_nl_u32(m+12)==41771);++frames;
        if(md_nl_u16(m+4)==16){assert(frames==1&&len==28&&md_nl_u16(m+6)==1&&md_nl_read_be32(m+24)==(fast_mode()?fast_gen:7u));}
        else if(md_nl_u16(m+4)==0xA0C){assert(md_nl_u16(m+6)==0x405);size_t a=20;a+=md_nl_align(md_nl_u16(m+a));a+=md_nl_align(md_nl_u16(m+a));assert(md_nl_u16(m+a+2)==(3|0x8000));size_t end=a+md_nl_u16(m+a);a+=4;while(a<end){++key_count;assert(md_nl_u16(m+a+2)==(1|0x8000)&&md_nl_u16(m+a+6)==(1|0x8000)&&md_nl_u16(m+a+10)==1);if (fast_mode()) {
                unsigned address_bytes = getenv("FAST_V6") ? 16 : 4;
                if (!strcmp(fake_mode(), "fast-cohort-poison") && m[a+12+address_bytes-1] == 255) poison = true;
                size_t keylen = md_nl_u16(m+a+4);
                size_t ta = a + 4 + md_nl_align(keylen);
                assert(md_nl_u16(m+ta) == 12 && md_nl_u16(m+ta+2) == 4);
                uint64_t timeout = ((uint64_t)md_nl_read_be32(m+ta+4) << 32) | md_nl_read_be32(m+ta+8);
                uint64_t want = !strcmp(fake_mode(), "fast-ttl-highbit") ? 15000 : !strcmp(fake_mode(), "fast-ttl-cap") ? 86415000 : 75000;
                if (!strcmp(fake_mode(), "fast-ttl-highbit") || !strcmp(fake_mode(), "fast-ttl-cap")) assert(timeout == want);
            }
            a+=md_nl_align(md_nl_u16(m+a));}assert(a==end);fake_length+=fake_ack(m,fake_reply+fake_length,poison ? -EACCES : (!strcmp(fake_mode(),"fast-restart") && batches==1)?-ERESTART:(!strcmp(fake_mode(),"ack-error")||!strcmp(fake_mode(),"fast-error"))?-EEXIST:0);}
        else assert(md_nl_u16(m+4)==17&&off+len==n);
        off+=md_nl_align(len);
    }assert(off==n&&frames>=3);
    if(fast_mode() && !poison && !(!strcmp(fake_mode(),"fast-restart") && batches==1))++fast_gen;
    if(!strcmp(fake_mode(),"wrong-pid"))md_nl_put32(fake_reply+12,1);
    if(!strcmp(fake_mode(),"wrong-seq"))md_nl_put32(fake_reply+8,1);
    if(!strcmp(fake_mode(),"duplicate-ack")){memcpy(fake_reply+fake_length,fake_reply,fake_length);fake_length*=2;}
    if(!strcmp(fake_mode(),"short-send"))return (ssize_t)n-1;
    return (ssize_t)n;
}
static ssize_t __attribute__((unused)) fake_receive(int fd,struct msghdr *m,int flags){assert(fd==fake_fd&&!flags&&m->msg_iovlen==1&&fake_length<=m->msg_iov->iov_len);struct sockaddr_nl *s=m->msg_name;memset(s,0,sizeof(*s));s->nl_family=16;m->msg_namelen=sizeof(*s);memcpy(m->msg_iov->iov_base,fake_reply,fake_length);if(batches)batch_received=true;if(!strcmp(fake_mode(),"late-recv")||(!strcmp(fake_mode(),"late-add-recv")&&batches))late_ms=6000;if(!strcmp(fake_mode(),"wrong-source"))s->nl_pid=1;if(!strcmp(fake_mode(),"wrong-groups"))s->nl_groups=1;if(!strcmp(fake_mode(),"wrong-family"))s->nl_family=2;if(!strcmp(fake_mode(),"truncate"))m->msg_flags=MSG_TRUNC;return (ssize_t)fake_length;}
#define uname fake_uname
#define getsockopt fake_getsockopt
#define socket fake_socket
#define bind fake_bind
#define getsockname fake_name
#define close fake_close
#define poll fake_poll
#define sendto fake_send
#define recvmsg fake_receive
#define clock_gettime fake_clock

/* 直接纳入被测实现以调用内部 add_target；宏替换仅存在于测试 driver。 */
#include NFT_SOURCE
#ifdef __APPLE__
#undef pthread_condattr_setclock
#undef pthread_cond_timedwait
#endif

static void record(md_packet *p, unsigned type, unsigned class_, const char *text) {
    uint8_t bytes[16];
    unsigned length = type == 28 ? 16 : 4;
    if (inet_pton(type == 28 ? AF_INET6 : AF_INET, text, bytes) != 1) abort();
    size_t at = p->len;
    p->data[at] = 0xc0; p->data[at + 1] = 12;
    md_write16(p->data + at + 2, (uint16_t)type);
    md_write16(p->data + at + 4, (uint16_t)class_);
    md_write32(p->data + at + 6, 60);
    md_write16(p->data + at + 10, (uint16_t)length);
    memcpy(p->data + at + 12, bytes, length); p->len += 12 + length;
}

typedef struct { md_nft *n; md_packet packet; int rc; char error[MD_ERROR_SIZE]; } fast_thread;
static void *fast_thread_run(void *opaque) {
    fast_thread *v = opaque;
    v->rc = md_nft_apply(v->n, &v->packet, v->error);
    return NULL;
}
static void many_records(md_packet *p, bool v6, unsigned count, unsigned start) {
    p->len = 19;
    md_write16(p->data+6, (uint16_t)count);
    md_write16(p->data+8, 0);
    md_write16(p->data+10, 0);
    for (unsigned j = 0; j < count; j++) {
        char address[80]; unsigned k = start + j;
        if (v6) snprintf(address, sizeof(address), "2001:db8::%x:%x", k >> 16, k & 65535);
        else snprintf(address, sizeof(address), "10.%u.%u.%u", (k >> 16) & 255, (k >> 8) & 255, k & 255);
        record(p, v6 ? 28 : 1, 1, address);
    }
}
static void cohort_test(md_nft *n, const md_packet *base, bool v6) {
    enum { N = 32 };
    fast_thread *v = calloc(N, sizeof(*v)); assert(v);
    pthread_t threads[N];
    pthread_mutex_lock(&n->lock); n->active = true; pthread_mutex_unlock(&n->lock);
    for (unsigned i = 0; i < N; i++) {
        v[i].n = n; v[i].packet = *base;
        many_records(&v[i].packet, v6, 200, i * 200);
        assert(!pthread_create(&threads[i], NULL, fast_thread_run, &v[i]));
    }
    for (;;) {
        unsigned queued = 0;
        pthread_mutex_lock(&n->lock);
        for (nft_fast_waiter *p = n->fast_head; p; p = p->next) queued++;
        if (queued == N) { n->active = false; pthread_cond_broadcast(&n->ready); pthread_mutex_unlock(&n->lock); break; }
        pthread_mutex_unlock(&n->lock);
        struct timespec pause = {0, 1000000}; nanosleep(&pause, NULL);
    }
    for (unsigned i = 0; i < N; i++) { assert(!pthread_join(threads[i], NULL)); assert(!v[i].rc); }
    assert(!n->active && !n->fast_head && !n->fast_tail && key_count == 6400);
    free(v);
}

/* 构造 Answer/Authority/Additional 及不同 class，确认只学习符合目标的 Answer 地址。 */
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    bool v6 = !strcmp(argv[2], "ipv6"), no_answer = !strcmp(argv[2], "nodata");
    char args[512], error[MD_ERROR_SIZE] = {0};
    snprintf(args, sizeof(args), "inet,%s,%s,%s,%u", argv[3], argv[4], v6 ? "ipv6_addr" : "ipv4_addr", v6 ? (fast_mode()?128u:48u) : (fast_mode()?32u:24u));
    md_nft *n = md_nft_new(args, error);
    if (!n) { fprintf(stderr, "%s\n", error); return 3; }
    md_packet response = {0};
    const uint8_t question[] = {1,'a',0,0,1,0,1};
    memcpy(response.data + 12, question, sizeof(question)); response.len = 12 + sizeof(question);
    md_write16(response.data + 2, 0x8180); md_write16(response.data + 4, 1);
    md_write16(response.data + 6, no_answer ? 0 : 2);
    md_write16(response.data + 8, 1); md_write16(response.data + 10, 1);
    if (v6) md_write16(response.data + 15, 28);
    const char *wanted = v6 ? "2001:db8:abcd:1234::9" : "192.0.2.9";
    const char *unwanted = v6 ? "2001:db8:ffff::7" : "203.0.113.7";
    if (!no_answer) {
        record(&response, v6 ? 28 : 1, 1, wanted);
        if (!strcmp(fake_mode(), "dedup")) { record(&response, v6 ? 28 : 1, 1, wanted); md_write16(response.data + 6, 3); }
        record(&response, v6 ? 28 : 1, 3, unwanted); /* Answer CH must not learn. */
    }
    record(&response, v6 ? 28 : 1, 1, unwanted); /* Authority must not learn. */
    record(&response, v6 ? 28 : 1, 1, unwanted); /* Additional must not learn. */
    int rc;
    if(fast_mode()){
        if(v6)setenv("FAST_V6","1",1);
        rc = md_nft_enable_fast(n, error);
        if (!strcmp(fake_mode(), "fast-ttl-highbit")) md_write32(response.data+25, UINT32_MAX);
        if (!strcmp(fake_mode(), "fast-ttl-cap")) md_write32(response.data+25, 0x7fffffff);
        if (!strcmp(fake_mode(), "fast-large-answer")) many_records(&response, v6, 257, 0);
        if (!strcmp(fake_mode(), "fast-small-buffer")) many_records(&response, v6, 64, 0);
        if (!rc && !strcmp(fake_mode(), "fast-cohort")) cohort_test(n, &response, v6);
        else if (!rc && !strcmp(fake_mode(), "fast-cohort-poison")) {
            md_packet *bad = malloc(sizeof(*bad)); assert(bad); *bad = response;
            bad->data[19 + 12 + (v6 ? 16 : 4) - 1] = 255;
            nft_fast_waiter a = {.packet=&response, .until=milliseconds()+5000};
            nft_fast_waiter b = {.packet=bad, .until=a.until};
            nft_fast_waiter *group[] = {&a, &b};
            nft_fast_process(n, group, 2, a.until);
            assert(a.rc == 0 && b.rc == -1 && b.error[0]);
            free(bad);
        }
        else if (!rc) {
            rc = md_nft_apply(n, &response, error);
            if (!rc) {
                if (!strcmp(fake_mode(), "fast-renew")) md_write32(response.data+25, 120);
                if (!strcmp(fake_mode(), "fast-sequence")) n->fast->seq = UINT32_MAX - 40;
                rc = md_nft_apply(n, &response, error);
            }
        }
    }else rc = add_target(argv[1], v6 ? &n->v6 : &n->v4, &response, milliseconds() + 5000, error);
    md_nft_free(n);
    printf("{\"opens\":%u,\"closes\":%u,\"sends\":%u,\"generations\":%u,\"batches\":%u,\"keys\":%u,\"rc\":%d}\n",opens,closes,sends,generations,batches,key_count,rc);
    if (rc) { fprintf(stderr, "%s\n", error); return 4; }
    puts("nft CLI transaction completed"); return 0;
}
