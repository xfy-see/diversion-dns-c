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
#include <unistd.h>
#include <linux/netlink.h>
#include "nft_netlink.h"
/* 仅替换 netlink 传输和时钟；CLI 子进程仍接收真实参数，便于核验接口边界。 */
static const int fake_fd=2147483646;
static uint8_t fake_reply[MD_NL_BUFFER_SIZE];static size_t fake_length;
static unsigned opens,closes,sends,generations,batches,key_count,post_receive_clocks;static uint64_t late_ms;static bool batch_received;
static const char *fake_mode(void){const char *s=getenv("FAKE_MODE");return s?s:"normal";}
static int __attribute__((unused)) fake_clock(clockid_t id,struct timespec *t){if(batch_received&&!strcmp(fake_mode(),"late-parse")&&++post_receive_clocks==2)late_ms=6000;int rc=clock_gettime(id,t);if(!rc&&id==CLOCK_MONOTONIC){t->tv_sec+=(time_t)(late_ms/1000);t->tv_nsec+=(long)(late_ms%1000)*1000000;if(t->tv_nsec>=1000000000){++t->tv_sec;t->tv_nsec-=1000000000;}}return rc;}
static int __attribute__((unused)) fake_socket(int family,int type,int protocol){assert(family==16&&type==(SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK)&&protocol==12);++opens;return fake_fd;}
static int __attribute__((unused)) fake_bind(int fd,const struct sockaddr *p,socklen_t n){assert(fd==fake_fd&&n==sizeof(struct sockaddr_nl));const struct sockaddr_nl *s=(const struct sockaddr_nl *)p;assert(s->nl_family==16&&!s->nl_pid&&!s->nl_groups);return 0;}
static int __attribute__((unused)) fake_name(int fd,struct sockaddr *p,socklen_t *n){assert(fd==fake_fd&&*n==sizeof(struct sockaddr_nl));struct sockaddr_nl *s=(struct sockaddr_nl *)p;s->nl_pid=41771;return 0;}
static int __attribute__((unused)) fake_close(int fd){if(fd==fake_fd){++closes;return 0;}return close(fd);}
static int __attribute__((unused)) fake_poll(struct pollfd *p,nfds_t n,int ms){if(n==1&&p->fd==fake_fd){assert(ms>0&&ms<=5000);if(!strcmp(fake_mode(),"late-wake")||(!strcmp(fake_mode(),"late-add-wake")&&batches))late_ms=6000;p->revents=p->events;return 1;}return poll(p,n,ms);}
static size_t __attribute__((unused)) fake_ack(const uint8_t *q,uint8_t *out,int error){memset(out,0,36);md_nl_put32(out,36);md_nl_put16(out+4,2);if(error)md_nl_put16(out+6,0x100);md_nl_put32(out+8,md_nl_u32(q+8));md_nl_put32(out+12,41771);int32_t e=error;memcpy(out+16,&e,4);memcpy(out+20,q,16);return 36;}
static ssize_t __attribute__((unused)) fake_send(int fd,const void *data,size_t n,int flags,const struct sockaddr *peer,socklen_t size){
    assert(fd==fake_fd&&!flags&&size==sizeof(struct sockaddr_nl));const struct sockaddr_nl *k=(const struct sockaddr_nl *)peer;assert(k->nl_family==16&&!k->nl_pid&&!k->nl_groups);++sends;fake_length=0;const uint8_t *p=data;
    if(md_nl_u16(p+4)==0xA10){++generations;assert(n==20&&md_nl_u16(p+6)==1&&md_nl_u32(p+12)==41771);
        if(!strcmp(fake_mode(),"gen-error")){fake_length=fake_ack(p,fake_reply,-EPERM);return (ssize_t)n;}
        uint32_t gen=!strcmp(fake_mode(),"zero-gen")?0:(!strcmp(fake_mode(),"changed-gen")&&generations==2)?8:7;
        memset(fake_reply,0,28);md_nl_put32(fake_reply,28);md_nl_put16(fake_reply+4,0xA0F);md_nl_put32(fake_reply+8,md_nl_u32(p+8));md_nl_put32(fake_reply+12,41771);fake_reply[19]=(uint8_t)gen;md_nl_put16(fake_reply+20,8);md_nl_put16(fake_reply+22,1);md_nl_be32(fake_reply+24,gen);fake_length=28;return (ssize_t)n;
    }
    ++batches;size_t off=0;unsigned frames=0;
    while(off<n){const uint8_t *m=p+off;size_t len=md_nl_u32(m);assert(len<=n-off&&len>=20&&md_nl_u32(m+12)==41771);++frames;
        if(md_nl_u16(m+4)==16){assert(frames==1&&len==28&&md_nl_u16(m+6)==1&&md_nl_read_be32(m+24)==7);}
        else if(md_nl_u16(m+4)==0xA0C){assert(md_nl_u16(m+6)==0x405);size_t a=20;a+=md_nl_align(md_nl_u16(m+a));a+=md_nl_align(md_nl_u16(m+a));assert(md_nl_u16(m+a+2)==(3|0x8000));size_t end=a+md_nl_u16(m+a);a+=4;while(a<end){++key_count;assert(md_nl_u16(m+a+2)==(1|0x8000)&&md_nl_u16(m+a+6)==(1|0x8000)&&md_nl_u16(m+a+10)==1);a+=md_nl_align(md_nl_u16(m+a));}assert(a==end);fake_length+=fake_ack(m,fake_reply+fake_length,!strcmp(fake_mode(),"ack-error")?-EEXIST:0);}
        else assert(md_nl_u16(m+4)==17&&off+len==n);
        off+=md_nl_align(len);
    }assert(off==n&&frames>=3);
    if(!strcmp(fake_mode(),"wrong-pid"))md_nl_put32(fake_reply+12,1);
    if(!strcmp(fake_mode(),"wrong-seq"))md_nl_put32(fake_reply+8,1);
    if(!strcmp(fake_mode(),"duplicate-ack")){memcpy(fake_reply+fake_length,fake_reply,fake_length);fake_length*=2;}
    if(!strcmp(fake_mode(),"short-send"))return (ssize_t)n-1;
    return (ssize_t)n;
}
static ssize_t __attribute__((unused)) fake_receive(int fd,struct msghdr *m,int flags){assert(fd==fake_fd&&!flags&&m->msg_iovlen==1&&fake_length<=m->msg_iov->iov_len);struct sockaddr_nl *s=m->msg_name;memset(s,0,sizeof(*s));s->nl_family=16;m->msg_namelen=sizeof(*s);memcpy(m->msg_iov->iov_base,fake_reply,fake_length);if(batches)batch_received=true;if(!strcmp(fake_mode(),"late-recv")||(!strcmp(fake_mode(),"late-add-recv")&&batches))late_ms=6000;if(!strcmp(fake_mode(),"wrong-source"))s->nl_pid=1;if(!strcmp(fake_mode(),"wrong-groups"))s->nl_groups=1;if(!strcmp(fake_mode(),"wrong-family"))s->nl_family=2;if(!strcmp(fake_mode(),"truncate"))m->msg_flags=MSG_TRUNC;return (ssize_t)fake_length;}
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

/* 构造 Answer/Authority/Additional 及不同 class，确认只学习符合目标的 Answer 地址。 */
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    bool v6 = !strcmp(argv[2], "ipv6"), no_answer = !strcmp(argv[2], "nodata");
    char args[512], error[MD_ERROR_SIZE] = {0};
    snprintf(args, sizeof(args), "inet,%s,%s,%s,%u", argv[3], argv[4], v6 ? "ipv6_addr" : "ipv4_addr", v6 ? 48u : 24u);
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
    int rc = add_target(argv[1], v6 ? &n->v6 : &n->v4, &response, milliseconds() + 5000, error);
    md_nft_free(n);
    printf("{\"opens\":%u,\"closes\":%u,\"sends\":%u,\"generations\":%u,\"batches\":%u,\"keys\":%u,\"rc\":%d}\n",opens,closes,sends,generations,batches,key_count,rc);
    if (rc) { fprintf(stderr, "%s\n", error); return 4; }
    puts("nft CLI transaction completed"); return 0;
}
