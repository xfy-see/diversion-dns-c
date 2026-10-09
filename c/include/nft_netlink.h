/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Portable wire codec. Linux constants/layout are asserted by nftset.c.
 * No sockets, retries, clocks or mutable set cache live in this header. */
#ifndef MD_NFT_NETLINK_H
#define MD_NFT_NETLINK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MD_NL_MAX_KEYS 4095u
#define MD_NL_CHUNK_KEYS 512u
#define MD_NL_MAX_REQUESTS 10u
#define MD_NL_BUFFER_SIZE 139264u
typedef struct {
    const uint8_t *wire;
    size_t length, count, offset[MD_NL_MAX_REQUESTS];
    uint32_t port;
    bool ack[MD_NL_MAX_REQUESTS], seen[MD_NL_MAX_REQUESTS];
} md_nl_requests;
typedef struct { uint8_t *wire; size_t capacity, length; } md_nl_writer;
static inline size_t md_nl_align(size_t n) { return (n + 3u) & ~(size_t)3u; }
static inline uint16_t md_nl_u16(const uint8_t *p) { uint16_t n; memcpy(&n,p,2); return n; }
static inline uint32_t md_nl_u32(const uint8_t *p) { uint32_t n; memcpy(&n,p,4); return n; }
static inline void md_nl_put16(uint8_t *p,uint16_t n) { memcpy(p,&n,2); }
static inline void md_nl_put32(uint8_t *p,uint32_t n) { memcpy(p,&n,4); }
static inline void md_nl_be32(uint8_t *p,uint32_t n) { p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n; }
static inline uint32_t md_nl_read_be32(const uint8_t *p) { return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }
static inline int md_nl_reserve(md_nl_writer *w,size_t n,size_t *at) {
    if(w->length>w->capacity||n>w->capacity-w->length)return -1;
    *at=w->length;memset(w->wire+w->length,0,n);w->length+=n;return 0;
}
static inline int md_nl_attr(md_nl_writer *w,uint16_t type,const void *data,size_t n) {
    size_t at;if(n>65531u||md_nl_reserve(w,md_nl_align(n+4),&at))return -1;
    md_nl_put16(w->wire+at,(uint16_t)(n+4));md_nl_put16(w->wire+at+2,type);
    if(n)memcpy(w->wire+at+4,data,n);return 0;
}
static inline int md_nl_nested_start(md_nl_writer *w,uint16_t type,size_t *at) {
    if(md_nl_reserve(w,4,at))return -1;
    md_nl_put16(w->wire+*at+2,(uint16_t)(type|0x8000));return 0;
}
static inline int md_nl_nested_end(md_nl_writer *w,size_t at) {
    if(w->length-at>65535u)return -1;
    md_nl_put16(w->wire+at,(uint16_t)(w->length-at));return 0;
}
static inline int md_nl_message_start(md_nl_writer *w,md_nl_requests *r,uint16_t type,uint16_t flags,uint32_t seq,uint8_t family,uint16_t subsystem,size_t *at) {
    if(!seq||r->count==MD_NL_MAX_REQUESTS||md_nl_reserve(w,20,at))return -1;
    r->offset[r->count]=*at;r->ack[r->count++]=(flags&4)!=0;
    md_nl_put16(w->wire+*at+4,type);md_nl_put16(w->wire+*at+6,flags);
    md_nl_put32(w->wire+*at+8,seq);md_nl_put32(w->wire+*at+12,r->port);
    w->wire[*at+16]=family;w->wire[*at+18]=(uint8_t)(subsystem>>8);w->wire[*at+19]=(uint8_t)subsystem;return 0;
}
static inline void md_nl_message_end(md_nl_writer *w,size_t at) { md_nl_put32(w->wire+at,(uint32_t)(w->length-at)); }
static inline bool md_nl_identifier(const char *s) {
    size_t n=0;if(!s)return false;
    for(;n<128&&s[n];++n){unsigned char c=(unsigned char)s[n];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||(n&&((c>='0'&&c<='9')||c=='-'))))return false;}
    return n>0&&n<128;
}
/* Input keys are fixed 16-byte slots; only the first key_bytes are encoded. */
static inline int md_nft_nl_batch_encode(uint8_t *out,size_t cap,md_nl_requests *r,uint32_t port,uint32_t seq,uint8_t family,const char *table,const char *set,const uint8_t (*keys)[16],size_t count,unsigned key_bytes,uint32_t generation) {
    if(!out||!r||!port||!seq||seq>UINT32_MAX-MD_NL_MAX_REQUESTS||!generation||!keys||!count||count>MD_NL_MAX_KEYS||(key_bytes!=4&&key_bytes!=16)||(family!=1&&family!=2&&family!=10)||!md_nl_identifier(table)||!md_nl_identifier(set))return -1;
    memset(r,0,sizeof(*r));r->wire=out;r->port=port;md_nl_writer w={out,cap,0};size_t at;uint8_t gen[4];md_nl_be32(gen,generation);
    if(md_nl_message_start(&w,r,16,1,seq++,0,10,&at)||md_nl_attr(&w,1,gen,4))return -1;md_nl_message_end(&w,at);
    for(size_t first=0;first<count;first+=MD_NL_CHUNK_KEYS){
        size_t elements;if(md_nl_message_start(&w,r,0xA0C,0x405,seq++,family,0,&at)||md_nl_attr(&w,1,table,strlen(table)+1)||md_nl_attr(&w,2,set,strlen(set)+1)||md_nl_nested_start(&w,3,&elements))return -1;
        size_t end=first+MD_NL_CHUNK_KEYS;if(end>count)end=count;
        for(size_t i=first;i<end;++i){size_t elem,key;if(md_nl_nested_start(&w,1,&elem)||md_nl_nested_start(&w,1,&key)||md_nl_attr(&w,1,keys[i],key_bytes)||md_nl_nested_end(&w,key)||md_nl_nested_end(&w,elem))return -1;}
        if(md_nl_nested_end(&w,elements))return -1;md_nl_message_end(&w,at);
    }
    if(md_nl_message_start(&w,r,17,1,seq,0,10,&at))return -1;md_nl_message_end(&w,at);r->length=w.length;return 0;
}
/* GETGEN requests a reply, not an additional success ACK. */
static inline int md_nft_nl_getgen_encode(uint8_t *out,size_t cap,md_nl_requests *r,uint32_t port,uint32_t seq) {
    if(!out||!r||!port||!seq)return -1;
    memset(r,0,sizeof(*r));r->wire=out;r->port=port;md_nl_writer w={out,cap,0};size_t at;
    if(md_nl_message_start(&w,r,0xA10,1,seq,0,0,&at))return -1;md_nl_message_end(&w,at);r->length=w.length;return 0;
}
static inline int md_nl_attrs_valid(const uint8_t *p,size_t n) {
    while(n){if(n<4)return -1;size_t len=md_nl_u16(p);if(len<4||md_nl_align(len)>n)return -1;p+=md_nl_align(len);n-=md_nl_align(len);}return 0;
}
static inline int md_nl_ext_ack(const uint8_t *p,size_t n) {
    unsigned seen=0;
    while(n){if(n<4)return -1;size_t len=md_nl_u16(p);uint16_t t=md_nl_u16(p+2);if(len<4||md_nl_align(len)>n)return -1;
        unsigned kind=t&0x3fff;size_t bytes=len-4;const uint8_t *v=p+4;
        if(!kind||kind>6||(seen&(1u<<kind)))return -1;seen|=1u<<kind;
        if(kind==1){if(t!=1||!bytes||bytes>256||v[bytes-1]||memchr(v,0,bytes-1))return -1;}
        else if(kind==3){if(t!=3||bytes>256)return -1;}
        else if(kind==4){if(t!=(4|0x8000)||md_nl_attrs_valid(v,bytes))return -1;}
        else if(t!=kind||bytes!=4)return -1;
        p+=md_nl_align(len);n-=md_nl_align(len);
    }return 0;
}
/* Return 0 valid ACK, -1 malformed. Kernel errno (positive) is separate.
 * Success ACKs are accepted only for requests that asked for ACK. */
static inline int md_nl_ack_one(md_nl_requests *r,const uint8_t *m,size_t length,int *kernel_errno) {
    if(length<36||md_nl_u16(m+4)!=2||(md_nl_u16(m+6)&~0x300)||md_nl_u32(m+12)!=r->port)return -1;
    size_t index=0;uint32_t seq=md_nl_u32(m+8);for(;index<r->count;++index)if(md_nl_u32(r->wire+r->offset[index]+8)==seq)break;
    if(index==r->count||r->seen[index])return -1;
    int32_t error;memcpy(&error,m+16,4);if(error>0||error< -4095)return -1;
    const uint8_t *request=r->wire+r->offset[index];size_t req_len=md_nl_u32(request);
    if(memcmp(m+20,request,16)||(!error&&!r->ack[index]))return -1;
    size_t end=36;
    if(error&&!(md_nl_u16(m+6)&0x100)){end=20+md_nl_align(req_len);if(end>length||memcmp(m+20,request,req_len))return -1;}
    if(md_nl_u16(m+6)&0x200){if(md_nl_ext_ack(m+end,length-end))return -1;}
    else if(end!=length)return -1;
    r->seen[index]=true;if(error)*kernel_errno=-error;return 0;
}
/* Caller validates recvmsg sender and truncation. Inspect the entire datagram,
 * including batch-boundary errors, before declaring the requested cohort done. */
static inline int md_nft_nl_ack_consume(md_nl_requests *r,const uint8_t *p,size_t n,int *kernel_errno) {
    if(!r||!p||!n||n>MD_NL_BUFFER_SIZE||!kernel_errno)return -1;*kernel_errno=0;
    while(n){if(n<16)return -1;size_t len=md_nl_u32(p);if(len<16||len>n||md_nl_align(len)>n||md_nl_ack_one(r,p,len,kernel_errno))return -1;p+=md_nl_align(len);n-=md_nl_align(len);}
    return 0;
}
static inline bool md_nft_nl_ack_complete(const md_nl_requests *r) { for(size_t i=0;i<r->count;++i)if(r->ack[i]&&!r->seen[i])return false;return true; }
/* One NEWGEN reply to a REQUEST-only GETGEN. Full BE32 GEN_ID is mandatory;
 * res_id is a low16 summary, not the generation used for the transaction. */
static inline int md_nft_nl_gen_consume(md_nl_requests *r,const uint8_t *p,size_t n,uint32_t *generation,int *kernel_errno) {
    if(!r||r->count!=1||!p||n<16||n>MD_NL_BUFFER_SIZE||!generation||!kernel_errno)return -1;*kernel_errno=0;
    size_t len=md_nl_u32(p);if(len>n||md_nl_align(len)!=n||len<20||md_nl_u32(p+8)!=md_nl_u32(r->wire+8)||md_nl_u32(p+12)!=r->port||r->seen[0])return -1;
    if(md_nl_u16(p+4)==2)return md_nl_ack_one(r,p,len,kernel_errno);
    if(md_nl_u16(p+4)!=0xA0F||md_nl_u16(p+6)||p[16]||p[17])return -1;
    p+=20;len-=20;unsigned seen=0;uint32_t gen=0;
    while(len){if(len<4)return -1;size_t a=md_nl_u16(p);unsigned t=md_nl_u16(p+2);if(a<4||md_nl_align(a)>len||!t||t>3||(seen&(1u<<t)))return -1;seen|=1u<<t;
        if(t==1||t==2){if(a!=8)return -1;if(t==1)gen=md_nl_read_be32(p+4);}
        else {size_t bytes=a-4;if(!bytes||bytes>16||p[a-1]||memchr(p+4,0,bytes-1))return -1;}
        p+=md_nl_align(a);len-=md_nl_align(a);
    }
    if(!(seen&2)||!gen)return -1;r->seen[0]=true;*generation=gen;return 0;
}
#endif
