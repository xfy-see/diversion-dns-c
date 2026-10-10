/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Portable wire codec. Linux constants/layout are asserted by nftset.c.
 * No sockets, retries, clocks or mutable set cache live in this header. */
/* 本头文件只读写内存中的 wire format，可在非 Linux 上测试；socket、
 * 时钟、重试与集合检查由 nftset.c 管理，Linux UAPI 常量由静态断言校验。 */
#ifndef MD_NFT_NETLINK_H
#define MD_NFT_NETLINK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* 最多 4095 个地址，每条添加消息最多 512 个；加上 batch begin/end
 * 不超过 10 条请求，缓冲区上限覆盖 IPv6 最坏情况，避免不受控分配。 */
#define MD_NL_MAX_KEYS 4095u
#define MD_NL_CHUNK_KEYS 512u
#define MD_NL_MAX_REQUESTS 10u
#define MD_NL_BUFFER_SIZE 139264u
/* 保存编码出的原始请求及偏移，用于逐条验证 ACK 的序列号和回显。
 * wire 的存储由调用方持有，在全部回包校验结束前必须保持有效且不变。 */
typedef struct {
    const uint8_t *wire;
    size_t length, count, offset[MD_NL_MAX_REQUESTS];
    uint32_t port;
    bool ack[MD_NL_MAX_REQUESTS], seen[MD_NL_MAX_REQUESTS];
} md_nl_requests;
typedef struct { uint8_t *wire; size_t capacity, length; } md_nl_writer;
/* netlink 长度/类型/序列号使用本机序，属性和消息按 4 字节对齐。
 * memcpy 避免未对齐访问；generation 和 nfgenmsg.res_id 则按协议用大端序，
 * 地址 payload 保留 DNS 提供的网络序字节。 */
static inline size_t md_nl_align(size_t n) { return (n + 3u) & ~(size_t)3u; }
static inline uint16_t md_nl_u16(const uint8_t *p) { uint16_t n; memcpy(&n,p,2); return n; }
static inline uint32_t md_nl_u32(const uint8_t *p) { uint32_t n; memcpy(&n,p,4); return n; }
static inline void md_nl_put16(uint8_t *p,uint16_t n) { memcpy(p,&n,2); }
static inline void md_nl_put32(uint8_t *p,uint32_t n) { memcpy(p,&n,4); }
static inline void md_nl_be32(uint8_t *p,uint32_t n) { p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n; }
static inline uint32_t md_nl_read_be32(const uint8_t *p) { return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }
/* 先检查剩余容量，再将包含 padding 的保留区清零；失败不越界写入。 */
static inline int md_nl_reserve(md_nl_writer *w,size_t n,size_t *at) {
    if(w->length>w->capacity||n>w->capacity-w->length)return -1;
    *at=w->length;memset(w->wire+w->length,0,n);w->length+=n;return 0;
}
static inline int md_nl_attr(md_nl_writer *w,uint16_t type,const void *data,size_t n) {
    size_t at;if(n>65531u||md_nl_reserve(w,md_nl_align(n+4),&at))return -1;
    md_nl_put16(w->wire+at,(uint16_t)(n+4));md_nl_put16(w->wire+at+2,type);
    if(n)memcpy(w->wire+at+4,data,n);return 0;
}
/* 嵌套属性先写 NLA_F_NESTED，结束时回填长度；长度包含子属性及
 * 它们的 padding，但单个属性的 nla_len 不含自己的末尾对齐填充。 */
static inline int md_nl_nested_start(md_nl_writer *w,uint16_t type,size_t *at) {
    if(md_nl_reserve(w,4,at))return -1;
    md_nl_put16(w->wire+*at+2,(uint16_t)(type|0x8000));return 0;
}
static inline int md_nl_nested_end(md_nl_writer *w,size_t at) {
    if(w->length-at>65535u)return -1;
    md_nl_put16(w->wire+at,(uint16_t)(w->length-at));return 0;
}
/* 记录每条请求是否要求 ACK；batch 边界虽不要求成功 ACK，
 * 内核仍可能对它返回错误，因此同样保留其序列号及报文偏移。 */
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
/* 一个原子 nft 批次包含 begin、分块的 NEWSETELEM 和 end；begin
 * 携带 generation，防止将按旧元数据构建的元素写入已变化的规则集。
 * 参数和缓冲区失败只表示编码失败，调用方不可发送未完成的缓冲区。 */
static inline int md_nft_nl_batch_timed_encode(uint8_t *out,size_t cap,md_nl_requests *r,uint32_t port,uint32_t seq,uint8_t family,const char *table,const char *set,const uint8_t (*keys)[16],size_t count,unsigned key_bytes,uint32_t generation,const uint64_t *timeouts) {
    if(!out||!r||!port||!seq||seq>UINT32_MAX-MD_NL_MAX_REQUESTS||!generation||!keys||!count||count>MD_NL_MAX_KEYS||(key_bytes!=4&&key_bytes!=16)||(family!=1&&family!=2&&family!=10)||!md_nl_identifier(table)||!md_nl_identifier(set))return -1;
    memset(r,0,sizeof(*r));r->wire=out;r->port=port;md_nl_writer w={out,cap,0};size_t at;uint8_t gen[4];md_nl_be32(gen,generation);
    if(md_nl_message_start(&w,r,16,1,seq++,0,10,&at)||md_nl_attr(&w,1,gen,4))return -1;md_nl_message_end(&w,at);
    for(size_t first=0;first<count;first+=MD_NL_CHUNK_KEYS){
        size_t elements;if(md_nl_message_start(&w,r,0xA0C,0x405,seq++,family,0,&at)||md_nl_attr(&w,1,table,strlen(table)+1)||md_nl_attr(&w,2,set,strlen(set)+1)||md_nl_nested_start(&w,3,&elements))return -1;
        size_t end=first+MD_NL_CHUNK_KEYS;if(end>count)end=count;
        for(size_t i=first;i<end;++i){size_t elem,key;if(md_nl_nested_start(&w,1,&elem)||md_nl_nested_start(&w,1,&key)||md_nl_attr(&w,1,keys[i],key_bytes)||md_nl_nested_end(&w,key))return -1;
            if(timeouts){uint8_t ttl[8];if(!timeouts[i])return -1;md_nl_be32(ttl,(uint32_t)(timeouts[i]>>32));md_nl_be32(ttl+4,(uint32_t)timeouts[i]);if(md_nl_attr(&w,4,ttl,8)||md_nl_attr(&w,5,ttl,8))return -1;}
            if(md_nl_nested_end(&w,elem))return -1;}
        if(md_nl_nested_end(&w,elements))return -1;md_nl_message_end(&w,at);
    }
    if(md_nl_message_start(&w,r,17,1,seq,0,10,&at))return -1;md_nl_message_end(&w,at);r->length=w.length;return 0;
}
static inline int md_nft_nl_batch_encode(uint8_t *out,size_t cap,md_nl_requests *r,uint32_t port,uint32_t seq,uint8_t family,const char *table,const char *set,const uint8_t (*keys)[16],size_t count,unsigned key_bytes,uint32_t generation) {
    return md_nft_nl_batch_timed_encode(out,cap,r,port,seq,family,table,set,keys,count,key_bytes,generation,NULL);
}
static inline int md_nft_nl_getset_encode(uint8_t *out,size_t cap,md_nl_requests *r,uint32_t port,uint32_t seq,uint8_t family,const char *table,const char *set) {
    if(!out||!r||!port||!seq||!md_nl_identifier(table)||!md_nl_identifier(set)||(family!=1&&family!=2&&family!=10))return -1;
    memset(r,0,sizeof(*r));r->wire=out;r->port=port;md_nl_writer w={out,cap,0};size_t at;
    if(md_nl_message_start(&w,r,0xA0A,1,seq,family,0,&at)||md_nl_attr(&w,1,table,strlen(table)+1)||md_nl_attr(&w,2,set,strlen(set)+1))return -1;
    md_nl_message_end(&w,at);r->length=w.length;return 0;
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
/* 扩展 ACK 只接受已知属性，校验类型、重复项、尺寸及字符串终止；
 * 未识别或格式错误的诊断不能被当成一次可靠的事务确认。 */
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
/* 回包须匹配 port、序列号及内核回显的原始请求头；重复 ACK 拒绝。
 * 被封顶的错误只回显请求头，未封顶错误还须逐字节核对原始请求。
 * 返回值区分结构错误与内核 errno，避免把合法的失败 ACK 当作成功。 */
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
/* 即使已看到最后一个成功 ACK，也扫描完整 datagram，以免漏掉其后的
 * batch 边界错误。请求状态跨 datagram 保留，调用方可继续收集剩余 ACK。 */
static inline int md_nft_nl_ack_consume(md_nl_requests *r,const uint8_t *p,size_t n,int *kernel_errno) {
    if(!r||!p||!n||n>MD_NL_BUFFER_SIZE||!kernel_errno)return -1;*kernel_errno=0;
    while(n){if(n<16)return -1;size_t len=md_nl_u32(p);if(len<16||len>n||md_nl_align(len)>n||md_nl_ack_one(r,p,len,kernel_errno))return -1;p+=md_nl_align(len);n-=md_nl_align(len);}
    return 0;
}
/* 仅要求成功 ACK 的请求参与完成判定；调用方还须检查 consume 返回值
 * 和 kernel_errno，完成判定本身不能代表内核事务成功。 */
static inline bool md_nft_nl_ack_complete(const md_nl_requests *r) { for(size_t i=0;i<r->count;++i)if(r->ack[i]&&!r->seen[i])return false;return true; }
/* One NEWGEN reply to a REQUEST-only GETGEN. Full BE32 GEN_ID is mandatory;
 * res_id is a low16 summary, not the generation used for the transaction. */
/* GETGEN 只接受一条匹配的 NEWGEN 或错误 ACK，必需的 GEN_ID 是
 * 大端 32 位属性；未知/重复字段、错误长度及缺失 generation 都返回失败。 */
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
/* GETSET metadata only: never dump elements. Require an ordinary timeout
 * address set, rejecting interval/map/constant/concatenated sets before writing.
 * Optional future attributes are length-checked, not interpreted. */
static inline int md_nft_nl_set_consume(md_nl_requests *r,const uint8_t *p,size_t n,uint8_t family,const char *table,const char *set,unsigned bytes,int *kernel_errno) {
    if(!r||r->count!=1||!p||n<20||n>MD_NL_BUFFER_SIZE||!kernel_errno||r->seen[0])return -1;
    *kernel_errno=0;size_t len=md_nl_u32(p);
    if(len!=n||md_nl_align(len)!=n||md_nl_u32(p+8)!=md_nl_u32(r->wire+8)||md_nl_u32(p+12)!=r->port)return -1;
    if(md_nl_u16(p+4)==2)return md_nl_ack_one(r,p,len,kernel_errno);
    if(md_nl_u16(p+4)!=0xA09||md_nl_u16(p+6)||p[16]!=family||p[17])return -1;
    p+=20;len-=20;unsigned seen=0;
    while(len){if(len<4)return -1;size_t a=md_nl_u16(p);unsigned t=md_nl_u16(p+2),kind=t&0x3fff;
        if(a<4||md_nl_align(a)>len||!kind)return -1;
        if(kind<=5){if(t!=kind||(seen&(1u<<kind)))return -1;seen|=1u<<kind;
            if(kind<=2){const char *want=kind==1?table:set;size_t z=strlen(want)+1;if(a!=4+z||memcmp(p+4,want,z))return -1;}
            else {if(a!=8)return -1;uint32_t v=md_nl_read_be32(p+4);if((kind==3&&v!=16)||(kind==4&&v!=(bytes==4?7u:8u))||(kind==5&&v!=bytes))return -1;}
        }
        p+=md_nl_align(a);len-=md_nl_align(a);
    }
    if(seen!=62)return -1;r->seen[0]=true;return 0;
}
#endif
