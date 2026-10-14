/* 纯内存 wire 测试：golden 编码、ACK 来源/请求对应、逐字节截断和 generation 校验。 */
#include "nft_netlink.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned checks;
#define CHECK(v) do { assert(v); ++checks; } while(0)
/* 构造可控 ACK，分别覆盖完整请求回显和 capped 回显；不调用 socket。 */
static size_t ack(uint8_t *out,const md_nl_requests *r,size_t i,int error,unsigned flags) {
    const uint8_t *q=r->wire+r->offset[i];size_t copied=error&&!(flags&0x100)?md_nl_u32(q):16;
    size_t n=20+md_nl_align(copied);memset(out,0,n);md_nl_put32(out,(uint32_t)n);md_nl_put16(out+4,2);md_nl_put16(out+6,(uint16_t)flags);md_nl_put32(out+8,md_nl_u32(q+8));md_nl_put32(out+12,r->port);int32_t e=error;memcpy(out+16,&e,4);memcpy(out+20,q,copied);return n;
}
static size_t gen_reply(uint8_t *out,uint32_t port,uint32_t seq,uint32_t g) {
    memset(out,0,44);md_nl_put32(out,44);md_nl_put16(out+4,0xA0F);md_nl_put32(out+8,seq);md_nl_put32(out+12,port);out[18]=(uint8_t)(g>>8);out[19]=(uint8_t)g;
    md_nl_put16(out+20,8);md_nl_put16(out+22,1);md_nl_be32(out+24,g);md_nl_put16(out+28,8);md_nl_put16(out+30,2);md_nl_be32(out+32,123);md_nl_put16(out+36,8);md_nl_put16(out+38,3);memcpy(out+40,"nft",4);return 44;
}
int main(void) {
    char nonterminated[128];memset(nonterminated,'a',sizeof(nonterminated));CHECK(!md_nl_identifier(nonterminated));
    uint8_t *wire=malloc(MD_NL_BUFFER_SIZE),*reply=malloc(MD_NL_BUFFER_SIZE),*copy=malloc(MD_NL_BUFFER_SIZE);
    uint8_t (*keys)[16]=calloc(MD_NL_MAX_KEYS,sizeof(*keys));assert(wire&&reply&&copy&&keys);
    const uint8_t v4[4]={192,0,2,9};memcpy(keys[0],v4,4);md_nl_requests r;int error;
    CHECK(!md_nft_nl_batch_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,700,1,"diag","learn4",(const uint8_t (*)[16])keys,1,4,0x12345678));
    const uint8_t golden_begin[]={28,0,0,0,16,0,1,0,188,2,0,0,43,163,0,0,0,0,0,10,8,0,1,0,18,52,86,120};
    CHECK(!memcmp(wire,golden_begin,sizeof(golden_begin)));
    CHECK(r.count==3&&r.ack[1]&&!r.ack[0]&&!r.ack[2]&&md_nl_u16(wire+r.offset[1]+4)==0xA0C&&md_nl_u16(wire+r.offset[1]+6)==0x405);
    CHECK(md_nl_u16(wire+r.offset[1]+6)==(1|4|0x400));
    /* Manually expected nested IPv4 payload, no timeout/interval attributes. */
    const uint8_t payload[]={1,0,0,0,9,0,1,0,'d','i','a','g',0,0,0,0,11,0,2,0,'l','e','a','r','n','4',0,0,20,0,3,128,16,0,1,128,12,0,1,128,8,0,1,0,192,0,2,9};
    CHECK(md_nl_u32(wire+r.offset[1])==16+sizeof(payload)&&!memcmp(wire+r.offset[1]+16,payload,sizeof(payload)));
    size_t n=ack(reply,&r,1,0,0);md_nl_requests saved=r;
    CHECK(!md_nft_nl_ack_consume(&r,reply,n,&error)&&!error&&md_nft_nl_ack_complete(&r));
    CHECK(md_nft_nl_ack_consume(&r,reply,n,&error)<0); /* duplicate */
    r=saved;size_t boundary=ack(copy,&r,0,0,0);CHECK(md_nft_nl_ack_consume(&r,copy,boundary,&error)<0); /* unrequested success */
    /* 所有截断长度都必须失败，避免只测试一两个固定短报文。 */
    for(size_t cut=0;cut<n;++cut){r=saved;CHECK(md_nft_nl_ack_consume(&r,reply,cut,&error)<0);}
    const size_t offsets[]={0,4,6,8,12,16,20,24,26,28,32};
    for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i){r=saved;memcpy(copy,reply,n);copy[offsets[i]]^=1;CHECK(md_nft_nl_ack_consume(&r,copy,n,&error)<0);}
    const int errors[]={ENOENT,EPERM,EINVAL,EEXIST,ENOMEM};
    for(size_t i=0;i<5;++i)for(unsigned capped=0;capped<2;++capped){r=saved;size_t z=ack(copy,&r,1,-errors[i],capped?0x100:0);CHECK(!md_nft_nl_ack_consume(&r,copy,z,&error)&&error==errors[i]);}
    r=saved;size_t z=ack(copy,&r,1,-EINVAL,0);copy[36]^=1;CHECK(md_nft_nl_ack_consume(&r,copy,z,&error)<0); /* echoed payload */
    r=saved;z=ack(copy,&r,1,-EINVAL,0x300);md_nl_writer w={copy,MD_NL_BUFFER_SIZE,z};CHECK(!md_nl_attr(&w,1,"fixture",8));md_nl_put32(copy,(uint32_t)w.length);CHECK(!md_nft_nl_ack_consume(&r,copy,w.length,&error)&&error==EINVAL);
    r=saved;memcpy(copy,reply,n);z=ack(copy+n,&r,2,-EINVAL,0x100);CHECK(!md_nft_nl_ack_consume(&r,copy,n+z,&error)&&error==EINVAL); /* inspect full datagram */
    CHECK(md_nft_nl_batch_encode(wire,20,&r,41771,700,1,"diag","learn4",(const uint8_t (*)[16])keys,1,4,1)<0);
    CHECK(md_nft_nl_batch_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,700,1,"diag","learn4",(const uint8_t (*)[16])keys,1,4,0)<0);
    CHECK(md_nft_nl_batch_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,700,1,"diag","9bad",(const uint8_t (*)[16])keys,1,4,1)<0);
    CHECK(md_nft_nl_batch_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,700,1,"diag","learn4",(const uint8_t (*)[16])keys,MD_NL_MAX_KEYS+1,4,1)<0);
    /* 最大 IPv6 批量验证拆分后的全部 ACK 到齐，不能首个成功就结束。 */
    for(size_t i=0;i<MD_NL_MAX_KEYS;++i)md_nl_be32(keys[i],(uint32_t)i);
    CHECK(!md_nft_nl_batch_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,1000,10,"diag","learn6",(const uint8_t (*)[16])keys,MD_NL_MAX_KEYS,16,1));
    CHECK(r.count==10&&r.length<MD_NL_BUFFER_SIZE);
    for(size_t i=1;i<r.count-1;++i){z=ack(copy,&r,i,0,0);CHECK(!md_nft_nl_ack_consume(&r,copy,z,&error)&&!error);CHECK(md_nft_nl_ack_complete(&r)==(i==r.count-2));}
    {   /* Stage 4: one GENID batch carrying an IPv4 and an IPv6 set equals begin + the two
         * single-set NEWSETELEM messages (same bytes, consecutive sequence numbers) + end. */
        uint8_t (*k4)[16]=calloc(2,16),(*k6)[16]=calloc(1,16);uint64_t t4[2]={75000,90000},t6[1]={75000};assert(k4&&k6);
        memcpy(k4[0],v4,4);k4[1][0]=198;k4[1][1]=18;k4[1][3]=7;k6[0][0]=0xfd;k6[0][1]=0xaa;k6[0][15]=9;
        md_nl_set_keys groups[2]={{1,"diag","learn4",(const uint8_t (*)[16])k4,2,4,t4},{1,"diag","learn6",(const uint8_t (*)[16])k6,1,16,t6}};
        md_nl_requests rm,r4,r6;uint8_t *w4=malloc(4096),*w6=malloc(4096);assert(w4&&w6);
        CHECK(!md_nft_nl_batch_multi_encode(wire,MD_NL_BUFFER_SIZE,&rm,41771,900,0x55,groups,2));
        CHECK(rm.count==4&&!rm.ack[0]&&rm.ack[1]&&rm.ack[2]&&!rm.ack[3]);
        CHECK(!md_nft_nl_batch_timed_encode(w4,4096,&r4,41771,900,1,"diag","learn4",(const uint8_t (*)[16])k4,2,4,0x55,t4));
        CHECK(!md_nft_nl_batch_timed_encode(w6,4096,&r6,41771,901,1,"diag","learn6",(const uint8_t (*)[16])k6,1,16,0x55,t6));
        size_t m4=r4.offset[2]-r4.offset[1],m6=r6.offset[2]-r6.offset[1];
        CHECK(!memcmp(wire,w4,r4.offset[1])); /* identical begin with generation */
        CHECK(rm.offset[2]-rm.offset[1]==m4&&!memcmp(wire+rm.offset[1],w4+r4.offset[1],m4));
        CHECK(rm.offset[3]-rm.offset[2]==m6&&!memcmp(wire+rm.offset[2],w6+r6.offset[1],m6));
        CHECK(md_nl_u32(wire+rm.offset[3]+8)==903&&md_nl_u16(wire+rm.offset[3]+4)==17&&rm.length==rm.offset[3]+20);
        /* Both NEWSETELEM must be ACKed before the multi-set batch counts as complete. */
        size_t za=ack(copy,&rm,1,0,0);CHECK(!md_nft_nl_ack_consume(&rm,copy,za,&error)&&!error&&!md_nft_nl_ack_complete(&rm));
        za=ack(copy,&rm,2,0,0);CHECK(!md_nft_nl_ack_consume(&rm,copy,za,&error)&&!error&&md_nft_nl_ack_complete(&rm));
        /* Single-group multi encode is byte-identical to the historical encoder. */
        CHECK(!md_nft_nl_batch_multi_encode(wire,MD_NL_BUFFER_SIZE,&rm,41771,900,0x55,groups,1)&&rm.length==r4.length&&!memcmp(wire,w4,r4.length));
        groups[1].set="9bad";CHECK(md_nft_nl_batch_multi_encode(wire,MD_NL_BUFFER_SIZE,&rm,41771,900,0x55,groups,2)<0);
        CHECK(md_nft_nl_batch_multi_encode(wire,MD_NL_BUFFER_SIZE,&rm,41771,900,0x55,groups,3)<0);
        free(k4);free(k6);free(w4);free(w6);
    }
    CHECK(!md_nft_nl_getgen_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,697));CHECK(r.length==20&&!r.ack[0]&&md_nl_u16(wire+4)==0xA10);saved=r;
    uint32_t g;z=gen_reply(copy,41771,697,0x12345678);CHECK(!md_nft_nl_gen_consume(&r,copy,z,&g,&error)&&g==0x12345678&&!error);
    CHECK(md_nft_nl_gen_consume(&r,copy,z,&g,&error)<0);
    r=saved;z=gen_reply(copy,41771,697,65536);CHECK(!md_nft_nl_gen_consume(&r,copy,z,&g,&error)&&g==65536);
    r=saved;z=gen_reply(copy,41771,697,0);CHECK(md_nft_nl_gen_consume(&r,copy,z,&g,&error)<0);
    for(size_t cut=0;cut<44;++cut){r=saved;gen_reply(copy,41771,697,1);CHECK(md_nft_nl_gen_consume(&r,copy,cut,&g,&error)<0);}
    const size_t gen_offsets[]={0,4,6,8,12,16,17,20,22,28,30,36,38,43};
    for(size_t i=0;i<sizeof(gen_offsets)/sizeof(gen_offsets[0]);++i){r=saved;gen_reply(copy,41771,697,1);copy[gen_offsets[i]]^=1;CHECK(md_nft_nl_gen_consume(&r,copy,44,&g,&error)<0);}
    r=saved;z=ack(copy,&r,0,-EPERM,0x100);CHECK(!md_nft_nl_gen_consume(&r,copy,z,&g,&error)&&error==EPERM);
    free(wire);free(reply);free(copy);free(keys);printf("{\"passed\":true,\"assertions\":%u,\"sockets_used\":false}\n",checks);return 0;
}
