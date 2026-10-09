#include "nft_netlink.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned checks;
#define CHECK(v) do { assert(v); ++checks; } while(0)
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
    for(size_t i=0;i<MD_NL_MAX_KEYS;++i)md_nl_be32(keys[i],(uint32_t)i);
    CHECK(!md_nft_nl_batch_encode(wire,MD_NL_BUFFER_SIZE,&r,41771,1000,10,"diag","learn6",(const uint8_t (*)[16])keys,MD_NL_MAX_KEYS,16,1));
    CHECK(r.count==10&&r.length<MD_NL_BUFFER_SIZE);
    for(size_t i=1;i<r.count-1;++i){z=ack(copy,&r,i,0,0);CHECK(!md_nft_nl_ack_consume(&r,copy,z,&error)&&!error);CHECK(md_nft_nl_ack_complete(&r)==(i==r.count-2));}
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
