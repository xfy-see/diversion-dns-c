/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Included by nftset.c: opt-in plain timeout sets, no CLI or subprocesses.
 * The active token protects all state. Each cohort completes only after ACK.
 * GETGEN before every cohort invalidates dedup after external ruleset changes.
 * Read existing expiration on cache misses to avoid shortening another name's
 * live mapping (including after restart or a bounded-cache collision). */
#define NFT_FAST_SLOTS 2048u
#define NFT_FAST_WIRE 270336u
#define NFT_FAST_COHORT 32u
struct nft_fast_waiter {
    struct nft_fast_waiter *next;
    const md_packet *packet;
    uint64_t until;
    bool working, done;
    int rc;
    char error[MD_ERROR_SIZE];
};
typedef struct { uint8_t key[16]; uint64_t expires; unsigned bytes; } nft_fast_entry;
struct nft_fast_state {
    int fd;
    uint32_t port, seq, generation;
    bool metadata[2];
    nft_fast_entry entries[2][NFT_FAST_SLOTS];
    uint8_t keys[MD_NL_MAX_KEYS][16];
    uint64_t timeouts[MD_NL_MAX_KEYS];
    uint8_t wire[NFT_FAST_WIRE], receive[MD_NL_BUFFER_SIZE];
};
static void nft_fast_free(nft_fast_state *s) { if(s){if(s->fd>=0)close(s->fd);free(s);} }
static void nft_fast_invalidate(nft_fast_state *s) {
    memset(s->entries,0,sizeof(s->entries));s->metadata[0]=s->metadata[1]=false;s->generation=0;
}
static uint32_t nft_fast_seq(nft_fast_state *s) {
    /* Reopen before wrap so stale datagrams cannot match a reused sequence. */
    if(s->seq>UINT32_MAX-32u)return 0;
    uint32_t seq=s->seq;s->seq+=16;return seq;
}
static int nft_fast_open(md_nft *n,char *err) {
    if(!n->fast){n->fast=calloc(1,sizeof(*n->fast));if(!n->fast){snprintf(err,MD_ERROR_SIZE,"allocate bounded fast nft state");return -1;}n->fast->fd=-1;}
    nft_fast_state *s=n->fast;
    if(s->fd>=0&&s->seq<=UINT32_MAX-32u)return 0;
    if(s->fd>=0)close(s->fd);
    s->fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,NETLINK_NETFILTER);
    if(s->fd<0){snprintf(err,MD_ERROR_SIZE,"open fast nft socket: %s",strerror(errno));return -1;}
    struct sockaddr_nl local={.nl_family=AF_NETLINK};socklen_t size=sizeof(local);
    if(bind(s->fd,(struct sockaddr *)&local,sizeof(local))||getsockname(s->fd,(struct sockaddr *)&local,&size)||size!=sizeof(local)||local.nl_family!=AF_NETLINK||!local.nl_pid||local.nl_groups){
        snprintf(err,MD_ERROR_SIZE,"bind fast nft socket: %s",strerror(errno));close(s->fd);s->fd=-1;return -1;
    }
    s->port=local.nl_pid;s->seq=1;nft_fast_invalidate(s);return 0;
}
static unsigned nft_fast_slot(const uint8_t *key,unsigned bytes) {
    uint32_t h=2166136261u;for(unsigned i=0;i<bytes;i++)h=(h^key[i])*16777619u;return h&(NFT_FAST_SLOTS-1u);
}
static uint8_t nft_fast_family(const nft_target *t) {return !strcmp(t->family,"inet")?1:!strcmp(t->family,"ip")?2:10;}
static int nft_fast_metadata(nft_fast_state *s,const nft_target *t,uint64_t until,char *err) {
    uint8_t request[320];md_nl_requests requests;size_t length;int e=0;
    if(md_nft_nl_getset_encode(request,sizeof(request),&requests,s->port,nft_fast_seq(s),nft_fast_family(t),t->table,t->set)||
       nft_nl_send(s->fd,request,requests.length,until,err)||nft_nl_receive(s->fd,s->receive,sizeof(s->receive),&length,until,err))return -1;
    if(md_nft_nl_set_consume(&requests,s->receive,length,nft_fast_family(t),t->table,t->set,t->bytes,&e)){
        snprintf(err,MD_ERROR_SIZE,"fast nft target must be a plain timeout IPv%u set",t->bytes==4?4u:6u);return -1;
    }
    if(e){snprintf(err,MD_ERROR_SIZE,"fast nft metadata: %s",strerror(e));return -1;}return 0;
}
/* Query exactly one element, not a set dump. ENOENT is a normal cache miss.
 * Attribute traversal validates nesting and returned key before expiration. */
static int nft_fast_existing(nft_fast_state *s,const nft_target *t,const uint8_t key[16],uint64_t until,uint64_t *remaining,char *err) {
    uint8_t request[384];md_nl_requests req={0};req.wire=request;req.port=s->port;
    md_nl_writer w={request,sizeof(request),0};size_t at,es,elem,k,length;int e=0;*remaining=0;
    if(md_nl_message_start(&w,&req,0xA0D,1,nft_fast_seq(s),nft_fast_family(t),0,&at)||md_nl_attr(&w,1,t->table,strlen(t->table)+1)||md_nl_attr(&w,2,t->set,strlen(t->set)+1)||md_nl_nested_start(&w,3,&es)||md_nl_nested_start(&w,1,&elem)||md_nl_nested_start(&w,1,&k)||md_nl_attr(&w,1,key,t->bytes)||md_nl_nested_end(&w,k)||md_nl_nested_end(&w,elem)||md_nl_nested_end(&w,es))return -1;
    md_nl_message_end(&w,at);req.length=w.length;
    if(nft_nl_send(s->fd,request,w.length,until,err)||nft_nl_receive(s->fd,s->receive,sizeof(s->receive),&length,until,err))return -1;
    uint8_t *p=s->receive;
    if(length<20||md_nl_u32(p)!=length||md_nl_u32(p+8)!=md_nl_u32(request+8)||md_nl_u32(p+12)!=s->port)goto invalid;
    if(md_nl_u16(p+4)==2){if(md_nl_ack_one(&req,p,length,&e))goto invalid;if(e==ENOENT)return 0;snprintf(err,MD_ERROR_SIZE,"fast nft element read: %s",strerror(e?e:EPROTO));return -1;}
    if(md_nl_u16(p+4)!=0xA0C||md_nl_u16(p+6)||p[16]!=nft_fast_family(t)||p[17])goto invalid;
    p+=20;length-=20;unsigned seen=0;bool found=false;
    while(length){if(length<4)goto invalid;size_t a=md_nl_u16(p);unsigned type=md_nl_u16(p+2);if(a<4||md_nl_align(a)>length)goto invalid;
        if(type==1||type==2){const char *v=type==1?t->table:t->set;if((seen&(1u<<type))||a!=strlen(v)+5||memcmp(p+4,v,a-4))goto invalid;seen|=1u<<type;}
        else if(type==(3|0x8000)){
            if(seen&8)goto invalid;seen|=8;const uint8_t *el=p+4;size_t eln=a-4;
            if(eln<4||md_nl_u16(el)!=eln||md_nl_u16(el+2)!=(1|0x8000))goto invalid;
            el+=4;eln-=4;unsigned fields=0;
            while(eln){if(eln<4)goto invalid;size_t z=md_nl_u16(el);unsigned ty=md_nl_u16(el+2);if(z<4||md_nl_align(z)>eln)goto invalid;
                if(ty==(1|0x8000)){if(fields&1||z!=8+t->bytes||md_nl_u16(el+4)!=4+t->bytes||md_nl_u16(el+6)!=1||memcmp(el+8,key,t->bytes))goto invalid;fields|=1;}
                else if(ty==5){if(fields&2||z!=12)goto invalid;fields|=2;*remaining=((uint64_t)md_nl_read_be32(el+4)<<32)|md_nl_read_be32(el+8);}
                el+=md_nl_align(z);eln-=md_nl_align(z);
            }
            if(fields!=3)goto invalid;found=true;
        }
        p+=md_nl_align(a);length-=md_nl_align(a);
    }
    if(seen!=14||!found)goto invalid;return 0;
invalid:snprintf(err,MD_ERROR_SIZE,"invalid fast nft element metadata");return -1;
}
typedef struct {nft_fast_state *s;const nft_target *t;size_t count;uint64_t until;} nft_fast_keys;
static int nft_fast_collect(const md_packet *p,const md_rr *rr,void *arg) {
    nft_fast_keys *v=arg;
    if(rr->section||rr->class_!=1||rr->type!=(v->t->bytes==4?1:28))return 0;
    if(rr->data_len!=v->t->bytes||milliseconds()>=v->until)return -1;
    const uint8_t *key=p->data+rr->data_offset;uint64_t ttl=(uint64_t)rr->ttl*1000+5000;
    for(size_t i=0;i<v->count;i++)if(!memcmp(v->s->keys[i],key,v->t->bytes)){if(v->s->timeouts[i]<ttl)v->s->timeouts[i]=ttl;return 0;}
    if(v->count==MD_NL_MAX_KEYS)return -1;
    memset(v->s->keys[v->count],0,16);memcpy(v->s->keys[v->count],key,v->t->bytes);v->s->timeouts[v->count++]=ttl;return 0;
}
static int nft_fast_target(nft_fast_state *s,const nft_target *t,unsigned family_index,nft_fast_waiter **cohort,size_t count,uint64_t until,char *err) {
    if(!t->enabled)return 0;
    nft_fast_keys v={s,t,0,until};
    for(size_t i=0;i<count;i++)if(md_dns_records(cohort[i]->packet,nft_fast_collect,&v,err))return -1;
    if(!v.count)return 0;
    uint32_t gen;
    if(nft_nl_generation(s->fd,s->port,nft_fast_seq(s),s->receive,until,&gen,err))return -1;
    if(gen!=s->generation){nft_fast_invalidate(s);s->generation=gen;}
    if(!s->metadata[family_index]){
        if(nft_fast_metadata(s,t,until,err))return -1;
        uint32_t after;if(nft_nl_generation(s->fd,s->port,nft_fast_seq(s),s->receive,until,&after,err))return -1;
        if(after!=gen){snprintf(err,MD_ERROR_SIZE,"nft generation changed during fast metadata validation");return -1;}
        s->metadata[family_index]=true;
    }
    size_t pending=0;uint64_t now=milliseconds();
    for(size_t i=0;i<v.count;i++){
        nft_fast_entry *entry=&s->entries[family_index][nft_fast_slot(s->keys[i],t->bytes)];
        bool known=entry->bytes==t->bytes&&!memcmp(entry->key,s->keys[i],t->bytes)&&entry->expires>now;
        /* The 4s slack covers TTL rounding and DNS/cache clock boundaries. */
        if(known&&entry->expires>=now+s->timeouts[i]-4000)continue;
        uint64_t existing=known?entry->expires-now:0;
        if(!known&&nft_fast_existing(s,t,s->keys[i],until,&existing,err))return -1;
        if(existing>s->timeouts[i])s->timeouts[i]=existing+1000;
        if(pending!=i){memcpy(s->keys[pending],s->keys[i],16);s->timeouts[pending]=s->timeouts[i];}pending++;
    }
    if(!pending)return 0;
    /* Snapshot generation after readback, then use it as batch precondition.
     * A change invalidates the entire cohort; callers must not receive success. */
    uint32_t before;if(nft_nl_generation(s->fd,s->port,nft_fast_seq(s),s->receive,until,&before,err))return -1;
    if(before!=gen){snprintf(err,MD_ERROR_SIZE,"nft generation changed before fast update");return -1;}
    md_nl_requests requests;
    if(md_nft_nl_batch_timed_encode(s->wire,sizeof(s->wire),&requests,s->port,nft_fast_seq(s),nft_fast_family(t),t->table,t->set,(const uint8_t (*)[16])s->keys,pending,t->bytes,gen,s->timeouts)){snprintf(err,MD_ERROR_SIZE,"encode fast nft batch");return -1;}
    uint64_t sent_at=milliseconds();
    if(nft_nl_send(s->fd,s->wire,requests.length,until,err))return -1;
    do {size_t length;int e=0;if(nft_nl_receive(s->fd,s->receive,sizeof(s->receive),&length,until,err))return -1;
        if(md_nft_nl_ack_consume(&requests,s->receive,length,&e)){snprintf(err,MD_ERROR_SIZE,"invalid fast nft ACK; mutation state unknown");return -1;}
        if(e){snprintf(err,MD_ERROR_SIZE,"fast nft update: %s",strerror(e));return -1;}
    }while(!md_nft_nl_ack_complete(&requests));
    uint32_t after;if(nft_nl_generation(s->fd,s->port,nft_fast_seq(s),s->receive,until,&after,err))return -1;
    if(after!=gen+1u){snprintf(err,MD_ERROR_SIZE,"nft generation changed around fast commit");return -1;}
    s->generation=after;
    for(size_t i=0;i<pending;i++){nft_fast_entry *entry=&s->entries[family_index][nft_fast_slot(s->keys[i],t->bytes)];memcpy(entry->key,s->keys[i],16);entry->bytes=t->bytes;entry->expires=sent_at+s->timeouts[i];}
    return 0;
}
static int nft_fast_cohort(md_nft *n,nft_fast_waiter **cohort,size_t count,uint64_t until,char *err) {
    if(nft_fast_open(n,err))return -1;
    int rc=nft_fast_target(n->fast,&n->v4,0,cohort,count,until,err);
    if(!rc)rc=nft_fast_target(n->fast,&n->v6,1,cohort,count,until,err);
    if(!rc&&milliseconds()>=until){snprintf(err,MD_ERROR_SIZE,"fast nft deadline exceeded");rc=-1;}
    if(rc){nft_fast_invalidate(n->fast);close(n->fast->fd);n->fast->fd=-1;}
    return rc;
}
static int nft_fast_apply(md_nft *n,const md_packet *r,char *err) {
    nft_fast_waiter self={.packet=r,.until=milliseconds()+5000};
    int lock_rc=pthread_mutex_lock(&n->lock);if(lock_rc){snprintf(err,MD_ERROR_SIZE,"fast nft mutex: %s",strerror(lock_rc));return -1;}
    if(n->fast_tail)n->fast_tail->next=&self;else n->fast_head=&self;n->fast_tail=&self;
    while(!self.done){
        if(!n->active&&n->fast_head==&self){
            nft_fast_waiter *cohort[NFT_FAST_COHORT];size_t count=0;uint64_t until=self.until;
            while(n->fast_head&&count<NFT_FAST_COHORT){nft_fast_waiter *p=n->fast_head;n->fast_head=p->next;p->working=true;cohort[count++]=p;if(p->until<until)until=p->until;}
            if(!n->fast_head)n->fast_tail=NULL;n->active=true;pthread_mutex_unlock(&n->lock);
            char message[MD_ERROR_SIZE]={0};int rc=nft_fast_cohort(n,cohort,count,until,message);
            pthread_mutex_lock(&n->lock);
            for(size_t i=0;i<count;i++){cohort[i]->rc=rc;snprintf(cohort[i]->error,MD_ERROR_SIZE,"%s",message);cohort[i]->done=true;}
            n->active=false;pthread_cond_broadcast(&n->ready);
        }else{
            /* Once selected the leader owns our stack pointer until done.
             * Its bounded I/O deadline applies to all selected members. */
            if(self.working){pthread_cond_wait(&n->ready,&n->lock);continue;}
            struct timespec deadline={(time_t)(self.until/1000),(long)(self.until%1000)*1000000};
            int rc=pthread_cond_timedwait(&n->ready,&n->lock,&deadline);
            if(rc&&!self.working&&!self.done){
                nft_fast_waiter **p=&n->fast_head,*previous=NULL;while(*p!=&self){previous=*p;p=&(*p)->next;}*p=self.next;if(n->fast_tail==&self)n->fast_tail=previous;
                self.rc=-1;snprintf(self.error,MD_ERROR_SIZE,"fast nft queue timeout/error: %s",strerror(rc));self.done=true;pthread_cond_broadcast(&n->ready);
            }
        }
    }
    pthread_mutex_unlock(&n->lock);if(self.rc)snprintf(err,MD_ERROR_SIZE,"%s",self.error);return self.rc;
}
