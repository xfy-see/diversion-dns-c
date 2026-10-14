/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 公共接口：报文由调用方持有，domain/cache/nft/engine 对象由对应 free 释放。
 * err 非空时应提供 MD_ERROR_SIZE 字节；各接口的特殊返回值见下方说明。 */
#ifndef MOSDNS_C_H
#define MOSDNS_C_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>

/* len 是 data 中有效的 DNS 字节数，不包含 TCP 的两字节长度前缀。 */
#define MD_MAX_PACKET 65535
#define MD_ERROR_SIZE 512
typedef struct { uint8_t data[MD_MAX_PACKET]; size_t len; } md_packet;
/* name 为解析后的小写 ASCII 域名；end 指向问题区末尾，含 QTYPE/QCLASS。
 * udp_size 默认 512，由 OPT 更新；do_bit 表示 EDNS 的 DNSSEC OK 位。 */
typedef struct {
    char name[256]; uint16_t type, class_, flags, udp_size;
    size_t end; bool do_bit;
} md_question;
/* RR 偏移均相对于原报文；section 为 0=Answer、1=Authority、2=Additional。 */
typedef struct {
    size_t ttl_offset, data_offset; uint16_t type, class_, data_len;
    uint32_t ttl; unsigned section;
} md_rr;
typedef int (*md_rr_fn)(const md_packet *, const md_rr *, void *);
/* 无对齐要求的网络字节序读写；调用方须先确认字段在缓冲区内。 */
uint16_t md_read16(const uint8_t *p);
uint32_t md_read32(const uint8_t *p);
void md_write16(uint8_t *p, uint16_t n);
void md_write32(uint8_t *p, uint32_t n);
/* 解析时校验问题区和全部资源记录；失败返回非零，成功返回 0。
 * records 可传 NULL 回调仅校验；回调非零会使遍历返回失败。 */
int md_dns_question(const md_packet *p, md_question *q, char *err);
int md_dns_records(const md_packet *p, md_rr_fn fn, void *arg, char *err);
/* RFC 2181 high-bit handling and one-day policy cap, shared by wire/cache/nft.
 * OPT's apparent TTL carries EDNS flags and must never pass through this. */
static inline uint32_t md_dns_ttl(uint32_t ttl) {
    return ttl > UINT32_C(0x7fffffff) ? 0 : ttl > 86400u ? 86400u : ttl;
}
int md_dns_normalize_ttl(md_packet *p, char *err);
/* 校验请求/响应身份和完整结构，避免接收错误 ID、问题或损坏响应。 */
bool md_dns_response_matches(const md_packet *q, const md_packet *r);
/* 可解析时保留原问题区生成错误响应，否则生成无问题的最小头。
 * strip_opt 只原地删除末尾 OPT，非末尾 OPT 返回失败。
 * limit_udp 按请求声明的上限截断响应并置 TC，TCP 响应不经过此步骤。 */
int md_dns_error(const md_packet *q, md_packet *r, unsigned rcode);
int md_dns_strip_opt(md_packet *p);
void md_dns_limit_udp(const md_packet *q, md_packet *r);
/* 一次解析的请求：md_dns_query_parse 做与 md_dns_question 完全相同的整包校验
 * （同样的拒绝条件和错误信息），并在同一遍里记录缓存键所需的 EDNS 检查
 * （至多一个无选项、版本 0、extended RCODE 0 的 OPT，且没有其他记录）。
 * 服务端收包时解析一次，之后 engine/cache/forward/limit_udp/error 全部复用。
 * 请求报文在处理期间只读；len 不符或未解析时，*_q 接口退回兼容的自行解析。
 * route 是 engine 的分流备忘（-1 未知，0 境外，1 CN），解析时置 -1。 */
typedef struct {
    md_question q; size_t len; bool valid, cache_edns_ok; signed char route;
} md_dns_query;
int md_dns_query_parse(const md_packet *p, md_dns_query *v, char *err);
bool md_dns_query_ok(const md_packet *p, const md_dns_query *v);
int md_dns_error_q(const md_packet *q, const md_dns_query *qv, md_packet *r, unsigned rcode);
void md_dns_limit_udp_q(const md_packet *q, const md_dns_query *qv, md_packet *r);

/* 一次解析的响应索引：md_dns_view_parse 做与 md_dns_question+md_dns_records
 * 完全相同的整包校验，同时记录每条 RR 的偏移（报文 <=65535 字节，16 位足够）。
 * 之后的 view 接口只遍历数组，不再解析报文。TTL 每次从报文现读，所以原地
 * 改写 TTL / 事务 ID 后 view 仍有效；改变长度后必须重新 parse（len 校验拒绝）。
 * 最小 RR 为 11 字节，65535 字节报文最多 5956 条，上限覆盖全部合法报文。 */
#define MD_DNS_VIEW_MAX_RR 5957u
typedef struct {
    uint16_t owner_offset, ttl_offset, data_offset, type, class_, data_len;
    uint8_t section;
} md_dns_view_rr;
typedef struct {
    size_t len; md_question q;          /* q 与 md_dns_question 的输出一致 */
    size_t opt_start, opt_end; uint32_t opt_ttl;
    bool valid, has_opt, signed_;       /* signed_: TSIG 或 additional 中的 SIG(0) */
    unsigned count, addresses;          /* addresses: Answer 中 IN A/AAAA 数量 */
    md_dns_view_rr rr[MD_DNS_VIEW_MAX_RR];
} md_dns_view;
int md_dns_view_parse(const md_packet *p, md_dns_view *v, char *err);
int md_dns_view_each(const md_packet *p, const md_dns_view *v, md_rr_fn fn, void *arg, char *err);
void md_dns_view_copy(md_dns_view *dst, const md_dns_view *src);
bool md_dns_view_matches(const md_packet *q, const md_question *qq, const md_packet *r, const md_dns_view *rv);
unsigned md_dns_view_rcode(const md_packet *p, const md_dns_view *v);
int md_dns_normalize_ttl_view(md_packet *p, md_dns_view *v, char *err);
/* 当前线程的堆上 scratch view（线程退出释放）；分配失败返回 NULL。 */
md_dns_view *md_dns_view_scratch(void);
#ifdef MD_DNS_COUNT_PASSES
/* 测试构建计数（见 dns.c）：请求/响应的问题段解析、整包 RR 遍历、view 构建、name()。 */
extern _Atomic unsigned long md_dns_passes[6];
#endif

/* 规则在加载期构建，查询期只读；重复规则可去重。加载失败前已加入的规则
 * 仍保留在对象中，调用方应按需销毁，不能把失败视作事务回滚。 */
typedef struct md_domain md_domain;
md_domain *md_domain_new(void);
int md_domain_add(md_domain *d, const char *rule, char *err);
int md_domain_load(md_domain *d, const char *path, char *err);
/* With the opt-in MD_REGEX_POSIX build, regexes only see printable ASCII
 * subjects <=253 bytes after one trailing dot; other subjects are regex misses.
 * Full/domain/keyword behavior is unchanged. See REGEX-POSIX-LITE.md. */
bool md_domain_match(const md_domain *d, const char *name);
void md_domain_free(md_domain *d);

/* 缓存内部同步读写，put/get 均复制有效报文，不把调用方缓冲区挂入缓存。
 * 销毁前必须停止使用该对象的查询及后台刷新任务。 */
typedef struct md_cache md_cache;
md_cache *md_cache_new(size_t capacity, uint32_t lazy_ttl);
/* 0 miss, 1 fresh, 2 stale. now is monotonic seconds. */
int md_cache_get(md_cache *c, const md_packet *q, md_packet *r, uint64_t now);
/* 同 md_cache_get；命中时 r 已改写 TTL/ID 并完成一次整包校验，rv 为其 view。
 * 校验失败按未命中处理（r->len=0）。rv 为 NULL 时只探测命中状态（r->len=0，
 * 不交付响应），供事件循环为 CN 命中选 lane，避免 worker 处再解析一遍。 */
int md_cache_get_view(md_cache *c, const md_packet *q, md_packet *r, md_dns_view *rv, uint64_t now);
void md_cache_put(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now);
/* 同 md_cache_put，但复用调用方已为 r 构建的 view，不再解析响应。 */
void md_cache_put_view(md_cache *c, const md_packet *q, const md_packet *r, const md_dns_view *rv, uint64_t now);
/* 同上，复用请求的一次解析 qv（不再解析请求）；qv 无效时退回自行解析。 */
int md_cache_get_q(md_cache *c, const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *rv, uint64_t now);
void md_cache_put_q(md_cache *c, const md_packet *q, const md_dns_query *qv, const md_packet *r, const md_dns_view *rv, uint64_t now);
bool md_cache_refresh_begin_q(md_cache *c, const md_packet *q, const md_dns_query *qv);
void md_cache_refresh_end_q(md_cache *c, const md_packet *q, const md_dns_query *qv);
/* begin 成功表示获得该 key 的刷新标记，必须由 end 配对释放；
 * false 还可能表示容量不足或 key 不支持缓存，不能只理解为重复刷新。 */
bool md_cache_refresh_begin(md_cache *c, const md_packet *q);
void md_cache_refresh_end(md_cache *c, const md_packet *q);
void md_cache_free(md_cache *c);

/* 已解析的上游配置；设置 SO_MARK/设备绑定要求 Linux，其他平台转发报错。 */
typedef struct {
    struct sockaddr_storage address; socklen_t address_len;
    bool tcp; uint32_t so_mark; char bind_device[64]; char tag[128];
} md_upstream;
int md_parse_address(const char *s, unsigned default_port, struct sockaddr_storage *a,
                     socklen_t *len, char *err);
int md_upstream_init(md_upstream *u, const char *addr, const char *dial_addr,
                     uint32_t mark, const char *device, char *err);
/* 同步竞争若干上游，取首个可用 NOERROR/NXDOMAIN；若只有其他错误响应，
 * 写入最后的错误响应并仍返回 0。事务失败返回非零；请求缓冲区只读，
 * 各竞争者共享五秒截止时间。 */
int md_forward(const md_upstream *us, size_t count, unsigned concurrent,
               const md_packet *q, md_packet *r, char *err);
/* 同 md_forward；rv 非空时在返回且 r->len>0 时填入 r 的 view（接收时的唯一一次解析）。 */
int md_forward_view(const md_upstream *us, size_t count, unsigned concurrent,
                    const md_packet *q, md_packet *r, md_dns_view *rv, char *err);
/* 同 md_forward_view，复用请求的一次解析 qv；qv 无效时退回自行解析。 */
int md_forward_q(const md_upstream *us, size_t count, unsigned concurrent,
                 const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *rv, char *err);
/* Server workers opt in once and clean up after their final synchronous query.
 * Unscoped/library calls keep fresh sockets. Allocation failure also stays fresh. */
void md_forward_worker_enable(void);
void md_forward_worker_cleanup(void);
/* Called by a worker after replying: closes used UDP sockets and pre-opens a
 * fresh single-use UDP socket per recently used upstream (M4 port randomness).
 * When udp_sport_reuse is enabled, may also park/reuse quiet sockets within limits. */
void md_forward_worker_idle(void);
/* Opt-in limited UDP source-port reuse. Default is off: every cold UDP query gets a
 * new kernel-random ephemeral port (M4). When enabled, each worker may park a small
 * number of quiet sockets per upstream and reuse them until max_uses or ttl_ms, then
 * rotate. A socket is never shared across concurrent in-flight queries. */
typedef struct {
    unsigned enabled;   /* 0 or 1 */
    unsigned max_uses;  /* 1..256 queries per socket before rotate */
    unsigned ttl_ms;    /* 100..60000 ms max age from open */
    unsigned pool_size; /* 1..4 parked sockets per worker per upstream */
} md_udp_sport_reuse;
void md_forward_set_udp_sport_reuse(const md_udp_sport_reuse *cfg);
void md_forward_get_udp_sport_reuse(md_udp_sport_reuse *cfg);

/* nft 对象负责提取响应 Answer 中 IN 类 A/AAAA 并更新既有集合。
 * 创建只解析参数，Linux 写入在 apply 执行；销毁前调用方须确保所有
 * apply 调用及等待者已经结束。 */
typedef struct md_nft md_nft;
md_nft *md_nft_new(const char *args, char *err);
int md_nft_enable_fast(md_nft *n, char *err);
int md_nft_apply(md_nft *n, const md_packet *r, char *err);
/* 同 md_nft_apply，复用 r 的 view；view 已完成整包校验，收集阶段不再解析。 */
int md_nft_apply_view(md_nft *n, const md_packet *r, const md_dns_view *rv, char *err);
/* 只读检查兼容路径的目标集合，interval set 缺少 auto-merge 时向 stderr 告警；
 * 读取失败时静默，不改变内核状态，也不影响返回结果。 */
void md_nft_audit(const md_nft *n);
void md_nft_free(md_nft *n);

/* engine 拥有不可变分流配置、规则、缓存、nft 和监听器。
 * listener 返回借用指针，entry 固定为 0；重新加载须建立新的 engine/cache。 */
typedef struct md_engine md_engine;
typedef struct { char listen[256]; bool tcp; size_t entry; unsigned idle_timeout; } md_listener;
/* Both modes load rule files and resolve named IPv6 scopes. check=true
 * never opens listeners/upstream connections or writes nft. */
md_engine *md_engine_load(const char *path, bool check, char *err);
size_t md_engine_listener_count(const md_engine *e);
const md_listener *md_engine_listener(const md_engine *e, size_t i);
/* 服务端过载保护，配置加载时已校验范围。queue_timeout_ms=0 表示排队任务不过期；
 * TCP 读/写期限单位为秒，连接数上限对所有 TCP listener 合计。 */
typedef struct {
    unsigned queue_timeout_ms, tcp_read_timeout, tcp_write_timeout;
    unsigned tcp_max_connections, tcp_max_connections_per_ip;
} md_server_limits;
const md_server_limits *md_engine_server_limits(const md_engine *e);
int md_engine_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r, char *err);
/* Event-loop dispatch. Only a fresh foreign cache hit (no nft, no refresh) is
 * answered here: MD_LANE_REPLY with r holding the final response. Otherwise
 * r->len=0 and the result names the worker lane so a dead upstream group
 * cannot delay the other group or cached answers: CACHED (CN cache hits that
 * still need nft, stale hits, invalid input), CN or FOREIGN upstream misses. */
enum { MD_LANE_CACHED, MD_LANE_CN, MD_LANE_FOREIGN, MD_LANE_COUNT, MD_LANE_REPLY = MD_LANE_COUNT };
unsigned md_engine_dispatch(md_engine *e, size_t entry, const md_packet *q, md_packet *r);
/* True only for MD_LANE_REPLY; CN cache hits still use workers for mandatory
 * nft finalization and lazy refresh. Leaves r->len=0 otherwise. */
bool md_engine_cached_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r);
/* 同 dispatch/query，复用服务端收包时的一次解析 qv，并在 qv->route 记住分流
 * 结果（dispatch 与 worker 不再各做一次域名匹配）。qv 无效时退回自行解析。 */
unsigned md_engine_dispatch_q(md_engine *e, size_t entry, const md_packet *q, md_dns_query *qv, md_packet *r);
int md_engine_query_q(md_engine *e, size_t entry, const md_packet *q, md_dns_query *qv, md_packet *r, char *err);
/* 销毁等待后台刷新结束；调用方先停服务/查询，避免访问已释放插件。 */
void md_engine_free(md_engine *e);
/* 单调时钟秒数，用于 TTL 和到期判断，不是 Unix 时间戳。 */
uint64_t md_now(void);
/* 单调时钟毫秒数，供服务端排队期限和 TCP 读写期限使用。 */
uint64_t md_now_ms(void);
/* CLOCK_MONOTONIC 纳秒；与同机其他进程的 CLOCK_MONOTONIC 可直接比较。 */
uint64_t md_now_ns(void);

/* ---- 可选的逐请求阶段计时（诊断用，默认关闭）----
 * 只有启动时设置环境变量 DIVERSION_TRACE=<文件路径> 才开启；未设置时
 * md_trace_cur 恒为 NULL，各打点只是一次线程局部读取和分支，不取时钟、
 * 不写文件，DNS/缓存/nft/上游语义完全不变。开启后每个请求结束时写一行
 * TSV（格式见 docs/tail-latency-attribution.md），时间为 CLOCK_MONOTONIC 纳秒，
 * 0 表示该阶段未发生。只用于受控测量，不用于生产。 */
enum {
    MD_T_RECV, MD_T_DISPATCHED, MD_T_ENQUEUE, MD_T_PICKUP, MD_T_ENGINE0,
    MD_T_UP_SEND, MD_T_UP_RECV, MD_T_NFT0, MD_T_NFT_IO, MD_T_NFT1, MD_T_ENGINE1,
    MD_T_REPLY, MD_T_COUNT
};
enum {
    MD_TF_HIT_FRESH = 1u << 0, MD_TF_HIT_STALE = 1u << 1, MD_TF_REFRESH_START = 1u << 2,
    MD_TF_UP_TCP = 1u << 3, MD_TF_UP_TC_FALLBACK = 1u << 4, MD_TF_NFT_FAST = 1u << 5,
    MD_TF_NFT_CLI = 1u << 6, MD_TF_NFT_LEADER = 1u << 7, MD_TF_FOLLOWER = 1u << 8,
    MD_TF_ERROR = 1u << 9, MD_TF_STALE_DROP = 1u << 10, MD_TF_LOOP_REPLY = 1u << 11,
    MD_TF_TCP = 1u << 12, MD_TF_REFRESH_JOB = 1u << 13
};
typedef struct {
    uint64_t t[MD_T_COUNT];
    uint32_t flags, up_resends, up_attempts;
    unsigned lane;
} md_trace;
extern bool md_trace_enabled;
extern _Thread_local md_trace *md_trace_cur;
static inline void md_trace_mark(unsigned stage) {
    if (md_trace_cur) md_trace_cur->t[stage] = md_now_ns();
}
static inline void md_trace_mark_first(unsigned stage) {
    if (md_trace_cur && !md_trace_cur->t[stage]) md_trace_cur->t[stage] = md_now_ns();
}
static inline void md_trace_flag(uint32_t flag) { if (md_trace_cur) md_trace_cur->flags |= flag; }
/* 进程启动时读取环境变量；失败只告警，不影响服务。 */
void md_trace_init(void);
/* 写一行记录：q 为请求报文（取 ID/QTYPE/QNAME），可为 NULL。 */
void md_trace_emit(const md_trace *t, const md_packet *q);
void md_trace_close(void);
/* pthread_create with at least MD_THREAD_STACK bytes of stack. musl defaults to
 * 128 KiB and a small RLIMIT_STACK shrinks glibc's default; larger platform
 * defaults are kept. Returns pthread_create's error number. */
#define MD_THREAD_STACK (1024u * 1024u)
int md_thread_create(pthread_t *thread, void *(*fn)(void *), void *arg);
/* 阻塞运行监听器与 worker；SIGINT/SIGTERM 触发回收，返回后可释放 engine。
 * workers 是每条 lane（缓存/CN/国外）各自的线程数，各 lane 独立排队和限额。 */
int md_server_run(md_engine *e, unsigned workers, char *err);
#endif
