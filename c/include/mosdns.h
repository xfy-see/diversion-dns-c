/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 公共接口：报文由调用方持有，domain/cache/nft/engine 对象由对应 free 释放。
 * err 非空时应提供 MD_ERROR_SIZE 字节；各接口的特殊返回值见下方说明。 */
#ifndef MOSDNS_C_H
#define MOSDNS_C_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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
/* 校验请求/响应身份和完整结构，避免接收错误 ID、问题或损坏响应。 */
bool md_dns_response_matches(const md_packet *q, const md_packet *r);
/* 可解析时保留原问题区生成错误响应，否则生成无问题的最小头。
 * strip_opt 只原地删除末尾 OPT，非末尾 OPT 返回失败。
 * limit_udp 按请求声明的上限截断响应并置 TC，TCP 响应不经过此步骤。 */
int md_dns_error(const md_packet *q, md_packet *r, unsigned rcode);
int md_dns_strip_opt(md_packet *p);
void md_dns_limit_udp(const md_packet *q, md_packet *r);

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
void md_cache_put(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now);
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
/* Server workers opt in once and clean up after their final synchronous query.
 * Unscoped/library calls keep fresh sockets. Allocation failure also stays fresh. */
void md_forward_worker_enable(void);
void md_forward_worker_cleanup(void);

/* nft 对象负责提取响应 Answer 中 IN 类 A/AAAA 并更新既有集合。
 * 创建只解析参数，Linux 写入在 apply 执行；销毁前调用方须确保所有
 * apply 调用及等待者已经结束。 */
typedef struct md_nft md_nft;
md_nft *md_nft_new(const char *args, char *err);
int md_nft_apply(md_nft *n, const md_packet *r, char *err);
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
int md_engine_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r, char *err);
/* Always returns false: cached responses use normal workers for mandatory nft
 * finalization and lazy refresh. Leaves r->len=0 when r is non-NULL. */
bool md_engine_cached_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r);
/* 销毁等待后台刷新结束；调用方先停服务/查询，避免访问已释放插件。 */
void md_engine_free(md_engine *e);
/* 单调时钟秒数，用于 TTL 和到期判断，不是 Unix 时间戳。 */
uint64_t md_now(void);
/* 阻塞运行监听器与 worker；SIGINT/SIGTERM 触发回收，返回后可释放 engine。 */
int md_server_run(md_engine *e, unsigned workers, char *err);
#endif
