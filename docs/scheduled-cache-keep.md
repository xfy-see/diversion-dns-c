# 常用境外域名定时预热（默认关闭）

`cache_keep_file` 让一个小的固定名单在没有客户端访问时也按 TTL 刷新，减少空闲后首次访问的 DNS 等待。它仅优化 DNS；不预连接网站、不缓存网页、不改变浏览器 DoH、TLS 或路由。

```ini
cache_size=4096
cache_keep_file=/etc/diversion-dns-c/foreign-keep.txt
cache_keep_qps=2
cache_keep_percent=10
```

固定名单可从 `c/examples/foreign-keep.txt` 复制。每行格式是 `<flags> <qtype> <具体域名>`：flags 默认 0，1/2/4 分别表示 AD/CD/DO 缓存键位；qtype 只允许 1（A）或 28（AAAA）。域名转为小写、重复键去重，不接受通配符、IP、URL、空标签、结尾点或未知类型。AD/CD/DO 不同、大小写不同的客户端查询仍是独立缓存键，本功能不改变原缓存键策略；需要哪种标志组合应明确列出，不自动扩大为所有组合。HTTPS RR 暂未支持定时维护。

示例名单包含 ChatGPT/OpenAI、Claude/Anthropic、Google 31 个常用入口和资源名称，A/AAAA 合计 62 键；是可裁剪的起始名单，不是完整网站依赖，也不保证每个名称两种地址都有答案。通配 CDN、租户专用名称应从实际访问补充。参考：
- [OpenAI 网络域名说明](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)
- [Claude 应用域名说明](https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions)
- [Google 主机名单](https://support.google.com/a/answer/6334001)

## 行为和边界

- 名单文件与 `cache_warm_file` 独立：前者只读、人工维护；后者由程序定期覆盖，只用于重启预热。相同路径或同一 inode 被配置检查拒绝。名单修改后需重启；未提供热重载。
- `check` 完整读取验证名单，不查询上游。配置失败或监听失败不启动定时查询。拒绝符号链接、FIFO、设备、NUL、超过 64 KiB、超过 1024 行或 256 唯一有效键的文件。有效境外键数不得超过缓存条目容量的一半；不锁定缓存条目、不绕过字节上限。
- 按 CN 规则分类的名称会跳过并统计加载时跳过行数。其余始终用配置的 foreign 上游、mark、接口及正常响应校验/缓存逻辑；不会把境外地址学习到 CN nft set，也不引入直连 DNS fallback。
- 仅一条后台查询同时进行，不使用用户查询的 worker/队列。`cache_keep_qps` 为 1–2、默认 2；是维护任务启动速率上限，不包括配置的上游并发、重试或用户流量。每次结束后再间隔，超时后不追赶补发。串行慢查询可能延后其他名单项的刷新，不能承诺全名单永远新鲜。
- 正向缓存按原 TTL 剩余 `cache_keep_percent`（1–50，默认 10）百分比提前刷新，每键加 0.75–1.25 倍错峰。每键至少间隔 5 秒；TTL 很短时允许自然到期，不人为延长新鲜期。检查元数据不修改 LRU、热度、用户计数，也不复制报文。
- 失败按每键 5/10/20/40/60 秒退避，并与 stale/访问预取共享后台刷新占位及已有缓存退避。没有旧条目时同样限制失败重试。恢复后的有效答案正常替换；有效 NXDOMAIN/NODATA 撤销旧地址。负答案不提前刷新，最少 30 秒；TTL=0、空 NODATA、无法入缓存的答案也最少 30 秒。
- 是否提供旧答案、旧答案最大期限仍由现有 `cache_stale_*` 或 legacy lazy 配置决定；开启定时维护不自动开启 stale。可继续用 `cache_stale_override` 为 DDNS 禁止旧答案。不要把 DDNS 或短 TTL 动态名称加入固定名单，除非确有需要。
- 后台探测不计入 `fresh_hit`/`miss_cold`、不提升访问热度；独立计数 `keep_query`、`keep_ok`、`keep_fail`、`keep_deferred`。`keep_ok` 是有效 DNS 完成，包含有效负答案，不代表一定有地址或已入缓存；`refresh_kept_old` 仍是共用缓存安全机制的计数。
- 默认关闭时没有新后台线程/定时扫描、没有前台新增时钟读取。启用时名单状态最多约 76 KiB，两个 DNS 报文缓冲合计约 128 KiB，另有已有维护线程栈和 DNS scratch；RSS 需要在设备上测量。名单查询持续产生一定额外 DNS 流量，应按 TTL 和实际使用裁剪。

## 验证与回退

运行 GitHub 构建产物：`python3 c/tests/cache_keep_test.py --application /path/to/verified/mosdns-c --output /new/result/directory`。该测试只使用回环模拟上游，保留请求、响应、日志和失败记录；已接入 `make test` 和下载包验证器。设备应另用隔离端口测试 A/AAAA、无人访问刷新、上游失败恢复、短 TTL/负答案、真实域名、用户查询性能、RSS、nft 无误写及正式配置保护。

回退：删除三项 `cache_keep_*` 配置并重启即可关闭；固定文件不会被改写，现有路由、nft 与缓存策略不因关闭而变化。回退旧二进制前也必须删除新键，否则旧版会拒绝未知配置。
