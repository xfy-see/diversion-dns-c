# 固定 CN-site DNS 分流配置

当前 `mosdns-c` 是专用的 CN-site / foreign 分流器。运行时只读取本页定义的
`key=value` 配置；不再解析 YAML、JSON、include、plugin tag 或 sequence。
[历史 site-only YAML](go-profiles-site-only.yaml) 保留为迁移输入和历史证据，不能直接启动当前程序。

## 固定请求链

1. 校验 DNS 问题，按原始问题的 QNAME 匹配加载完成的 CN 域名集合
2. 查询整个引擎共享的一份缓存
3. 未命中时，CN 问题只使用 CN 上游组，其他问题只使用 foreign 上游组
4. CN 问题有响应时，执行已配置的 nft 地址学习；新鲜或 stale 缓存命中也走这一步
5. 返回响应；UDP 按客户端容量处理截断，TCP 保持完整响应

上游失败不会跨组 fallback。CNAME 和 Answer 地址都不会重新决定路由；只有原始
QNAME 决定 CN/foreign。所有监听器使用同一条固定链。规则、路由、上游和配置在
引擎生命周期内不可变，没有热重载；修改配置或规则后必须重启，旧缓存不会跨引擎复用。
因此不需要在同一引擎的缓存 key 里额外保存 route ID。

cache key 保留问题名大小写、QTYPE、QCLASS 和 AD/CD/DO；当前仅缓存合格的 IN 查询。
其他 class、带 EDNS options、非 OPT 附加数据或压缩问题会绕过缓存。DNS 事务 ID 不属于
cache key，命中时改为当前请求 ID。nft 学习失败会使查询失败，不能用缓存跳过学习来掩盖错误。

## CLI 与路径

```sh
./mosdns-c check -c c/examples/minimal.conf
./mosdns-c start -c c/examples/minimal.conf --cpu 4
./mosdns-c check -d /etc/mosdns -c config.conf
```

默认配置文件名是 `config.conf`。`start/check/version/help` 保留；`--cpu` 是每条 worker lane
（缓存命中 / CN 上游 / 国外上游）的线程数，范围 1–64，默认 4（共 12 个线程），只用于 `start`。

`-d/--dir` 先改变进程工作目录，然后读取配置。相对配置路径和每个 `cn_domain_file`
都相对于这个工作目录，而非配置文件所在目录。没有 `include`，也不展开 `~` 或环境变量。
根目录的 [config.conf](../config.conf) 和 [minimal.conf](../c/examples/minimal.conf)
使用仓库相对的演示规则；请在仓库根目录运行，或通过 `-d` 指向该目录。

`check` 与 `start` 使用相同的配置解析和规则加载：它读取全部 CN 规则文件，编译 regexp，
验证必填资源、数值、监听地址和 nft 参数。缺失文件或错误规则会立即失败，报告配置或
规则的文件路径及行号。`check` 不打开 listener、不给上游发包、不调用 nft 写入，也不验证
端口能否绑定、上游是否可达、Linux mark/接口权限、nft 可执行文件或目标集合是否存在。
例外：在 Linux 上能只读访问 nf_tables 时，`check`/`start` 会用 Netlink GETSET 检查默认（非 fast）
路径的 interval 目标集合，缺少 `auto-merge` 时打印告警；读取失败不报错，也不影响退出码。
命名 IPv6 scope（如 `%eth0`）会查询本机接口索引；这仍不能证明实际网络可用。
它是完整规则预检，不是运行环境验收。

## 文本格式

- 一行一个 `key=value`；第一个 `=` 分隔 key 和 value
- key 区分大小写；key/value 两端的 ASCII 空白被去除，空值被拒绝
- 空行和去除前导空白后以 `#` 开头的整行注释被忽略
- 没有行尾注释；`cn_domain_file=rules#backup.txt` 的 `#` 是文件名的一部分
- 没有引号、转义、字符串插值、列表语法或续行；双引号也是字面内容
- 重复的列表键按出现顺序追加；重复的单值键和未知键报错，不能后值覆盖前值
- 每行最多 4096 字节，不包含 LF；CRLF 的 CR 仍计入该上限。文件最多 1 MiB
- 嵌入 NUL 和非空白控制字节被拒绝；错误带 `文件:行号`
- 数值为完整无符号十进制；只有 mark 额外接受 `0x` / `0X` 十六进制。无正负号、单位、八进制或浮点数，前导零仍按十进制解释

例如以下路径含空格，无需也不能加引号：

```conf
cn_domain_file=rules/cn sites.txt
```

以下不是注释，会因为数值内容非法而失败：

```conf
cache_size=1024 # explanation
```

## 完整键表

| 键 | 次数 / 范围 | 省略时 |
|---|---|---|
| `listen_udp` | 列表，数字 IPv4/IPv6 地址 | 无 UDP listener |
| `listen_tcp` | 列表，数字 IPv4/IPv6 地址 | 无 TCP listener |
| `cn_domain_file` | 必填列表，1–64 个规则文件 | 报错 |
| `cn_upstream` | 必填列表，1–64 个数字 UDP/TCP 上游 | 报错 |
| `foreign_upstream` | 必填列表，1–64 个数字 UDP/TCP 上游 | 报错 |
| `cache_size` | 单值，0–10000000 条；0 禁用缓存 | 1024 |
| `cache_lazy_ttl` | 单值，0–4294967295 秒；旧键：正向回答**自写入起**的总保留时间（不是 TTL 之后追加）；0 关闭。与 `cache_stale_ttl*`/`cache_stale_override` 互斥 | 0 |
| `cache_stale_ttl` | 单值，0–86400 秒；国外组正向回答在 **TTL 到期之后**可额外 stale 服务的秒数（RFC 8767）；建议 30–120 | 0（关闭） |
| `cache_stale_ttl_cn` | 单值，0–86400 秒；CN 组同上 | 0（关闭） |
| `cache_stale_answer_ttl` | 单值，1–300 秒；stale 回答中写入的 TTL | `cache_stale_ttl*` 模式 30；旧 lazy 模式 5 |
| `cache_stale_override` | 列表，最多 8 项，`<秒>:<域名规则文件>`（规则语法同 `cn_domain_file`）；首个匹配生效，覆盖该域名 stale 秒数，0 禁用（DDNS、快速切换） | 无 |
| `cache_prefetch_percent` | 单值，0–50；被复用（≥2 次命中）的新鲜条目剩余 TTL ≤ 原 TTL×百分比（抖动 0.75–1.25×）时后台预取；建议 10 | 0（关闭） |
| `cache_prefetch_max` | 单值，1–64；并发预取上限（同时受总刷新上限 64 约束）；需 `cache_prefetch_percent` | 8 |
| `cache_max_bytes` | 单值，0 或 4096–4294967295；按字节限制缓存（每条按 96 字节固定开销 + key + 报文计） | 0（仅条目上限） |
| `cache_foreign_reserve_percent` | 单值，0–90；国外条目占用不超过该比例（条目与字节）时，淘汰优先取 CN 条目，CN 冷门域名不能挤掉国外热点 | 0（全局 LRU） |
| `cache_warm_file` | 单值；重启预热文件路径，只保存域名（不保存 IP），原子写入（同目录临时文件 + fsync + rename） | 不预热 |
| `cache_warm_max` | 单值，1–10000；保存/预热的最多名称数；需 `cache_warm_file` | 512 |
| `cache_warm_qps` | 单值，1–100；启动预热的速率（单线程顺序） | 10 |
| `cache_warm_save_interval` | 单值，30–86400 秒；周期保存间隔（退出时也保存） | 600 |
| `cache_keep_file` | 固定境外域名定时维护名单，只读；详见 [定时预热](scheduled-cache-keep.md) | 关闭 |
| `cache_keep_qps` | 1–2，单并发后台维护任务速率；需 `cache_keep_file` | 2 |
| `cache_keep_percent` | 1–50，TTL 提前刷新百分比并错峰；需 `cache_keep_file` | 10 |
| `cn_mark` / `foreign_mark` | 各一个 uint32，十进制或 `0x` | 0，不设置 mark |
| `cn_interface` / `foreign_interface` | 各一个，1–63 可打印 ASCII 字节，不含空白或斜杠 | 不绑定接口 |
| `cn_concurrent` / `foreign_concurrent` | 各一个，1–3 | 1 |
| `tcp_idle_timeout` | 单值，所有 TCP listener 共用，1–86400 秒 | 30 |
| `tcp_read_timeout` | 单值，一个 TCP 帧从首字节到收完的期限，1–300 秒 | 5 |
| `tcp_write_timeout` | 单值，一个 TCP 回复从开始写到写完的期限，1–300 秒 | 10 |
| `tcp_max_connections` | 单值，所有 TCP listener 合计的连接上限，1–1024 | 128 |
| `tcp_max_connections_per_ip` | 单值，同一来源地址的 TCP 连接上限，1–1024 | 32 |
| `queue_timeout_ms` | 单值，请求在 lane 中排队的最长时间，0–60000 毫秒；0 表示不过期 | 2000 |
| `nftset_ipv4` | 单值，五段逗号格式，IPv4 mask 1–32 | 不学习 IPv4 |
| `nftset_ipv6` | 单值，五段逗号格式，IPv6 mask 1–128 | 不学习 IPv6 |
| `nftset_fast` | 单值，0/1；1 要求 Linux ≥6.12、/32 或 /128 和预建普通 timeout set | 0 |
| `nftset_hit_window_ms` | 单值，0–10000 毫秒；热命中跳过窗口，0 关闭（每个 CN 回答都核对/写入内核），需要 nft 目标 | 1000 |
| `udp_sport_reuse` | 单值，0/1；1 启用有限上游 UDP 源端口复用（削弱每查询端口唯一性） | 0 |
| `udp_sport_reuse_max_uses` | 单值，1–256；每个 socket 复用查询次数上限（仅 `udp_sport_reuse=1` 时生效） | 16 |
| `udp_sport_reuse_ttl_ms` | 单值，100–60000 毫秒；socket 自打开起的最长存活（仅启用时生效） | 2000 |
| `udp_sport_reuse_pool` | 单值，1–4；每 worker 每上游可停放的空闲 UDP socket 数（仅启用时生效） | 2 |

必须至少配置一个 listener。UDP 和 TCP listener **合计最多 64 个**，同一传输中的重复
数字地址被拒绝。`cache_size=0` 时，非零 `cache_lazy_ttl` 或任何 `cache_stale_*`/`cache_prefetch_*`/`cache_max_bytes`/`cache_foreign_reserve_percent`/`cache_warm_*` 键会报错。

监听地址及上游的缺省端口为 53，显式端口为 1–65535。使用明确数字地址；不支持 hostname
或 `:53` 的空主机缩写。监听所有 IPv4 地址可写 `0.0.0.0:53`。带端口的 IPv6 必须加方括号。
上游可以写 `192.0.2.1`、`udp://192.0.2.1:53`、`tcp://[2001:db8::1]:5353`，不支持
TLS/HTTPS/QUIC、SOCKS、bootstrap、`dial_addr` 或每个端点单独覆盖 mark/接口。
组内所有端点继承本组 mark 和接口。并发和端点顺序继续使用原来的 `md_forward` 行为，
首个可用 NOERROR/NXDOMAIN 获胜；没有因此增加跨组 fallback。

### nftset 参数

```conf
nftset_ipv4=inet,mosdns_cn,cn_site4,ipv4_addr,32
nftset_ipv6=inet,mosdns_cn,cn_site6,ipv6_addr,128
```

格式是 `family,table,set,address_type,mask`，恰好五段，无段内空白、隐含字段或缺省 mask。
IPv4 key 要求 `family=inet|ip` 且 `address_type=ipv4_addr`；IPv6 key 要求
`family=inet|ip6` 且 `address_type=ipv6_addr`。mask 不能为 0。表名和集合名为 1–127
字节，以 ASCII 字母或下划线开头，后续仅字母、数字、下划线或连字符。

nft 执行模块保留原语义：只学习 Answer 中 IN A/AAAA，不读取 CNAME 目标来改变路由，
不学习 Authority/Additional。普通地址集合使用原 Linux Netlink generation 检查、事务和
完整成功回执（generation 窗口内用 Netlink GETSET 校验元数据，冲突时有界重试 3 次）；interval 集合保留原 argv/stdin CLI 与前缀行为
（是否 interval 也由 GETSET 判断，不再调用 `nft list set`）。没有 auto-merge 的 interval 集合遇到重叠前缀时跳过冲突元素、
写入其余元素并正常回答，打印限速告警；`check`/`start` 对缺少 auto-merge 的 interval 目标只告警。mask 对 interval 集合生效，
普通集合写入具体地址。集合必须预先存在，程序不会创建表或集合，不发送元素 TTL，
继续使用集合默认 timeout，也没有用户态 membership 缓存或维护线程。

只有配置了 nft 的 CN 响应会调用该模块，foreign 响应不会学习。保留的重要边界是：
模块先检查 Linux 支持和标准路径里的 `nft`，然后才可能因没有可学习地址跳过内核写入。
因此 CN 的空回答、NXDOMAIN 或没有 A/AAAA 的回答并不保证绕过这项环境要求；
非 Linux 上配置 nft 的 CN 请求仍会失败。FIFO 等待、元数据检查和写入共用原 5 秒预算。
不明确的提交结果不会自动重放，查询路径会报告失败。

## 过载保护

- 每条 lane（缓存/CN/国外）各有 `--cpu` 个 worker 和 64 个未完成请求配额，lane 满时 UDP 回 SERVFAIL、TCP 关闭连接
- worker 取出排队超过 `queue_timeout_ms` 的请求时直接回 SERVFAIL，不访问上游；默认 2000 ms，小于常见客户端 2–5 秒的超时。
  选择回 SERVFAIL 而不是静默丢弃：与 lane 满时行为一致，TCP 连接必须得到回复才能继续，仍在等待的客户端可以立即重试其他服务器
- 除 DNS ID 外字节完全相同的 CN/国外查询共享正在进行的上游交换，回复只改写 ID；跟随者计入 lane 配额
- TCP 待写回复不计入 lane 配额；`tcp_read_timeout`/`tcp_write_timeout` 限制单帧读取和单个回复写出的总时长，
  `tcp_idle_timeout` 限制两次进展之间的空闲时间
- 达到 `tcp_max_connections_per_ip` 或 `tcp_max_connections` 时，先淘汰最久无进展的空闲连接，其次淘汰回复写不出去的连接；
  等待 worker 的连接不淘汰，都不可淘汰时拒绝新连接。IPv6 按完整地址计数
- 最坏情况报文对象内存约（3×64 + `tcp_max_connections`）× 128 KiB，按需分配

## 缓存、stale 与预取

- 容量有界，hash + 每组（CN/国外）一条 LRU，跨组按全局使用序号比较，默认等价于一条全局 LRU；
  容量单位是条目，可再加 `cache_max_bytes` 字节上限；`cache_foreign_reserve_percent` 为国外热点保留份额
- NXDOMAIN 保留 30 秒，SERVFAIL 保留 5 秒；空 Answer 的 NOERROR 受记录最小 TTL 和 300 秒上限约束，没有可用 TTL 时不缓存；
  这些负面/错误回答都不会 stale 服务
- 旧键 `cache_lazy_ttl` 保持原语义：正向回答从最初存储时刻开始计算的**总**保留时间（TTL 大于它时会更早删除），
  stale 记录 TTL 为 5 秒。新键 `cache_stale_ttl`（国外）/`cache_stale_ttl_cn`（CN）是 **TTL 到期之后**追加的秒数，
  硬截止 = 写入时刻 + TTL + stale 秒数，stale 回答 TTL 默认 30 秒（RFC 8767 建议）。两套键互斥
- stale 命中立即回答旧数据并尝试异步刷新；同 key 刷新去重（stale 刷新与预取共用占位），总计最多 64 个刷新任务。
  后台刷新启动尝试另受每个引擎 64 次/秒、突发 8 次的令牌桶限制（分配/线程创建失败也消耗令牌）；前台首次查询不受此预算影响。
  同 key 连续失败后按 5、10、20、30 秒退避（之后保持 30 秒），成功恢复重置；等待下一次命中触发，不延长旧答案硬截止
- **后台刷新/预取/预热**得到 SERVFAIL（或超时、无响应）时，硬截止前**不替换**仍有效的正向旧回答
  ；后台刷新任务失败计入 `refresh_fail`，确实保留同代旧正答案时计入 `refresh_kept_old`（包括传输超时）。
  合法的 NXDOMAIN、NODATA 或地址变化正常替换；TTL=0、空 NODATA、超出字节预算或分配失败无法保存新回答时，也撤销旧项。
  畸形、截断、不匹配、签名响应或暂时错误不会据此撤销旧项。前台未命中时的 SERVFAIL 照旧缓存 5 秒
- 预取：被复用（≥2 次命中，固定）的正向新鲜条目在剩余 TTL ≤ TTL×`cache_prefetch_percent`%（每条随机抖动 0.75–1.25×，
  至少 1 秒，TTL<2 秒不预取）时由 worker 启动一次后台刷新；每个已存回答最多认领一次，并发受 `cache_prefetch_max` 限制，
  被刷新并发/速率限制拒绝后，下一次命中可重新认领；失败后须先经过同 key 退避。若任务在进入 worker 前被队列丢弃，认领仍可能保留至条目更新/过期。
  需要预取的国外新鲜命中改走缓存 lane（事件循环不创建线程），其余国外新鲜命中仍在事件循环回答。
  默认关闭：它增加上游查询数（每个热点每个 TTL 约多一次），建议从 10 开始
- 刷新使用首次分类的同一上游组及同一 CN 最终处理路径，绝不跨组
- **nft 决策**：CN 的 stale 命中照旧经 nft（与 fresh 命中相同，受热命中跳过窗口约束）；CN 的预取、stale 刷新与启动预热结果
  也经 `finalize` 写 nft，使新地址在客户端使用前已在集合中；国外回答从不写 nft。CN 集合学习仍只来自 CN 组回答
- 保留旧的错误边界：取得有效 DNS 回答后，即使 nft 最终处理失败，该回答仍可能入缓存；后续命中仍重新执行 nft，并继续报告学习失败
- 重启预热：`cache_warm_file` 周期（及退出时）保存最近被复用的 A/AAAA 名称，每行 `<key标志位> <qtype> <name>`，只含名称，
  从不保存地址；全部监听器和工作线程启动成功后，由维护线程按 `cache_warm_qps` 顺序经正常解析路径预热（CN 经 nft），已缓存的名称跳过。配置或绑定失败不会读取、覆盖旧名单。
  文件必须是普通文件，拒绝符号链接、FIFO 和设备；最多读取 4 MiB / 20000 行（含空行、坏行），过长或含 NUL 的行整行丢弃。保存使用同目录随机独占临时文件（0600），完成 fsync 后原子替换；既有符号链接或特殊文件不会被替换。
- 统计：每个请求在每组只计一次：`fresh_hit`、`stale_hit`、`miss_cold`（近期未见）、`miss_evicted`（被容量淘汰）、
  `miss_expired`（超过截止）、`bypass`（ECS/EDNS 选项等不可缓存），以及 `refresh_ok`/`refresh_fail`/`refresh_kept_old`/
  `prefetch`/`evictions`/`warm`。淘汰原因由 4096 槽位的 ghost 表近似判定。设置环境变量 `DIVERSION_CACHE_STATS=1` 时退出前打印到
  stderr；`DIVERSION_CACHE_STATS=<N>`（N≥5）另外每 N 秒打印一次。计数使用 relaxed 原子量，开销是每请求一次原子加
- `refresh_ok` 表示后台任务取得并最终处理有效的 NOERROR/NXDOMAIN，包含有效但不可缓存而撤销旧项的情况；不是“成功插入缓存”的计数。
  `refresh_fail` 也包括后台任务分配/线程创建失败；`prefetch` 只计实际启动的预取线程，CN 的调度探测与 worker 查找合计只增加一次命中/热度。预热查询仍单独计入 `warm`
- `cache_size=0` 完全跳过缓存、刷新、预取与预热

## 域名规则

`cn_domain_file` 文件逐行支持 `domain:`、`full:`、`keyword:`、`regexp:`；无前缀是 domain
后缀规则。多个文件形成一个 CN 集合。原规则加载器的大小写、注释、重复规则、文件错误
和 regexp 语义保持不变。当前配置不接受内联规则、组合 domain_set 或否定/AND matcher。

regexp 继续使用固定 PCRE2 10.48 8-bit、无 Unicode、无 JIT 的构建，按字节匹配且有
匹配/回溯深度上限。`(*UTF)`、`(*UCP)`、`\p`、`\P`、`\X` 不支持；不会默默忽略或降级
错误规则。DNS 问题名只接受可打印 ASCII 标签，包括常规 punycode；不做 IDNA 转换或
Unicode 大小写折叠，国际化名称要预先转为 ASCII/punycode。

## 从历史 site-only YAML 迁移

[离线迁移工具](../scripts/migrate-site-config.py) 使用 Python 3 和可选的 PyYAML。
PyYAML 只在操作人员运行该工具时需要；部署二进制及配置读取没有 YAML 依赖。
环境需要预先安装可用的 PyYAML，工具不会联网或自动安装依赖。

```sh
python3 scripts/migrate-site-config.py docs/go-profiles-site-only.yaml -o /tmp/site-only.conf
./mosdns-c check -c /tmp/site-only.conf
```

`-o` 只创建新文件，拒绝覆盖。省略 `-o` 时，验证完成后一次输出到 stdout。输入不支持时
不会生成文件或任何配置输出。shell 自己的 `>` 重定向会先创建/截断目标，若要保留此保证
请使用 `-o`。迁移工具不读规则、不查网络、不修改 nft，只转换经证明的配置结构；之后
还应使用当前二进制执行 `check`，再单独验收真实 Linux 运行环境。

工具仅接受历史 site-only 的完整等价图：一个文件型 domain_set、一个 cache、两个
forward、main / CN resolve / finalize 三个 sequence 和使用同一 main 的 listener。
标签名称可以改变、插件定义可以换序；工具从引用关系推断角色并校验每一步。
CN 与 foreign 都必须进入相同 finalize，缓存命中也必须进入那里；finalize 为同一个
CN qname 条件下的一到两个 nftset 参数，随后 accept。它不尝试翻译其他任意控制流。

可转换：1–64 个规则文件、每组 1–64 个数字上游、mark、接口、1–3 并发、缓存大小/lazy、
总计不超过 64 个 listener 及统一 TCP idle timeout、显式有效的 IPv4/IPv6 nft 参数。
它保留列表内顺序和相对路径。旧 C YAML 的 TCP listener 省略 idle_timeout 时实际为
10 秒，工具明确输出 `tcp_idle_timeout=10`，不会误用新配置的 30 秒缺省值。

拒绝（即使某个额外字段填写了看似无害的缺省值）：

- include、API、额外插件、未知字段、重复映射键、多 document、YAML anchors/aliases/merge/显式 tag/directive
- 内联 exps、组合 domain_set、不同 listener entry、per-listener idle timeout 不一致
- 改写的 matcher、fallback、CNAME/IP 分流、额外动作、未引用插件及任何不符合上述图的 sequence
- 上游 `dial_addr`、端点 tag、端点 mark/接口覆盖、pipeline/TLS/SOCKS/bootstrap 选项
- 非 info 日志设置、日志文件/production 字段、cache dump
- 旧值 `cache.size=0`（旧语义是回退 1024）、concurrent=0 或大于 3（旧语义会默认/截断）、idle_timeout=0、nft mask=0
- 超出新格式范围、不可保留的控制字节/两端空白、需主机接口查询的 scoped IPv6

工具有 1 MiB 输入、嵌套/节点数和输出行长限制。结构先经安全的纯 YAML 节点解析，
不构造 Python 对象；重复键、alias 等在可能被覆盖或展开前即被拒绝。

## 部署前检查

[site-only.conf](../c/examples/site-only.conf) 保留历史 Linux 示例的规则路径、DNS IP、mark
和 nft 集合。`br-lan` 和 `c131tm` 必须替换/核实为实际接口；后者只是旧隔离测试接口。
必须先准备 `/etc/mosdns/cn-site.txt`、已有 nft 集合、直连/隧道路由及防泄漏策略。
设置 mark 或绑定接口本身不会创建 WireGuard、路由或防泄漏规则。

本程序不会安装服务、接管系统 DNS、创建路由或自动调整生产环境。配置/规则预检、
mock 功能回归、真实 Linux nft/出口验证、文件大小/RSS/QPS 和持续稳定性是不同证据，
不能互相代替。

## 快速 nft 学习的边界（0.1.1）

普通 RR 的 TTL 最高位为 1 时按 0 处理，其余最多 86400 秒；返回报文、缓存、
nft 学习使用同一规则，EDNS OPT 不改写。需要改写 TTL 的 TSIG/SIG(0) 报文会失败。
fast 路径写入 TTL+15 秒，不继承 set 默认 timeout；已有永久元素不会被改短。
从 `nftset_fast=0` 切换到 `1` 时，CLI 路径学到的元素在没有默认 timeout 的集合中是永久的，
fast 路径不会让它们过期：切换时对只含 DNS 学习地址的集合执行一次 `nft flush set`（见
[c/README.md](../c/README.md) 的迁移说明）。
目标必须 flags timeout（不含 dynamic/interval/map）；静态 CN-IP 保留独立集合。

每个响应只学习前 256 条 Answer IN A/AAAA（按报文顺序，重复也计数），超出部分不写入，
DNS 正常回答并打印限速告警（0.1.1 及以前回 SERVFAIL）；队列批次
最多 32 个请求、1024 条地址。事务按实际 SO_SNDBUF 拆分。generation 竞争最多尝试
五次，不延长原有 5 秒期限：提交前后 generation 变化时采用新 generation，并用 GETSETELEM
逐条读回本批地址（存在且 timeout 不短于期望），只重写缺失或过短的元素；批次失败后按
成员剩余时间份额隔离，仍无法完成者返回失败。
已有连接需要另外保存 conntrack 分流标记；新连接按当前地址集合判断。

## 热命中跳过窗口（nftset_hit_window_ms，默认 1000 ms）

热点 CN 域名每次缓存命中都会调用 nft 学习。窗口开启时，若同一回答的全部 IN A/AAAA
（≤64 条，按原始地址）都在窗口内被本进程写入成功或核对通过，且（fast 路径）已知的
内核剩余寿命满足与原跳过写入相同的判据（5 秒期限 + TTL+15 秒 − 14 秒，TTL 同样
封顶 86400），本次回答不再访问内核（不进入 FIFO/串行令牌、不读 generation）。
两条路径（fast 与 CLI/兼容，含 interval 目标）行为相同；需要更长租期的回答永远不会
被跳过，因此“续期不缩短”和 TTL 上限不变；被跳过的回答不写入任何东西，也就不可能缩短。

记录的失效：任一写入/核对错误清空全部记录；fast 路径观察到 generation 变化（外部
写者、flush、重建）时丢弃全部映射并清空记录；进程重启记录为空。

**已接受的取舍**：外部 `nft flush`/`delete element`/删表重建后，本进程最多在
“最后一次核对 + 窗口”之前不会重新学习该地址（窗口内的命中仍正常回答，只是不写回）；
窗口结束后的第一个回答会重新核对并写回。兼容路径不知道集合默认 timeout，若内核
对重复添加会刷新默认 timeout，则续期最多推迟一个窗口。`nftset_hit_window_ms=0` 恢复
逐次核对的旧行为。`DIVERSION_NFT_STATS=1` 时退出前向 stderr 打印 applies/skipped/
transactions 计数（契约测试使用）。

冷路径 fast 读回（GETSETELEM）按最多 8 个地址一批编码进同一 datagram，最后一批还附带
finish 所需的 GETGEN：与原先「每地址一次往返，再单独 GETGEN」语义相同（内核按序处理），
但系统调用与唤醒次数更少。单地址冷查询从「读回 + 世代」两趟变成一趟。

同一 fast cohort 中同时有 IPv4 与 IPv6 待写地址、且总数不超过单个事务上限时，两族
地址合并为一个 GENID 保护的事务（一次 begin/end、一次 ACK 往返、一次 generation
复读）；任一集合被拒绝则整个事务不提交，随后按原逻辑重试/隔离。只含一族的 cohort
与原流程完全相同。

## 上游 UDP 已知限制（0.1.2 / M4）

**默认**每次上游 UDP 交换使用全新 connected socket 与内核随机源端口（随机 ID + 随机端口约
31 位熵；已用 socket 不复用；空闲预开只把 `socket`/`connect` 挪出热路径）。在
**mipsel_24kc**（测试机 A，Linux 6.12.94）上，冷缓存 / 首次上游 UDP 查询相对 v0.1.1 约多
**+4–5 ms P50**、约 **+5 ms P99**（2026-10-13 六轮中位数消融：冷 A P99 约 **7.3 → ~12 ms**）；
热路径不受影响。该路径上 conntrack 约每条冷查询增加 1 条。**aarch64**（测试机 B）冷路径无实质回归。

### 可选：`udp_sport_reuse`（显式 opt-in）

设置 `udp_sport_reuse=1` 可启用有时限、有次数上限的小容量 UDP 源端口复用，以降低 MIPS 冷查询
代价。启用后每个 worker 可按上游停放最多 `udp_sport_reuse_pool` 个空闲 socket，在
`udp_sport_reuse_max_uses` 次查询或 `udp_sport_reuse_ttl_ms` 毫秒内复用（须无待收数据报）；
超限后关闭并换新端口。同一 socket 不会并发服务多个 in-flight 查询。热路径在未触及上游 /
纯缓存命中时仍只做维护标志检查（与 PR #8 一致）。

**安全权衡：** 启用会削弱「每查询唯一源端口」；离路径伪造仍须猜中随机 DNS ID，但端口熵随复用
窗口下降。仅在接受该权衡、并需要 MIPS 冷延迟时打开。建议起步值：

```conf
udp_sport_reuse=1
udp_sport_reuse_max_uses=16
udp_sport_reuse_ttl_ms=2000
udp_sport_reuse_pool=2
```

默认 `udp_sport_reuse=0` 时行为与当前 main 完全一致（含「10 查询 → 10 端口」测试）。

**测试机 A 实测（2026-10-13，mipsel_24kc）：** 主要改善冷 **AAAA**——6 轮全部改善；冷 A 无稳定收益；TCP 受顺序效应影响大，无稳定结论。启用池后 500 QPS 累计 30 分钟：900,000/900,000 成功、零漏发、整体 P99 2.976 ms。协议、nft、队列/TCP 限制、池边界、interval 重叠、链路本地 IPv6 功能测试通过。默认保持 `udp_sport_reuse=0`（每查询新源端口）；启用会削弱源端口唯一性（上游随机 DNS ID 仍保留）。仅当慢速 MIPS 上冷 AAAA 延迟重要时建议启用。
消融结论：恢复无上限 UDP 池（保留随机 ID）或整段回退 M4 可回到基线冷 P99；回退 N3 不能。

