# 专用 C DNS 分流器

C11/POSIX 前台程序，固定执行“原始 QNAME 匹配 CN → 共享缓存 → CN 或 foreign 上游 →
CN nft 最终处理 → 返回”的请求链。运行时配置已替换为有界 `key=value` 解析器，
没有 YAML、插件注册表、动态 sequence、include 或 tag 引用。

完整配置、迁移限制、缓存与 nft 行为见 [固定分流器配置说明](../docs/fixed-splitter.md)。
历史 [site-only YAML](../docs/go-profiles-site-only.yaml)、旧 YAML 示例和旧 graph 测试仍保留，
供历史产物验证和迁移回归使用，不能作为当前运行配置。

## 运行

先从精确提交对应的 CI 产物取得已验证的二进制；从仓库根目录运行：

```sh
/path/to/mosdns-c version
/path/to/mosdns-c check -c c/examples/minimal.conf
/path/to/mosdns-c start -c c/examples/minimal.conf --cpu 4
```

默认读取 `config.conf`，`--cpu`（范围 1–64，默认 4）是**每条 worker lane** 的线程数：缓存命中、
CN 上游、国外上游三条 lane 各自排队，默认共 12 个工作线程，线程栈显式不小于 1 MiB。`-d/--dir` 在读取配置前
切换工作目录；配置和规则文件的相对路径都基于该目录。演示规则在
[c/examples/cn-site.txt](examples/cn-site.txt)，请先替换为实际规则与上游。

`check` **加载实际规则文件并编译 regexp**，检查配置、数字地址和 nft 参数，不打开
listener、不发送 DNS 查询、不写 nft。规则缺失或格式错误会使检查失败，带文件和行号。
端口占用、上游可达性、mark/绑定接口权限及 nft 运行环境仍需单独验收。

生产 Linux 的 [site-only.conf](examples/site-only.conf) 需要预先存在的 CN 规则、接口、
nft 集合和路由。程序不会安装服务、接管系统 DNS、创建 WireGuard 或添加防泄漏规则。

## 保留的运行能力

| 模块 | 当前行为 |
|---|---|
| 域名 | 文件型 domain/full/keyword/regexp，ASCII 大小写归一化；一次加载后只读 |
| 固定分流 | 原始 QNAME 决定唯一上游组；CNAME/Answer 地址不改路由；无跨组 fallback |
| 上游 | 数字 IPv4/IPv6、UDP/TCP、每组最多 3 并发；ID/问题校验；UDP 每秒重发、TC 转 TCP |
| 缓存 | 引擎共享、有界 hash+LRU、TTL 递减、负缓存、lazy TTL 5 秒返回与异步同 key 去重 |
| 服务 | 有界队列、UDP、TCP 持久连接/连续帧/部分读写、UDP 大小限制、SIGINT/SIGTERM 清理 |
| Linux 出口 | 每组 SO_MARK、SO_BINDTODEVICE；设置失败报错 |
| nftset | CN 响应包括缓存命中都最终处理；只学习 Answer 中 IN A/AAAA；保留普通/interval 集合写入路径 |

每个引擎配置不可变，缓存 key 保留 QNAME 原始大小写、QTYPE/QCLASS、AD/CD/DO。
当前仅缓存合格的 IN 查询；带非空 EDNS options、其他附加数据或压缩问题绕过缓存。
修改规则或出口配置必须重启，不能让不同配置共用热缓存。

NXDOMAIN 缓存 30 秒、SERVFAIL 5 秒；无 Answer 的 NOERROR 受记录最小 TTL 和 300 秒
上限约束。正向 lazy 总保留期从最初存储时间计算，不是 TTL 加 stale 时长。stale 响应
普通记录 TTL 为 5 秒，后台刷新仍走同一个已分类出口及 CN 最终处理路径。

上游工作线程连接池继续每线程 8 槽、空闲 30 秒，按端点、传输、mark 和接口隔离。
一个连接内不复用已用过的 DNS ID；异常或脏连接关闭。库调用和非工作线程使用新连接。
没有 pipeline。UDP 每秒用同一 connected socket 和原 ID 重发，共享原 5 秒交换预算；
TC 转 TCP 后停止 UDP 重发。

nft 普通集合仍有 generation 前后校验和完整 Netlink 成功回执；窗口内的集合元数据用 Netlink
GETSET 读取（每次写入只调用一次 `nft list set` 判断 interval），generation 冲突或批次
ERESTART 时新开 socket、退避 1–4 ms 后最多尝试 3 次；序列号在 32 位范围内回绕，不会耗尽。interval 集合仍走
argv/stdin CLI，不启动 shell。不创建表/集合，不发送元素 TTL，使用集合默认 timeout。
配置 mask 作用于 interval 前缀，普通集合使用具体地址。FIFO 等待、检查和写入共享
原有 5 秒预算；不明确的提交结果不自动重放。没有 Answer 地址不代表完全跳过 nft
环境检查：CN 负回答仍可能因非 Linux 或没有标准路径的 `nft` 失败。

UDP 接收缓冲单独请求 256 KiB 并读回实际值，受内核限制；Linux 读回值含双倍
bookkeeping，不等于 RSS。UDP/TCP listener 合计最多 64 个，TCP 连接默认最多 128 个
（`tcp_max_connections`），每条 lane 未完成请求最多 64 个，异步 lazy 刷新最多 64 个。
国外组的新鲜缓存命中在事件循环直接回复；CN 缓存命中（仍须写 nft）和 stale 命中进入不访问
上游的缓存 lane。一个上游组全部超时不会占用另一组或缓存 lane 的 worker 与排队配额。
TCP 每连接串行处理，可处理已排队的连续帧；某条 lane 满时 UDP 返回 SERVFAIL、TCP 关闭连接。

同一上游组内仍会互相影响，但有界：该组 worker 被不回答的上游占住时，每次交换最长 5 秒；
排队超过 `queue_timeout_ms`（默认 2000 ms）的请求不再访问上游，直接回 SERVFAIL（与 lane 满时
相同，仍在等待的客户端可以立即重试，已放弃的客户端忽略它）。因此一批黑洞查询会让该组
停摆约一个上游期限（约 5 秒），而不是按队列长度累加。除 DNS ID 外完全相同的查询（问题
大小写、标志、EDNS 全同）共享正在进行的那一次上游交换，不另占 worker；跟随者仍计入
该 lane 的 64 个配额，所以超过 64 个的同名重试风暴仍会让该组在这次交换结束前返回 SERVFAIL。

TCP 待写回复不计入任何 lane 配额，慢读客户端不能让 UDP 的 CN 缓存命中失败。每个 TCP
连接最多持有一个待写回复：一帧须在 `tcp_read_timeout`（默认 5 秒）内收完，一个回复须在
`tcp_write_timeout`（默认 10 秒）内写完，否则关闭连接；空闲连接仍按 `tcp_idle_timeout`
关闭。同一来源地址最多 `tcp_max_connections_per_ip`（默认 32）个连接（IPv6 按完整
/128 计算）。达到每 IP 或总数上限时，先淘汰最久无进展的空闲连接，其次淘汰回复写不出去的
连接；正在等待 worker 的连接不淘汰，都不可淘汰时才拒绝新连接。最坏情况下的报文对象内存约为
（3×64 + `tcp_max_connections`）× 128 KiB，默认约 40 MiB，按需分配；内存紧张的路由器可以
调低 `tcp_max_connections`。TCP 53 仍建议只对可信 LAN 开放。

无 UDP packet-info 源地址选择、Unix listener、HTTP API、指标、磁盘 cache dump、加密 DNS、
SOCKS 或 bootstrap。

## 正则依赖与构建约定

PCRE2 固定 10.48，8-bit 静态库、禁用 Unicode/JIT/16-bit/32-bit。无系统库 fallback。
默认依赖目录 `.build/pcre2-8-no-unicode-no-jit`，应用目录
`.build/c-native-no-unicode-no-jit`，避免复用旧 Unicode 构建。
libyaml 不再编译或链接进程序/库；`vendor/libyaml/` 的历史源码与 MIT 许可证保留。
Python 的 PyYAML 仅用于可选的 [离线迁移工具](../scripts/migrate-site-config.py)。

regexp 按字节匹配，`\d`/`\w` 保持 ASCII 类语义，存在匹配/回溯深度上限；与 Go RE2
语法及最坏复杂度不同。`(*UTF)`、`(*UCP)`、`\p{...}`、`\P{...}` 和 `\X` 编译失败。
DNS 服务只接受可打印 ASCII 问题标签，包含常规 punycode；不做 IDNA 或 Unicode
大小写归一化。库级 UTF-8 字节测试不代表服务支持 raw Unicode 问题名。

默认遵循 [AGENTS.md](../AGENTS.md)：由 GitHub Actions 构建和验证，不在本地调用 C
编译器、Make build target 或 Zig。只有得到单独明确授权，才运行本机构建命令。
CI/已授权构建环境使用以下固定依赖流程：

```sh
mkdir -p .build/deps
curl --fail --location --retry 3 \
  https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz \
  -o .build/deps/pcre2-10.48.tar.gz
python3 scripts/build-native-pcre2.py \
  --archive .build/deps/pcre2-10.48.tar.gz \
  --output .build/pcre2-8-no-unicode-no-jit --jobs 4
make -C c -j4
make -C c test
```

依赖脚本校验源码 SHA-256
`ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888`，
拒绝复用输出目录，保存构建日志及静态库哈希。交叉链接必须使用目标平台同配置的 PCRE2
库；macOS `.a` 不能用于 Linux。应用、固定 PCRE2 依赖及独立测试默认使用 `-Os -flto`，
链接也开启 LTO；静态 Linux 发布仍使用 musl、section GC、strip 和原 1 MiB stack 设置，
没有关闭 unwind 表。ASan/UBSan profile 保留 `-O1` 和 frame pointer 以便诊断。
更改编译参数时必须使用全新的输出目录，不能复用旧 `.o`/`.a`。LTO 会把项目、依赖及
部分 runtime 合并为一个输入，尺寸报告将它们记为 `mixed_lto`，不声称能拆出各自字节。
原始精确链接重放、完整 ELF 哈希和诊断节布局校验继续保留；PCRE2 配置、输入库与
最终诊断符号独立验证。默认本机构建保留调试信息，不能把体积直接和其他语言
剥离后的 release 做公平对照。

## 验证与历史证据

当前 CI 测试目标为 `dns_test`、`cache_domain_test`、`fixed_config_test`、
`fixed_engine_test`、`nft_netlink_test`，外加共享域名 fixture、`fixed_integration.py`、
nft CLI mock 和 CLI smoke。native 与 ASan/UBSan 均运行；Linux ARM64/x86_64 提供
固定依赖静态产物。实际是否通过应以精确提交的 CI 及下载验证回执为准。

仅 Python 的校验可以在本地执行，不调用 C 编译器：

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

迁移回归需要可选 PyYAML；缺少该模块时明确跳过这组测试。旧 `engine_test.c`、
`plan_regression_test.c`、`integration.py`、`plan_integration.py` 和 YAML 资产保持原样，
不属于当前固定分流器的构建目标；验证脚本保留历史 bundle 的旧 suite 路径。

域名 fixture 保留原有 70 条断言和四项 Unicode/RE2 专项的明确跳过，不声明完整 Go
matcher 兼容。八条 Loyalsoldier direct-list 固定 regexp、Unicode 功能拒绝和文件行号
错误仍是保留项。nft mock 使用生产报文编码/回执和 Darwin 窄 UAPI shim，不执行真实 nft，
不能证明设备上的 Netlink 权限、集合行为或 mark/接口出口。

[历史验证记录](VALIDATION.md) 与 [旧 graph 测试说明](TESTING-PLAN-COVERAGE.md)
只解释历史实现和历史证据。原 r12 性能数字在[根 README](../README.md)保留，不是本次
专用实现的新成绩。真实内核写入、目标设备出口、二进制/RSS/QPS 和持续稳定性仍须
各自提供独立测量；配置预检、编译成功或 mock 通过都不能代替它们。

## Optional regex experiment

The default remains PCRE2 without Unicode/JIT. An experimental libc ERE
backend can be selected with `REGEX_BACKEND=posix-lite`; its deliberately
restricted syntax and printable-ASCII subject contract are documented in
[REGEX-POSIX-LITE.md](REGEX-POSIX-LITE.md). It is not a drop-in PCRE2 replacement.

## Optional plain-set fast path

`nftset_fast=1` requires /32 IPv4 and /128 IPv6 targets in pre-existing **plain timeout sets** (flags timeout only, address types ipv4_addr / ipv6_addr). It makes no subprocess calls and does not create sets or rules. Keep static CN-IP prefixes in separate interval sets. The default remains the compatible interval/CLI implementation.

The fast writer batches up to 32 queued queries and 1024 address records, using
socket-sized transactions of at most 512 keys. DNS success waits for all ACKs.
Each response may contain at most 256 Answer IN A/AAAA records (duplicates count);
larger answers fail before joining the queue. A failed cohort is retried member by
member within fair shares of the original five-second deadlines, preserving healthy
queries when another member has a bad target or update. It never returns a partial
successful DNS answer. IPv4 and IPv6 writes are not one atomic transaction.

Linux 6.12 or newer is checked at configuration time on Linux. Older/backported
kernels must use `nftset_fast=0` until their behavior is validated. Every request
checks generation; races and kernel ERESTART trigger at most three attempts within
the original deadline. A post-ACK generation jump is revalidated, never blindly
accepted: the external writer may have flushed the just-written mappings.

Permanent existing elements are preserved, including after restart. A sufficiently
long existing lease is reused; short leases are refreshed without shortening a
longer shared mapping.

**Migrating from `nftset_fast=0` to `nftset_fast=1`:** the CLI path adds elements
without a per-element timeout, so in a `flags timeout` set without a default
`timeout` every address it learned is permanent. The fast path deliberately keeps
permanent elements, so those addresses would never expire after the switch. Flush
the DNS-learned sets once while switching (stop the service, flush, start with
`nftset_fast=1`):

```sh
nft flush set inet mosdns_cn cn_site4
nft flush set inet mosdns_cn cn_site6
```

Use the table/set names from `nftset_ipv4`/`nftset_ipv6`. Only flush sets that
contain nothing but DNS-learned addresses; static CN-IP prefixes belong in
separate sets. Until clients re-query, new connections to those destinations take
the non-CN route; existing connections keep their route only if conntrack pinning
is in place. To keep the current mappings instead, re-add each element with an
explicit `timeout` (e.g. `nft add element inet mosdns_cn cn_site4 { 192.0.2.1
timeout 10m }` after deleting the permanent one); the fast path then refreshes it
normally.
The DNS response and cache normalize TTL high-bit values to zero (RFC 2181) and
cap ordinary RR TTLs at 86400 seconds. OPT fields are exempt. nft installs that TTL
plus 15 seconds, overriding the set's default timeout deliberately. No configurable
minimum TTL or dynamic-set support is added. Transaction-signed responses requiring
TTL rewriting fail rather than return an invalid signature.

The 2048-slot cache per family remains bounded, generation-invalidated and lazy.
Missing/wrong sets, malformed ACKs and exhausted deadlines fail closed, with no CLI
fallback. Rule changes immediately after the final check remain outside any DNS/nft
transaction; re-query after reload repairs cached answers. Existing connections can
retain their route through the separate conntrack pinning rules.

Route lookups must include both static CN-IP and dynamic DNS-learned sets. Do not remove dnsmasq learning until these lookups and C writes have passed real A/AAAA, first-connection, reload and rollback tests.
