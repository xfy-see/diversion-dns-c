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

默认配置文件名是 `config.conf`。`start/check/version/help` 保留；`--cpu` 是工作线程数，
范围 1–64，默认 4，只用于 `start`。

`-d/--dir` 先改变进程工作目录，然后读取配置。相对配置路径和每个 `cn_domain_file`
都相对于这个工作目录，而非配置文件所在目录。没有 `include`，也不展开 `~` 或环境变量。
根目录的 [config.conf](../config.conf) 和 [minimal.conf](../c/examples/minimal.conf)
使用仓库相对的演示规则；请在仓库根目录运行，或通过 `-d` 指向该目录。

`check` 与 `start` 使用相同的配置解析和规则加载：它读取全部 CN 规则文件，编译 regexp，
验证必填资源、数值、监听地址和 nft 参数。缺失文件或错误规则会立即失败，报告配置或
规则的文件路径及行号。`check` 不打开 listener、不给上游发包、不调用 nft 写入，也不验证
端口能否绑定、上游是否可达、Linux mark/接口权限、nft 可执行文件或目标集合是否存在。
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
| `cache_lazy_ttl` | 单值，0–4294967295 秒；0 关闭 lazy | 0 |
| `cn_mark` / `foreign_mark` | 各一个 uint32，十进制或 `0x` | 0，不设置 mark |
| `cn_interface` / `foreign_interface` | 各一个，1–63 可打印 ASCII 字节，不含空白或斜杠 | 不绑定接口 |
| `cn_concurrent` / `foreign_concurrent` | 各一个，1–3 | 1 |
| `tcp_idle_timeout` | 单值，所有 TCP listener 共用，1–86400 秒 | 30 |
| `nftset_ipv4` | 单值，五段逗号格式，IPv4 mask 1–32 | 不学习 IPv4 |
| `nftset_ipv6` | 单值，五段逗号格式，IPv6 mask 1–128 | 不学习 IPv6 |

必须至少配置一个 listener。UDP 和 TCP listener **合计最多 64 个**，同一传输中的重复
数字地址被拒绝。`cache_size=0` 时，非零 `cache_lazy_ttl` 会报错。

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
完整成功回执；interval 集合保留原 argv/stdin CLI 与前缀行为。mask 对 interval 集合生效，
普通集合写入具体地址。集合必须预先存在，程序不会创建表或集合，不发送元素 TTL，
继续使用集合默认 timeout，也没有用户态 membership 缓存或维护线程。

只有配置了 nft 的 CN 响应会调用该模块，foreign 响应不会学习。保留的重要边界是：
模块先检查 Linux 支持和标准路径里的 `nft`，然后才可能因没有可学习地址跳过内核写入。
因此 CN 的空回答、NXDOMAIN 或没有 A/AAAA 的回答并不保证绕过这项环境要求；
非 Linux 上配置 nft 的 CN 请求仍会失败。FIFO 等待、元数据检查和写入共用原 5 秒预算。
不明确的提交结果不会自动重放，查询路径会报告失败。

## 缓存与 lazy 刷新

- 容量有界，hash + LRU；TTL 随存储时长递减，容量单位是条目而非字节
- NXDOMAIN 保留 30 秒，SERVFAIL 保留 5 秒；空 Answer 的 NOERROR 受记录最小 TTL 和 300 秒上限约束，没有可用 TTL 时不缓存
- 正向回答的 `cache_lazy_ttl` 是从最初存储时刻开始计算的总保留时间，不是在 DNS TTL 之后再加一段 stale 时间
- stale 命中将普通记录 TTL 设为 5 秒，并尝试异步刷新；同 key 刷新去重，总计最多 64 个刷新任务
- 刷新使用首次分类的同一上游组及同一 CN 最终处理路径，绝不跨组；上游交换失败不会主动删除已有 stale 回答
- 保留旧的错误边界：取得有效 DNS 回答后，即使 nft 最终处理失败，该回答仍可能入缓存；后续命中仍重新执行 nft，并继续报告学习失败
- `cache_size=0` 完全跳过缓存及 lazy 刷新

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
