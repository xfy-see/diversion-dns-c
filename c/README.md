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

默认读取 `config.conf`，默认工作线程 4 个（`--cpu` 范围 1–64）。`-d/--dir` 在读取配置前
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

nft 普通集合仍有 generation 前后校验和完整 Netlink 成功回执；interval 集合仍走
argv/stdin CLI，不启动 shell。不创建表/集合，不发送元素 TTL，使用集合默认 timeout。
配置 mask 作用于 interval 前缀，普通集合使用具体地址。FIFO 等待、检查和写入共享
原有 5 秒预算；不明确的提交结果不自动重放。没有 Answer 地址不代表完全跳过 nft
环境检查：CN 负回答仍可能因非 Linux 或没有标准路径的 `nft` 失败。

UDP 接收缓冲单独请求 256 KiB 并读回实际值，受内核限制；Linux 读回值含双倍
bookkeeping，不等于 RSS。UDP/TCP listener 合计最多 64 个，TCP 连接最多 128 个，
未完成请求最多 64 个，异步 lazy 刷新最多 64 个。TCP 每连接串行处理，可处理已排队的
连续帧；队列满时 UDP 返回 SERVFAIL、TCP 关闭连接。无 UDP packet-info 源地址选择、
Unix listener、HTTP API、指标、磁盘 cache dump、加密 DNS、SOCKS 或 bootstrap。

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
