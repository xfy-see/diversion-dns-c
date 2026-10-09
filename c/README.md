# mosdns C 最小实现

与 Go/Rust 并存的 C11/POSIX 前台实现，参考 [Go minimal](../docs/go-profiles.md)，沿用 `coremain → plugin → pkg` 分层和 YAML 的 plugin/sequence 模型。初版实现 site-only DNS 分流；没有自动安装、路由配置或系统 DNS 接管。

## 构建和运行

需要 C11 编译器、Make、POSIX threads，以及固定为 10.48 的 PCRE2 8-bit 静态库，关闭 Unicode 和 JIT。原生 CI、ASan/UBSan 和 Linux 静态 release 使用同一依赖配置；保留 PCRE2，不替换 regexp 引擎。仓库内置 [libyaml 0.2.5](vendor/libyaml/ORIGIN.md) 源码及 MIT 许可证，domain/full/keyword 和 YAML 解析范围不变。Makefile 默认只使用 `.build/pcre2-8-no-unicode-no-jit`，缺少依赖时失败，不回退到系统 PCRE2，也不自动下载依赖。默认应用构建目录也隔离为 `.build/c-native-no-unicode-no-jit`，避免复用旧 Unicode 构建。

默认遵循 [仓库工作流](../AGENTS.md)，由 GitHub Actions 编译并验证对应提交的产物；只有用户明确授权本地编译时，才在仓库根目录运行以下依赖构建和 Make 命令（下文测试中的构建命令也一样）：

```sh
mkdir -p .build/deps
curl --fail --location --retry 3 \
  https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz \
  -o .build/deps/pcre2-10.48.tar.gz
python3 scripts/build-native-pcre2.py \
  --archive .build/deps/pcre2-10.48.tar.gz \
  --output .build/pcre2-8-no-unicode-no-jit --jobs 4
make -C c -j4
./.build/c-native-no-unicode-no-jit/mosdns-c version
./.build/c-native-no-unicode-no-jit/mosdns-c check -c c/examples/minimal.yaml
./.build/c-native-no-unicode-no-jit/mosdns-c start -c c/examples/minimal.yaml --cpu 4
```

`--cpu` 指工作线程数，范围 1–64，默认 4。`-d/--dir` 改变工作目录；配置中的 include 和规则文件相对路径也按这个目录解析。示例监听 `127.0.0.1:15362`，上游地址需要按实际网络调整。已有 Linux site-only 配置可以使用 [go-profiles-site-only.yaml](../docs/go-profiles-site-only.yaml)，运行前须准备其中的规则文件、接口、mark 路由和 nft 集合。

依赖脚本校验 PCRE2 10.48 源码包 SHA-256 `ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888`，要求全新输出目录，并记录配置、构建日志和静态库哈希。`--disable-unicode --disable-jit --disable-pcre2-16 --disable-pcre2-32` 是此产物的兼容性约定。其他安装前缀或交叉工具链可通过 Make 变量指定，但必须使用相同依赖配置：

```sh
make -C c BUILD=../.build/c-custom \
  CC=/path/to/target-cc AR=/path/to/target-ar \
  PCRE2_CFLAGS=-I/path/to/target/include \
  PCRE2_LIB=/path/to/target/lib/libpcre2-8.a
```

交叉链接必须使用目标平台的 PCRE2 静态库。macOS 的 `.a` 不能用于 Linux。默认构建保留调试信息；它的体积不作为与其他语言 release 产物的公平对照。

## 能力范围

| 模块 | 初版行为 |
|---|---|
| 配置/CLI | YAML/YML/JSON、include、tag 引用；`start/check/version/help` |
| 六类插件 | `domain_set`、`cache`、`forward`、`sequence`、`udp_server`、`tcp_server` |
| 域名规则 | domain/full/keyword/regexp、规则文件、组合 domain_set；ASCII 大小写归一化 |
| sequence | AND、`!`、qname/has_resp/_true/_false、accept/reject/return/jump/goto、`$plugin`、快捷 cache/forward/nftset |
| 上游 | 数字 IPv4/IPv6、UDP/TCP、数字 dial_addr、tag 选择；最多三个并发上游；ID/问题校验；UDP 每秒重发、TC 转 TCP |
| 内存缓存 | 有界 hash+LRU、TTL 递减、NXDOMAIN 30 秒/SERVFAIL 5 秒、lazy 返回 TTL 5 秒并异步刷新/同 key 去重 |
| 服务 | 有界工作队列、UDP、TCP 持久连接/连续帧/部分读写、客户端 UDP 大小限制、SIGINT/SIGTERM 清理 |
| Linux 路由约束 | SO_MARK、SO_BINDTODEVICE；设置失败返回错误 |
| nftset | 读取已有集合类型，学习 Answer 中 IN 类 A/AAAA；interval 集合使用配置前缀 |

`check` 读取配置/include、编译内联规则表达式、校验插件、参数和引用，不加载外部规则文件（包括 `domain_set.files` 和 `qname &文件`）、不打开 listener、不执行 nft。因此 `check` 成功不能证明规则文件的 regexp 可用；内联 Unicode 表达式会在 `check` 时报错，外部文件中的同类表达式要到实际启动加载文件时才报错，包含文件路径和行号，并使启动失败。部署前应使用同一产物、完整规则文件和隔离的测试配置核对实际加载/启动结果，不能把 `check` 当作完整规则预检。mark、接口绑定和 nft 操作在查询时验证。无 API、指标、磁盘 cache dump、加密 DNS、SOCKS 或 bootstrap。

## 当前兼容边界

- 配置键区分大小写，拒绝未知/重复键和多份 YAML document，不支持 Go 的 dotted-key 归一化。JSON 使用 libyaml 解析，因此也接受 YAML 语法；没有单独的严格 JSON 语法检查。日志输出到 stderr，`log.level` 校验但不控制细分日志等级；非空 `log.file` 和 `log.production: true` 被拒绝。
- regexp 使用无 Unicode、无 JIT 的 8-bit PCRE2，按字节匹配，`\d`/`\w` 保持 ASCII 类语义；匹配/回溯深度有上限，与 Go RE2 的语法和最坏复杂度不同。`(*UTF)`、`(*UCP)`、`\p{...}`、`\P{...}` 和 `\X` 编译失败；不会忽略错误规则、转成字面量或回退到其他引擎。域名大小写只处理 ASCII；DNS 问题名只接受可打印 ASCII 标签（含常规 punycode），不接受 raw Unicode、二进制标签、多问题或非 QUERY opcode。国际化域名规则和查询须预先使用 ASCII/punycode，本实现不做 IDNA 转换或 Unicode 大小写归一化。库级字节匹配测试中的 UTF-8 字节不代表 DNS 服务支持 raw Unicode 域名。
- 服务端工作线程使用有界 UDP/TCP 上游连接池：每线程 8 槽、空闲 30 秒，按端点、传输、mark 和接口隔离；一个连接内不复用已用过的 DNS ID，异常或脏连接关闭。库调用及非工作线程仍新建连接。不提供 pipeline；非零 upstream idle_timeout/max_conns、enable_pipeline 和 TLS 相关参数会报错。UDP 等待回答期间，每秒在同一 connected socket 上重发原始查询与 ID，保留 mark/接口设置；重发不延长交换共享的 5 秒期限，TC 转 TCP 后停止 UDP 重发。sequence 设置 5 秒执行预算并在动作边界检查，正在执行的交换最多还需 5 秒；递归/循环也有深度与步数上限。
- `reject` 支持 0–15 的基础 RCODE。UDP 大回答生成带 TC 的 question-only 回答，客户端可转 TCP；不会保留可容纳的部分 Answer 或补造 OPT。
- 缓存保持 IN 类、问题大小写和 AD/CD/DO 隔离。带非空 EDNS options、额外非 OPT 数据或压缩问题的查询绕过缓存。只剥离末尾 OPT；非末尾 OPT 回答不缓存，以保留 DNS 压缩偏移。lazy_cache_ttl 与 Go 相同，是自存储时起的总保留时间，并非额外 stale 时长。
- nftset 需要标准路径的 `nft`，每次查询新读集合元数据；普通地址集合通过 Linux Netlink 事务写入，interval 集合保留 argv/stdin CLI 写入。不启动 shell，不创建表或集合。表名和集合名限定 1–127 字节，以 ASCII 字母或下划线开头，后续仅字母、数字、下划线或连字符。普通集合写入前以完整 ruleset generation 包围第二次元数据检查，并在 batch 中校验 generation；必须收到完整成功回执，错误、代际改变或提交状态不明确时失败，不自动重放。仅学习 Answer 中 IN A/AAAA，不发送元素 TTL，使用集合默认 timeout；没有用户态 membership 缓存或元素维护线程。整个 apply 的 FIFO 等待、元数据检查和写入共享原有 5 秒预算。macOS 可检查配置，实际 mark/接口绑定和 nftset 仍只支持 Linux。
- UDP listener 单独请求 256 KiB 接收缓冲并读回实际值，受内核上限约束；Linux 读回值包含双倍 bookkeeping，不等于进程 RSS。最多 64 个 listener、128 个 TCP 连接、64 个未完成查询和 64 个异步 lazy 刷新；TCP 每连接串行处理，支持已排队的连续帧。队列满时 UDP 返回 SERVFAIL，TCP 关闭连接。没有 Go 的 UDP packet-info 源地址选择或 Unix listener 支持。

## 验证

```sh
make -C c test
make -C c -j4 BUILD=../.build/c-asan SANITIZE=1
make -C c test BUILD=../.build/c-asan SANITIZE=1
python3 c/tests/nft_cli_test.py --output .build/c-nft-cli-native
python3 c/tests/nft_cli_test.py --output .build/c-nft-cli-asan --sanitize
```

测试使用临时回环端口和 mock DNS。系统限制本地 socket 绑定时需要允许测试进程绑定回环端口。单元测试覆盖报文边界、缓存寿命/LRU/线程并发、十万条域名规则、配置错误、引用和 sequence 控制流；端到端测试覆盖实际分流、缓存、lazy 刷新、UDP/TCP、截断回退、ID 校验、并发客户端和只读检查。

`tests/nft_cli_test.py` 使用 Darwin 上的窄 UAPI shim 和 fake Netlink I/O 检查实际生产路径；普通集合验证两次元数据读取、GETGEN 与成功回执事务，interval 仍验证原 argv/stdin 前缀。`tests/nft_netlink_test.c` 检查生产使用的报文编码和回执解析。它们同时覆盖仅学习 Answer 中 IN 地址、空回答无写入及非法名称拒绝。Linux 交叉构建另外使用真实 UAPI 静态断言。可用 `--old-source <旧nftset.c>` 验证旧实现的字面双引号会使此回归失败。它不执行真实 nft，也不代替设备内核写入与路由验证。

UDP 重发修复针对已确认的丢包耐受性差异：旧 C 只发送一次，冻结 Go 每秒重发。独立首包丢弃诊断可复现这项差异。131 首轮冷缓存 UDP 并发 4 的超时原因仍未证实；后续相同固定 N 的一次成功重播和本机故障注入均不能单独定位原始 LAN 故障。原始记录保留在 [测试报告](../optimization/c-profiles-20261009/REPORT.md)。

`tests/cache_domain_test.c` 首先检查实际链接的 PCRE2 已关闭 Unicode/JIT，避免误连系统库而得到假通过；逐条测试 [Loyalsoldier direct-list 固定版本](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/99f994716ed6323595c9ba5ff6dc36b6a1fe27c7/direct-list.txt#L111725-L111732) 的全部八条 regexp，覆盖正例、负例、锚点、数字/单词类、重复次数、分组、ASCII 大小写及 punycode。源文件 Git blob 为 `7f1511773bce814fa841dcab4ff2a6314bd8575b`。另有五类 Unicode 功能编译拒绝和文件路径/行号回归；`tests/engine_test.c` 检查内联表达式拒绝、外部文件 `check` 跳过与启动加载失败的区别。

`tests/domain_fixture.py` 复用已有 `tests/fixtures/matcher_domain.json` 的 ASCII/公共 regexp 语法子集；原有四项 Unicode/RE2 专项仍逐项输出跳过原因，未扩大跳过范围，也未声明完整 matcher 兼容。它另外独立测试 ASCII 类、引用、八进制、单词边界、按字节匹配，以及五类 Unicode 功能必须拒绝；这些新增测试不属于跳过项。目标设备、真实 nftset 内核写入、mark 路由和性能尚需各自验证。本机 mock 通过与 Linux 交叉编译不代替这些实机证据。

初版历史验证通过三个单元套件、14 项端到端测试、共享 fixture 的 70 条断言及 ASan/UBSan；Linux ARM64/x86_64 的 24 个编译单元通过。详细范围和本机证据位置见 [验证记录](VALIDATION.md)，这些数字不作为本次无 Unicode 产物的验证结论。

最新分版本实机结果、文件大小、RSS/HWM 和尚未通过的范围见[当前测试状态](../optimization/c-profiles-20261009/STATUS.md)。本文件中的初版数字属于历史验证；不能把它们当作当前产物的实测结果。
