# Go 构建版本

当前 Go 代码提供 `full` 与 `minimal` 两个编译版本。两者复用同一套 DNS 请求上下文、缓存、域名匹配和 UDP/TCP 处理代码；`minimal` 使用编译标签 `mosdns_minimal` 限定功能，以适合当前 CN-site 直连、其他域名经 WireGuard 查询的分流场景。

## 能力范围

| 能力 | full | minimal |
|---|---|---|
| 配置格式 | YAML / YML / JSON | YAML / YML / JSON |
| 插件 | 当前完整插件注册表 | 六个插件类型：`domain_set`、`cache`、`forward`、`sequence`、`udp_server`、`tcp_server` |
| 域名匹配 | 原有匹配器 | `qname`，包括 domain/full/regexp/keyword 规则 |
| 执行链 | 原有执行能力 | `has_resp`、`nftset`，以及 `accept`、`goto`、`return`、`jump` 等 sequence 内置动作 |
| DNS 上游 | UDP、TCP、DoT、DoH、DoH3、DoQ | 数字 IP 地址的 UDP/TCP；保留 UDP 截断后的 TCP 回退 |
| 上游路由约束 | socket mark / 绑定接口 | socket mark / 绑定接口 |
| 缓存 | 内存、lazy cache、磁盘 dump、HTTP 管理接口 | 内存、lazy cache；无磁盘 dump |
| HTTP API / 指标 | 支持 | 无 API，不创建或更新未导出的业务指标 |
| pprof | 显式启用 `pprof` 标签 | 不支持 |
| SOCKS / bootstrap | 支持现有选项 | 不支持 |
| 服务及配置转换命令 | 当前完整 CLI | 前台 `start`、`check`、`version`、帮助 |

`qname`、`has_resp` 是 sequence 匹配器，`nftset` 是 sequence 快捷执行器，不额外计入六个插件类型。最小版也保留 sequence 的 `reject`、`_true`、`_false` 内置动作。`nftset` 写入需要 Linux nftables 及相应权限。

最小版启动时会明确拒绝 HTTP API、磁盘 dump 参数（`dump_file` 或非零 `dump_interval`）、加密 DNS 协议、TCP TLS 证书/密钥，以及 SOCKS/bootstrap 参数。它没有 `ip_set`、`resp_ip` 等完整插件；CN-IP 的网站流量分流由既有 nftables 和路由规则承担，不在这个最小 DNS 配置中进行回答筛选。

这里的 `full` 指当前分支完整功能集合。此前优化已经将配置格式收敛为 YAML/YML/JSON，并更换轻量指标实现：指标 HTTP 输出为 Prometheus text 0.0.4 与 gzip，不支持 protobuf/OpenMetrics 或 zstd 协商；扩展插件的指标接口及部分 Go runtime 指标也有兼容边界，见 [轻量指标说明](../pkg/metrics/README.md)。pprof 默认关闭，需要单独编译开启。因此它不代表上游历史版本的所有扩展接口保持逐字兼容。

## 构建

使用 Python 3.9+ 与 Go 1.26。脚本默认构建两个未压缩的 Linux ARM64 可执行文件，`CGO_ENABLED=0`，不需要目标设备另行安装 Go runtime。它不调用 UPX，也不安装或启动程序。

```sh
python3 benchmarks/build-go-profiles.py \
  --go /path/to/go1.26/bin/go \
  --output /tmp/mosdns-profiles-example \
  --version local-20261008
```

`--output` 必须是尚不存在的目录。省略它时，在仓库 `.build/` 下创建带时间与随机后缀的新目录。可以指定 `--profile full|minimal|both`、`--goos`、`--goarch`；默认是 `both`、`linux`、`arm64`。版本字符串限 1–128 个字母、数字及 `. _ / + ~ -`。

构建有 pprof 的完整版本：

```sh
python3 benchmarks/build-go-profiles.py \
  --go /path/to/go1.26/bin/go \
  --profile full --pprof \
  --output /tmp/mosdns-full-pprof-example
```

`--profile minimal --pprof` 会失败。`both --pprof` 只给 full 加上 pprof，minimal 仍不含它。

脚本继承已配置的 `GOMODCACHE`、`GOCACHE`、`GOPATH` 等环境和模块下载设置。离线构建前应准备模块缓存，并设置 `GOPROXY=off`、`GOSUMDB=off`。脚本设置 `GOTOOLCHAIN=local`、`GOENV=off`、`GOWORK=off` 并清空 `GOFLAGS`，避免自动下载工具链、使用仓库之外的 workspace 或继承额外编译标签。固定构建参数为：

```text
-mod=readonly -trimpath -buildvcs=false -pgo=off -p=2
-ldflags="-s -w -buildid= -X main.version=<version>"
```

输出目录包括：

- `mosdns-full-linux-arm64` / `mosdns-minimal-linux-arm64`：所选版本的二进制；Windows 目标附 `.exe`。
- `snapshot/`：冻结的根目录全部 Go 文件、`coremain/`、`mlog/`、`pkg/`、`plugin/`、`tools/`、`go.mod`、`go.sum` 和 `tests/fixtures/`、`tests/profiles/`。部署、旧优化证据、工具链和 `.build/` 不进入快照。
- `full-deps.json` / `minimal-deps.json`：对应编译标签的 production 依赖图，使用不带 `-test` 的 `go list -deps -json` 获取。
- `manifest.json`：输入文件 SHA-256、输入树摘要、Go 版本与工具链文件摘要、命令、非敏感环境白名单、依赖图摘要以及二进制大小和 SHA-256。
- 各命令日志。

构建只在冻结快照中运行，并在命令前后及最终输出前核对原输入和全部快照文件。所列项目源码新增、删除或修改，快照变化，Go 可执行文件变化，依赖解析失败或构建失败，都会使 manifest 标记 `failed`。校验范围为本项目输入、快照和 Go 可执行文件；GOROOT 与模块缓存使用记录的工具链版本和模块校验和，没有逐文件冻结。只把 `status: complete` 的 manifest 当作成功输出；失败目录保留供诊断，不能沿用为新构建输出目录。构建成功证明产物生成与输入一致，不替代功能、性能和设备运行验证。

## 当前 site-only 分流配置

[go-profiles-site-only.yaml](go-profiles-site-only.yaml) 可供两个版本使用。它监听回环地址 `127.0.0.1:15361` 的 UDP 与 TCP，不占用 53 端口，也不自动修改 OpenWrt、WireGuard、nftables 或路由策略。

查询链如下：

1. 先检查内存缓存；缓存命中也执行最终 CN-site 地址学习。
2. CN-site 域名直接查询默认 DNS 示例地址 `192.168.100.1:53`，绑定 `br-lan` 并使用直连 socket mark `0x01000000`。
3. 其他域名查询 `1.1.1.1:53`，绑定既有 WireGuard 接口示例 `c131tm`，使用隧道 mark `0x02000000`。
4. CN-site 回答写入已有 `inet mosdns_cn` 表的 `cn_site4` / `cn_site6` 集合，然后返回。没有 `223.5.5.5` 首查、CN-IP 回答选择或 dnsmasq `dns_seen4/6` 重复学习。

运行前需要准备并核实：

- `/etc/mosdns/cn-site.txt` 为实际 CN-site 规则文件。
- 当前路由默认 DNS 的数字 IP 地址；若它不是 `192.168.100.1`，修改示例。程序不会动态追踪 `/etc/resolv.conf` 中的变化。
- `br-lan` 与实际 WireGuard 接口；`c131tm` 是此前隔离测试的示例名称，测试清理后不保证仍存在。
- 已有 `inet mosdns_cn` nft 表，集合 `cn_site4` 类型为 `ipv4_addr`、`cn_site6` 类型为 `ipv6_addr`，以及需要的超时设置。示例不会创建它们。
- 已有出口规则能够让 `0x01000000` 直连、`0x02000000` 经隧道，并拦截隧道不可用时的错误出口。`bind_to_device` 和 `so_mark` 不会自动创建隧道、路由或防泄漏规则。
- 已有网站流量分流规则使用静态 CN-IP 与动态 `cn_site4/6` 集合。这个 DNS 进程本身不会修改网站流量的路由策略。

最小版可先执行不打开 socket、不修改 nftables 的检查：

```sh
./mosdns-minimal-linux-arm64 check -c /etc/mosdns/go-profiles-site-only.yaml
./mosdns-minimal-linux-arm64 start -c /etc/mosdns/go-profiles-site-only.yaml
```

`check` 只做配置解码和插件可用性检查；插件参数、接口、socket 和 nft 集合在实际启动/请求路径验证。前台 `start` 需要已准备的网络配置及相应 Linux 权限。示例不包含常驻安装或自动接管系统 DNS 的步骤。
