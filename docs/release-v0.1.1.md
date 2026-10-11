# diversion-dns-c v0.1.1

版本号 `0.1.1`，OpenWrt APK 版本 `0.1.1-r1`。运行 `version` 显示 `mosdns-c 0.1.1 fixed-splitter`。`v0.1.1` tag 打在 v0.1.1 发布 PR 合并到 main 后产生的合并提交上（Release 正文末尾的“发布提交”一行就是它）。这个发布 PR 只改发布脚本、CI 工作流、文档和测试，C 源码（`c/` 目录）与 PR #5 的合并提交 `0ad41b9` 完全相同；下文的性能和实机数据都是在 `0ad41b9`（或与它同树的 `2ec46d4`）上测得的。

## 概要

v0.1.1 是 v0.1.0 之后的稳定性版本，主要变化如下：

- 新增可选的 **nftset_fast netlink 快速路径**。
- 修复默认 CLI 路径上的 4 个高优先级问题：并发写入时 SERVFAIL、netlink 序列号耗尽、上游卡住拖垮所有查询、musl 小线程栈段错误。
- 解决国外上游黑洞后长时间无法解析的问题。
- 修复 TCP 慢客户端、slowloris 把服务挡住的问题。
- 默认配置（`nftset_fast=0`）现在可以正常使用。如果内核 ≥6.12，并且使用普通 timeout set，推荐打开 `nftset_fast=1`。

## 亮点

- **nftset_fast=1：用 netlink 直接写 nft set**。每个 CN 回答不再 fork/exec `nft`（每个回答 0 次 exec，CLI 路径是 1 次）。实测 x86 VM 上单次写入约 0.01 ms，CLI 路径约 1.8 ms。CN 查询吞吐达到测试客户端的上限（约 2.4–2.8 万 qps），CLI 路径约 470–520 qps。详见下文"性能"一节。
- **CLI 路径提速约 2 倍**：每个 CN 回答的 nft 调用从 2 次降为 1 次。16 并发时 CN 吞吐 270 qps → 约 510–540 qps，p50 约 59 ms → 约 30 ms（x86 VM）。
- **上游组互相隔离**：缓存命中、CN、国外三条 lane 各自排队。国外上游全部黑洞时，CN 查询和缓存命中不受影响。
- **黑洞恢复**：国外上游黑洞后，同组的正常查询恢复时间从约 80 s 降到约 4.5 s（x86 VM 和两台实机结果一致）。

## 修复

| 编号 | 修复内容 |
|---|---|
| H1 | 国外上游无响应时，CN 查询和缓存命中不再排在它后面等 5 s，也不会在积压后全部 SERVFAIL。worker 按缓存命中、CN、国外三条 lane 分开；国外的新鲜缓存命中在事件循环中直接回复。 |
| H3 | 默认 CLI 路径下，dnsmasq nftset、fw4 或脚本同时写 nft 时，CN 查询不再大量 SERVFAIL（之前约 91%）。元数据检查改用 netlink GETSET；generation 冲突或 ERESTART 时最多重试 3 次，带 1–4 ms 抖动。 |
| H4 | 长时间运行后（约 2.68 亿次写入）CN 查询会永久 SERVFAIL、只能重启恢复，这个问题已修复：netlink 序列号现在在 32 位范围内安全回绕。 |
| M3 | 用 musl 静态构建、并且没有加 `-z stack-size` 时，CLI 路径第一个 CN 查询就会段错误。现在 worker 和刷新线程的栈显式设为不小于 1 MiB，64 KiB 缓冲区改为在堆上分配。 |
| R1 | 一个上游组被黑洞查询占满后，不会再停摆约 80 s。排队超过 `queue_timeout_ms` 的请求直接回 SERVFAIL，不访问上游；同时会合并字节完全相同的在途查询，重试风暴只访问上游一次。 |
| R2 | TCP 慢读客户端（只发查询、不读回复）不会再让 UDP 的 CN 缓存命中 SERVFAIL。TCP 待写回复不再占用 lane 配额。 |
| M5 | 约 140 个只发 1 字节的 TCP 连接就能挡住所有新的 TCP 客户端，这个问题已修复。新增单帧读期限、单个回复写期限、总连接上限和每 IP 连接上限；连接满时优先淘汰最久没有进展的连接。 |
| N1 | fast 路径下，没有 A/AAAA 的 CN 回答（NXDOMAIN、TXT、纯 CNAME 等）直接返回，不再排队，也不再做 netlink 往返。 |
| N3 | fast 路径在和其他写者竞争时，重试前加入随机退避，误报失败约减少到原来的 1/4～1/5（但不是 0，见已知限制）。 |

## 新配置项

| 键 | 默认 | 范围 | 说明 |
|---|---|---|---|
| `queue_timeout_ms` | 2000 | 0–60000 毫秒，0 表示不过期（旧行为） | 请求在 lane 中排队的最长时间 |
| `tcp_read_timeout` | 5 | 1–300 秒 | 一个 TCP 帧从收到首字节到读完的期限 |
| `tcp_write_timeout` | 10 | 1–300 秒 | 一个 TCP 回复从开始写到写完的期限，偶尔读几个字节也不能续期 |
| `tcp_max_connections` | 128 | 1–1024 | 所有 TCP listener 合计的连接上限（与原来的固定值相同） |
| `tcp_max_connections_per_ip` | 32 | 1–1024 | 同一来源地址的连接上限。IPv4 按 `::ffff:a.b.c.d` 计，IPv6 按完整 /128 计 |
| `nftset_fast` | 0 | 0/1 | 1 表示启用 netlink 快速路径，要求见下 |

`nftset_fast=1` 的要求（不满足时，`check` 或启动会报配置错误）：
- Linux **≥6.12**（启动时用 `uname` 检查；更旧的内核或打了回移补丁的内核请用 `nftset_fast=0`）。
- 必须配置 `nftset_ipv4` 或 `nftset_ipv6`。IPv4 mask 只能是 **/32**，IPv6 只能是 **/128**。
- 目标必须是预先建好的**普通 timeout set**：只设 `flags timeout`，类型为 `ipv4_addr` 或 `ipv6_addr`，不能带 dynamic、interval 或 map。程序不会创建 set 或规则。静态 CN-IP 前缀请放在单独的 interval set 中。
- 每个回答最多 256 条 Answer A/AAAA 记录，超过时该请求 SERVFAIL。写入的元素超时为 TTL+15 s，会覆盖 set 的默认 timeout。

## 行为变化与升级注意

- **排队超过 2 s 会收到 SERVFAIL**：以前这类请求会继续执行（往往在客户端放弃以后才回复）。如果上游很慢（RTT 接近 1 秒）并且有突发流量，可以调大 `queue_timeout_ms`，或设为 `0` 恢复旧行为。
- **`--cpu` 现在是每条 lane 的线程数**（范围 1–64，默认 4）。三条 lane 各开这么多线程，所以 `--cpu 4` 一共是 **12 个 worker**。原来写 `--cpu 64` 的配置，现在会得到 192 个线程。内存紧张的路由器建议用 `--cpu 2`。
- **最坏情况内存变大**：报文对象最坏约 **40 MiB**（3 条 lane × 64 个请求 + 128 个 TCP 连接，每个约 128 KiB，按需分配）。v0.1.0 约 8 MiB，PR #4 之后约 24 MiB。实机正常和压力测试中的 cgroup 峰值是 15.69 / 17.69 MiB。64/128 MB 的设备可以调低 `tcp_max_connections`，或者用 `--cpu 2`。
- **TCP 连接可能被淘汰**：同一个来源超过 32 个连接，或者总数达到 128 时，会关闭最久没有进展的连接。如果很多客户端在同一个 NAT 或转发器后面，需要调大 `tcp_max_connections_per_ip`。
- **fast 路径不支持 6.12 以下的内核**：在 <6.12 内核上设置 `nftset_fast=1` 会被配置检查拒绝，不会退回 CLI 路径。
- **从 CLI 路径迁移到 `nftset_fast=1` 时，需要 flush 一次 set**：CLI 路径在没有默认 timeout 的 set 中写入的是永久元素，而 fast 路径会刻意保留永久元素，所以这些地址永远不会过期。切换时先停止服务，flush 只含 DNS 学习地址的 set，再用 `nftset_fast=1` 启动：
  ```sh
  nft flush set inet mosdns_cn cn_site4
  nft flush set inet mosdns_cn cn_site6
  ```
  表名和 set 名请换成你在 `nftset_ipv4`/`nftset_ipv6` 中配置的名称，**不要 flush 含有静态 CN-IP 的 set**。flush 之后、客户端重新查询之前，新连接会走非 CN 路由。如果想保留现有映射，可以删除永久元素后带 `timeout` 重新添加，例如 `nft add element inet mosdns_cn cn_site4 { 192.0.2.1 timeout 10m }`。
- 所有回答（包括国外回答和缓存命中）的 TTL 都会规范化：最高位为 1 的 TTL 当作 0，上限 86400 s。需要改写 TTL 的 TSIG/SIG(0) 回答会失败。
- APK 版本比较：`0.1.1-r1` 高于 `0.1.0-r1`。以前的测试包 `0.2.0-r1` 仍然会被当作更高的版本。

## 已知限制

- **M1**：interval set 中已有重叠前缀、并且没有 `auto-merge` 时，相关域名会永久 SERVFAIL（"interval overlaps"）。interval set 请加上 `auto-merge`。
- **M4**：上游 DNS ID 原样转发，UDP 上游连接是池化复用的，没有随机化 ID。
- **N2**：fast 模式下，超过 256 条地址的回答会 SERVFAIL（CLI 路径不受影响）。
- **N4**：fast 模式下一个地址族持续失败（例如 v6 set 配错）时，会清空两个族的去重缓存。功能正确，但开销变大。
- **N6**：TTL 规范化作用于所有回答（见上文）。
- **同组上游阻塞**：上游 I/O 仍然是同步的。上游被黑洞时，同组的正常查询仍可能失败约一个上游期限（约 5 s）。跨组和缓存命中不受影响。
- **合并只针对字节完全相同的查询**：使用 0x20 大小写随机化的客户端不会被合并。跟随者计入 64 个配额，所以超过 64 个的同名重试风暴，在这次上游交换结束前（≤5 s）仍会返回 SERVFAIL。
- **IPv6 按 /128 限制每 IP 连接数**：拥有整个 /64 的客户端可以绕过每 IP 上限，但仍然受总上限和淘汰策略限制。
- **fast 路径和其他写者并发时，偶尔有 SERVFAIL**：两个进程高强度竞争时，每 48000 次约有 0–5 次失败；实机上并发 helper 写者也偶尔复现。这是已有问题，修复前的 main 也一样。
- CLI 路径每个 CN 回答仍然要 fork 一次 `nft`，x86 上 CN 吞吐约 500 qps，MIPS 上更低。
- TCP 53 建议只对可信 LAN 开放。

## 性能

表 1 在 x86 VM 上测得：Linux 6.12.94，8 vCPU，netns 隔离。客户端是 Python，上限约 2.5–3 万 qps，所以 fast 路径和国外查询的数字测到的是客户端上限。每格都是单次短测，"—"表示没有测。

| 指标 | v0.1.0 `96f7d7d` | `c9925c0`（fast-path 合并） | `688c4d4`（PR #4） | **v0.1.1 `0ad41b9`** |
|---|---|---|---|---|
| CN 缓存命中 1 线程 qps，p50/p99 ms | — | CLI 249，3.97/5.02；fast 28158，0.03/0.23 | CLI 484，2.02/2.69；fast 27154，0.03/0.19 | CLI 466.4，2.10/2.81；fast 24153.5，0.03/0.12 |
| CN 缓存命中 16 线程 qps，p50/p99 ms | CLI 约 252–253，62.7–62.8/67.0–70.2 | CLI 275，58.2/64.3；fast 23480，0.59/1.84 | CLI 527，30.1/35.7；fast 29924，0.48/1.33 | CLI 512.8，31.04/35.59；fast 27993.2，0.50/1.52 |
| CN 未命中 16 线程 qps，p50/p99 ms | — | CLI 269，59.2/67.5；fast 23667，0.58/1.71 | CLI 543，29.3/33.3；fast 27937，0.49/1.40 | CLI 518.7，30.77/34.98；fast 26508.3，0.51/1.48 |
| 单次 nft 写入（新 IP / 重复 IP） | CLI 3.88/3.69 ms¹ | CLI 3.548/3.500 ms；fast 0.011/0.005 ms | CLI 1.79/1.83 ms；fast 0.012/0.003 ms | —（nft 代码未改，未重测） |
| 每个 CN 回答的 nft exec 次数 | 2 | CLI 2；fast 0 | CLI 1；fast 0 | —（未重测） |
| H1：4 个国外黑洞查询在途时，CN 缓存命中延迟 | 4703.5 ms | 4699.7 ms | 2.5–3.0 ms | 2.4–3.2 ms |
| H1：80 个国外黑洞查询在途时，CN 缓存命中 | 全部 SERVFAIL | 4000/4000 SERVFAIL | 全部 NOERROR（CLI 542 qps；fast 27536 qps） | 全部 NOERROR（CLI 522.5 qps；fast 26623.5 qps） |
| H3：外部 nft 写者并发时 CN 的 SERVFAIL | 274/300（CLI） | CLI 821/900；fast 0/60900 | CLI 0/1500、0/3000；fast 0/1500 | CLI 0/1500、0/3000；fast 0/1500 |
| R1：68 个国外黑洞查询后，正常国外查询恢复时间 | — | — | 79.60 s（每 2 s 探测为 81.5 s） | **4.50 s**（每 2 s 探测为 6.1 s） |

¹ 在 fast-path 分支 310a6e8 上测得，当时 CLI 路径代码与 v0.1.0 相同。

**实机验证（仓库所有者提供，688c4d4 → PR #5 `2ec46d4`，树与 `0ad41b9` 相同；单次运行）**

| P99（ms） | .122 mipsel_24kc | .131 aarch64 |
|---|---|---|
| 热缓存 A / AAAA | 2.589→2.637 / 2.791→2.782 | 0.430→0.435 / 0.467→0.410 |
| 冷缓存 A / AAAA | 5.795→5.566 / 5.234→5.222 | 1.015→0.987 / 0.979→0.999 |
| TCP 混合 | 11.207→12.052 | 1.107→1.102 |
| 68 个黑洞查询后的恢复时间 | 79.71 s → 4.56 s | 79.60 s → 4.52 s |
| cgroup 内存峰值 | 15.69 MiB | 17.69 MiB |

两台设备都是 Linux 6.12.94。功能请求合计 62,072/62,072 成功，P99 基本不变，没有 OOM。

## 验证

- **GitHub CI**（每次 main push 都跑）：
  - Native macos-arm64 / linux-amd64：PCRE2 和 POSIX-lite 两个后端，native 加 ASan/UBSan。
  - Static linux-amd64 / linux-arm64：musl 静态，在匹配的硬件上执行。
  - Real kernel / GCC 14：gcc-14 `-Werror`，真实内核 nft 事务测试；CLI 路径测试覆盖外部写者、国外黑洞、128 KiB 小栈、R1 过期丢弃和合并、R2 TCP 慢读者、M5 连接上限。另有 musl 静态小栈测试。
  - 两个 OpenWrt APK 作业（aarch64_cortex-a53、mipsel_24kc）：官方 OpenWrt 25.12.5 SDK 构建，在 QEMU 中运行同一 SDK 构建的 C 测试和 12 项 loopback 集成测试。
  - 每组 `make test` 包括：netlink mock 157 项断言、nft CLI contract 70 项、domain fixture 11 例/70 项断言、集成测试 12 项；Python 测试 223 项。
- **真实内核本机复测**（Debian，Linux 6.12.94，netns 隔离）：
  - `nft_kernel_test.py` 17/17，`nft_kernel_cli_test.py` 6/6（gcc-14 和 clang ASan 两种构建）。
  - 完整服务器 TSan，在 CLI 和 fast 混合负载下 0 条报告。
  - H1、H3、H4（用 gdb 模拟序列号边界）、M3 回归都通过。
- **两台实机**：.122 mipsel_24kc 和 .131 aarch64，Linux 6.12.94。
  - R1 恢复时间 79.7 s → 4.5 s。
  - R2 场景 20 SERVFAIL → 20 NOERROR。
  - M5 场景新客户端从被拒绝变为成功。
  - 62,072/62,072 个功能请求成功，P99 基本不变，内存峰值约 16–18 MiB，没有 OOM。
- **没有验证的内容**：
  - 6.12 以下的真实内核（只用伪造 uname 测试过版本门槛）。
  - M4 伪造攻击实验。
  - 长时间运行（H4 是用 gdb 模拟的）。
  - 与真实 dnsmasq nftset、fw4 reload 同时运行。

## 下载附件

- `diversion-dns-c-lite-0.1.1-r1_aarch64_cortex-a53.apk`、`diversion-dns-c-lite-0.1.1-r1_mipsel_24kc.apk`：未签名的 POSIX-lite 动态 APK。不含 init、配置和 LuCI，不会自动接管 DNS。
- `buildinfo-aarch64_cortex-a53.json`、`buildinfo-mipsel_24kc.json`
- `verification-aarch64_cortex-a53-v0.1.1.tar.gz`、`verification-mipsel_24kc-v0.1.1.tar.gz`：原始 CI 证据，包括精确源码、SDK 配置、ABI 检查和测试日志。
- `pcre2-native-linux-amd64-v0.1.1.tar.gz`、`pcre2-native-macos-arm64-v0.1.1.tar.gz`、`pcre2-static-linux-amd64-v0.1.1.tar.gz`、`pcre2-static-linux-arm64-v0.1.1.tar.gz`
- `posix-lite-native-linux-amd64-v0.1.1.tar.gz`、`posix-lite-native-macos-arm64-v0.1.1.tar.gz`、`posix-lite-static-linux-amd64-v0.1.1.tar.gz`、`posix-lite-static-linux-arm64-v0.1.1.tar.gz`
- `release-verification.json`、`RELEASE-NOTES.md`、`SHA256SUMS`

使用前先校验 `SHA256SUMS`，再展开对应的 `verification-<arch>-v0.1.1.tar.gz`，校验其中的 `SHA256SUMS`。SHA256 只保证内容完整，不提供发布者签名认证。
