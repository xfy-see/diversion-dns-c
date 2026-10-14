# diversion-dns-c v0.1.2

版本号 `0.1.2`，OpenWrt APK `0.1.2-r1`，CLI 显示 `mosdns-c 0.1.2 fixed-splitter`。本版包含 v0.1.1 后的修复与优化（PR #7–#15）；发布提交和构建身份以 Release 正文及 `release-verification.json` 为准。

## 改动与兼容性

- 上游 UDP 默认每次使用新 socket/随机源端口和随机 DNS ID；未使用的预备 socket 在回复之后维护。`udp_sport_reuse=0` 保持默认；可选有限复用会削弱每查询源端口唯一性，不能把它当安全性不变的加速开关。
- 请求和响应解析结果在缓存、分流和 nft 处理中复用。压缩指针必须指向合法的已解析域名边界；指入 TTL、原始 RDATA 或标签中间等畸形回答被拒绝。
- nft 并发规则集变化后回读确认，仅补写缺失地址。普通 set 的 `nftset_fast=0` 路径也可直接使用 netlink，不再每次启动 nft 命令；interval 路径仍有不同开销。
- 超过 256 条 Answer A/AAAA 的回答正常返回，但只学习前 256 条；interval 重叠前缀可跳过而不使整条查询永久 SERVFAIL。跳过或截断地址不进入 CN-site 集合，可能按默认路由转发。
- 新增 `nftset_hit_window_ms=1000`，短窗口内跳过满足续期条件的重复写入，设 0 恢复逐次核对。外部 flush、删除或重建后，重新学习最多延后一个窗口；CLI 路径续期也可能延后一个窗口。
- 同批 IPv4/IPv6 写入合并；fast 回读最多 8 个元素一批，末批携带规则集版本检查。额外 scratch 约 35 KB，保持永久元素与续期不缩短语义。
- Linux 在启动 worker 前预分配 fd table，减少首次 TCP 连接扩容的停顿；上游 socket 原子设置 nonblocking/close-on-exec，减少系统调用。

`nftset_fast` 默认仍为 0。启用 fast 要求 Linux ≥6.12、普通 timeout set、/32 和 /128；程序不创建生产集合或路由。配置、端口复用选项及迁移说明见 [fixed-splitter.md](https://github.com/xfy-see/diversion-dns-c/blob/main/docs/fixed-splitter.md)。从 CLI 改为 fast 时先处理旧永久学习元素，勿清空静态 CN-IP 集合。

## 验证与性能边界

2026-10-15 的功能与性能证据基于 `6b4173af09de127a943470f3f60b07bd3ccf78fe`（PR #15）。发布准备只调整版本标识、打包/发布配置、文档及相关测试（含 UDP fixture 独占端口检查）；不能把前述提交的测量改称最终发布提交实测。

- .122（mipsel）和 .131（ARM64）分别通过 20/20 协议、63/63 nft 真实内核检查；外部 flush/删除/重建恢复探针每机 24 项通过，观测最大约 0.88 秒。
- macOS 下载产物 native 与 ASan/UBSan 共 20 条验证命令通过，各 86 条 nft 契约通过；ARM64 下载静态库测试 5/5。
- 176 个性能场景中，2,406,433 次实际发送均正确响应、集合校验通过；计划 2,444,000 次，37,567 次未发送，严格速率只通过 96/176 轮。**本版不宣称严格 2000 QPS 已通过或冷查询 P99 获得稳定提升。**
- .122 冷 A/AAAA 的独立测试和完整矩阵方向相反；.131 使用 MIPS 设备作负载端时有调度停顿。同机诊断支持继续排查负载链路，但不能替代原拓扑的严格速率验收。
- M4 的新端口默认行为在慢速 MIPS 冷路径存在相对 v0.1.1 的成本；有限复用的历史结果主要改善冷 AAAA，不能承诺所有场景提速。
- 测试使用隔离端口/临时集合和受控 LAN 上游，A/AAAA 均使用 IPv4 DNS 传输。公网网页/WebSocket、VPN 出口、IPv6 DNS 传输、正式 APK 安装升级和重启持久化不由这些结果证明。

原始 PR #15 证据归档有 4330 个文件，SHA256SUMS 摘要为 `c0efdf42d7d591d5c88ea1d551dbcffb301fd8f1ee59df38ca2425f61b83357d`。功能、性能、稳定性和最终包验证分别记录，不将已知失败改为通过。

## 包与升级

APK 为未签名动态 POSIX-lite 包，包含程序但不附带 init、生产配置、LuCI 或自启动。发布不会自动部署到路由器。安装前保存原二进制、配置和路由规则；`0.1.2-r1` 高于 `0.1.1-r1`，但低于历史实验包 `0.2.0-r1`。PCRE2 验证包保留 PCRE2，关闭 Unicode/JIT。

发布资产（共 17 项；压缩验证包内含精确源码、逐文件哈希和 CI 日志）：

- `SHA256SUMS`
- `RELEASE-NOTES.md`
- `release-verification.json`
- `diversion-dns-c-lite-0.1.2-r1_aarch64_cortex-a53.apk`
- `buildinfo-aarch64_cortex-a53.json`
- `verification-aarch64_cortex-a53-v0.1.2.tar.gz`
- `diversion-dns-c-lite-0.1.2-r1_mipsel_24kc.apk`
- `buildinfo-mipsel_24kc.json`
- `verification-mipsel_24kc-v0.1.2.tar.gz`
- `pcre2-native-linux-amd64-v0.1.2.tar.gz`
- `pcre2-native-macos-arm64-v0.1.2.tar.gz`
- `pcre2-static-linux-amd64-v0.1.2.tar.gz`
- `pcre2-static-linux-arm64-v0.1.2.tar.gz`
- `posix-lite-native-linux-amd64-v0.1.2.tar.gz`
- `posix-lite-native-macos-arm64-v0.1.2.tar.gz`
- `posix-lite-static-linux-amd64-v0.1.2.tar.gz`
- `posix-lite-static-linux-arm64-v0.1.2.tar.gz`
