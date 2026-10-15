# diversion-dns-c v0.1.3

版本号 `0.1.3`，OpenWrt APK `0.1.3-r1`，CLI 显示 `mosdns-c 0.1.3 fixed-splitter`。本版在 v0.1.2 上加入 DNS 降级自动恢复覆盖层（PR #20），并收录未使用的 vendored libyaml 清理（PR #19）。C 请求处理逻辑没有新增改动；未合并的缓存优化不在本版中。

## DNS 自动恢复

现有定制 OpenWrt 守护在健康检查失败后切换到 ISP DNS。新增覆盖层保持备用 DNS 服务，同时探测并恢复 C DNS：

- 首次冷却至少 120 秒，连续三轮验证国内/境外 A、AAAA，每轮间隔 10 秒；只有全部成功才切回。
- 回切后继续通过客户端 DNS 入口验证新鲜查询和固定域名正答案。失败按 60/120/240/480/900 秒退避重试，持续健康 600 秒后重置。
- 手工降级和未知来源的降级保持不动，不自动覆盖管理员选择。
- 持久事务仅保存和恢复 dnsmasq 的 server/cachesize。处理中断和重启遗留状态；备用恢复失败时保留 C，避免停止仍可能提供服务的进程。

健康循环每轮增加 8 次 DNS 请求，轮询等待 20 秒。健康探测接受匹配的 NOERROR/NXDOMAIN，拒绝 SERVFAIL、超时和截断；最终固定域名检查必须有实际地址记录。探测域名和国内规则归类必须符合部署说明。

## 安装边界

`openwrt-recovery-v0.1.3.tar.gz` 单独提供覆盖脚本、README、LICENSE 和精确提交/源码树/逐文件 SHA256 清单。它针对 `192.168.100.1` 已有的定制布局，依赖现有 `dns-mode.sh`、策略及守护服务、15363 端口、UCI、flock、Lua/nixio。先阅读包内 README 并备份、准备设备端定时撤回，再验证依赖和路径；不能直接套用到未知布局。

APK 为未签名的动态 POSIX-lite 包，仍只安装程序，不包含服务配置、自动恢复覆盖层、LuCI 或自启动，也不会自动接管 DNS。发布本身不部署设备。PCRE2 包保留 PCRE2 并关闭 Unicode/JIT。包版本高于 `0.1.2-r1`，低于历史实验包 `0.2.0-r1`。

## 验证与限制

覆盖层真机验收使用 PR #20 提交 `a91d68a2395ffc70e8be6c7ba7cc6a20a8e1623f`，主路由保留原有 C 0.1.1 二进制。发布仅修改版本标识、发布流程、文档和测试；不能把这次覆盖层结果称为 v0.1.3 APK 的真机安装验收。

- Python/脚本专项 33/33，完整 Python 回归 358 项中 325 通过、33 平台跳过。
- `.1` BusyBox 隔离替身场景 10/10，实际 Lua 对受控 A/AAAA 回包验证 16/16。
- `.1` 受控触发健康降级后，从 ISP DNS 就绪到自动恢复 C DNS 共 156 秒，没有人工调用恢复。
- 连续 567 条 LAN 实际 DNS 请求中 566 成功；进入降级、重启 dnsmasq 时出现 1 条约 2 秒超时。自动回切阶段未观察到新增失败。这是每秒一条抽样，不承诺切换无中断。
- C 二进制、路由、防火墙、DDNS 以及无关 DHCP 配置保持不变，设备端备份保留。

本轮没有切断真实 WAN/WireGuard、重启主路由或完成 24 小时稳定性测试；没有验证 IPv6 DNS 传输或外部 VPN 终端。A/AAAA 是记录类型，传输使用 IPv4。中断/重启协调和十分钟稳定复位由脚本测试覆盖。

最终发布提交的构建、kernel、delivery、APK 和独立测试套件均由发布脚本重新核验；准确的提交、run/attempt、资产摘要和检查范围见 `release-verification.json`。APK 还会从下载件独立检查元数据、ELF、payload，并在官方 SDK libc/QEMU 下执行版本和集成测试。云端及模拟验证不能替代最终 APK 的真机验收。本版没有新的 QPS 或延迟提升声明，v0.1.2 已记录的性能限制仍适用。

## 下载内容

正式资产共 18 项：

- `SHA256SUMS`
- `RELEASE-NOTES.md`
- `release-verification.json`
- `openwrt-recovery-v0.1.3.tar.gz`
- `diversion-dns-c-lite-0.1.3-r1_aarch64_cortex-a53.apk`
- `buildinfo-aarch64_cortex-a53.json`
- `verification-aarch64_cortex-a53-v0.1.3.tar.gz`
- `diversion-dns-c-lite-0.1.3-r1_mipsel_24kc.apk`
- `buildinfo-mipsel_24kc.json`
- `verification-mipsel_24kc-v0.1.3.tar.gz`
- `pcre2-native-linux-amd64-v0.1.3.tar.gz`
- `pcre2-native-macos-arm64-v0.1.3.tar.gz`
- `pcre2-static-linux-amd64-v0.1.3.tar.gz`
- `pcre2-static-linux-arm64-v0.1.3.tar.gz`
- `posix-lite-native-linux-amd64-v0.1.3.tar.gz`
- `posix-lite-native-macos-arm64-v0.1.3.tar.gz`
- `posix-lite-static-linux-amd64-v0.1.3.tar.gz`
- `posix-lite-static-linux-arm64-v0.1.3.tar.gz`

验证包保留精确源码、逐文件哈希和 CI 日志。已有 tag/release 不会被覆盖；发布资产先完整上传为草稿并校验 GitHub digest，再公开为正式版本。
