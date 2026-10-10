# diversion-dns-c v0.1.0

正式版本号为 `0.1.0`；OpenWrt APK 为 `0.1.0-r1`。命令行保留现有 `mosdns-c` 名称，运行 `version` 显示 `mosdns-c 0.1.0 fixed-splitter`。

## 功能与下载

- 固定 CN/foreign DNS 分流、共享 TTL/LRU/lazy 缓存、UDP/TCP 上游与 TCP 持久连接、nft 最终处理、有界 `key=value` 配置及离线检查/迁移工具
- 默认 PCRE2 保持不变；可选 POSIX-lite 使用受限 ASCII 正则，不等价于任意 PCRE2 表达式
- 双架构动态 POSIX-lite APK：`diversion-dns-c-lite-0.1.0-r1_aarch64_cortex-a53.apk` 和 `diversion-dns-c-lite-0.1.0-r1_mipsel_24kc.apk`
- 另附 PCRE2/native/static 和 POSIX-lite/native/static 验证包、逐架构 buildinfo、源代码和完整测试证据、`release-verification.json` 及 `SHA256SUMS`

APK 以官方 OpenWrt 25.12.5 SDK 构建，分别参考 `qualcommax/ipq60xx` 和 `ramips/mt7621`。CPU 标签相同并不保证固件 userspace ABI 匹配。APK 声明 `libc` / `libpthread` 依赖；ELF 仅动态依赖 `libc.so`。某些设备仍需要相应的 `libpthread` 包登记。不得为了试用替换系统 libc。

## 安装与配置边界

APK 仍是实验性、未签名产物，不是默认受信的软件源包。SHA256 校验内容完整性，不提供发布者签名认证；本发布没有生成签名密钥或修改设备信任。包只含应用及 OpenWrt 包管理记录，不包含 init、配置、LuCI 或自启动，不会自动接管 DNS 或配置分流。

此前测试 APK 使用 `0.2.0-r1`；按 APK 包管理版本比较，`0.1.0-r1` 是降版本，不是自动升级。升级/降级前先备份现有配置与规则，核对 ABI 与依赖，再单独安排安装。不要用强制覆盖选项覆盖用户配置，也不要把旧 `0.2.0` 包改名当作本版本。

旧 YAML 不直接作为新运行配置。使用源码中的 `scripts/migrate-site-config.py` 离线迁移受支持的 site-only 配置，再用新程序 `check` 校验配置与规则；保留原文件与备份，迁移后仍需实际环境验收。

## 验证与复现

只有同一发布提交的四个常规 build/test job 和两个 APK job 全部通过，才创建 `v0.1.0`。所有附件绑定精确 commit、run/attempt、源码与 SHA256；发布阶段重新下载并验证 Actions ZIP 摘要、包版本、源码、ELF 与测试记录，并用固定 SDK 工具独立提取 APK、检查 ABI、执行 CLI 和 12 项 loopback 集成测试。

每个 APK 的 CI 还执行五个 C harness、157 项 netlink mock 断言、18 项 nft CLI 检查、43,200 次并发 regex 匹配及 81,089 次与同源 PCRE2 的便携子集差分比较。两个已知预算差异与不支持的语法保持明确记录。macOS 的可选 PyYAML 测试在未安装该依赖时明确跳过，不计为通过。

这些是 GitHub CI、匹配 SDK libc 和 QEMU 的验证。本次 `0.1.0` 未在用户实机重新验收；旧版本的设备反馈和历史参考 rootfs 检查不代表新版本实机测试。没有据此宣称真实内核 nft 写入、实际出口、性能、RSS、闪存增量或长期稳定性已验证。

先校验 `SHA256SUMS`，再展开对应 `verification-<arch>-v0.1.0.tar.gz` 并校验其中的 `SHA256SUMS`。其中保留原始 buildinfo、元数据、测试日志、SDK pins 和精确源代码。按源代码中的 `packaging/openwrt/README.md` 使用匹配 SDK 在全新目录复现；正式 APK 必须由 `v0.1.0` 的确切源码重新构建。
