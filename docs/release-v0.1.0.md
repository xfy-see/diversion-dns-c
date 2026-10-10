# diversion-dns-c v0.1.0

仅提供两个 OpenWrt POSIX-lite APK（0.1.0-r1），请按设备架构选择：

- `diversion-dns-c-lite-0.1.0-r1_aarch64_cortex-a53.apk`：aarch64_cortex-a53，参考 qualcommax/ipq60xx
- `diversion-dns-c-lite-0.1.0-r1_mipsel_24kc.apk`：mipsel_24kc，参考 ramips/mt7621

使用官方 OpenWrt 25.12.5 SDK 构建。请核对固件 userspace ABI 和 libc/libpthread 依赖；CPU 标签相同不代表 ABI 一定兼容，不要替换系统 libc。POSIX-lite 仅支持受限 ASCII 正则；源码默认 PCRE2 保持不变。

APK 是实验性未签名包；SHA256 只校验完整性，不提供发布者签名认证。包不含 init、配置、LuCI 或自启动，不会自动接管 DNS。此前测试版为 0.2.0-r1，安装本版属于降版本；请先备份配置与规则，再单独安排安装，不要强制覆盖用户配置。旧 YAML 需离线迁移并经 `check` 校验。

原始发布提交：`96f7d7dd11ce4f4eb937d29b7371c10c138825f6`。四个常规构建/测试和两个 APK 构建/测试均已通过，APK 已经独立下载校验、固定 SDK 检查和 QEMU loopback 测试。完整测试资料保留在 [构建 Actions](https://github.com/xfy-see/diversion-dns-c/actions/runs/38042353860) 和 [APK Actions](https://github.com/xfy-see/diversion-dns-c/actions/runs/38042353817)（artifact 下载遵循 90 天保留期），不再作为本 Release 附件。本版尚未在用户设备重新验收，不代表真实内核 nft、性能或长期稳定性已验证。

## SHA256

- aarch64_cortex-a53：`d5cd4b75a24382f321fe235e95bbfeaa34f4b473ba1de298f731eab1a66789fa`
- mipsel_24kc：`df16c975210e0a2d1c9b8274e3dbe18936a51a02170d020918beb92dfb14737e`

GitHub 自动生成的 Source code 下载入口仍保留；两个 APK 的原始字节、版本和 tag 均未改变。
