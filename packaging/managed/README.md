# 核心服务与 LuCI 管理双包

本分支基于已验证 stats head a16eafe（PR #27，依赖 #25），未合并或正式发布。
GitHub 在固定 SDK 中编译并验证原 POSIX-lite ELF，再用同一 SDK 的 apk mkpkg
打成两个原生 APK。只在 GitHub 临时 runner 上用 sudo 为暂存目录设 root 所有权，打包后恢复。保留 `packaging/openwrt` 的裸程序包及原验证流程。

| 包 | 内容 | 默认行为 |
|---|---|---|
| diversion-dns-c | 已核验程序 `/usr/libexec/diversion-dns-c`、procd 服务 `diversion-dns`、UCI 与示例配置 | enabled=0，不启动、不改 DNS/路由 |
| luci-app-diversion-dns | 三分区 LuCI、stats 归集、查询、检测和诊断、固定 RPC ACL、monitor 服务 | 页面可见；monitor enabled=0，需显式启用 |

核心包包含 nftables 运行依赖，单独安装时也支持需要 nft 命令的路径。
管理包精确依赖同版本核心包；依赖 Lua/jsonc/nixio、LuCI、rpcd file、uclient-fetch、
CA 与 mbedTLS ustream、ip-full、nftables、wireguard-tools。当前验证目标为 OpenWrt
25.12.5 的 mipsel_24kc 与 aarch64_cortex-a53。不要为了安装替换系统 libc/TLS。
包版本 `0.1.3_pre20261019~<commit>-r1` 为候选交付版本，程序版本保持 0.1.3。

## 首次安装与启用

先核验精确提交/run/attempt/ZIP 和 SHA256SUMS；`managed-packages.json` 列出每个
文件的 hash/模式、依赖和包摘要。产物未签名，仅允许对已核验的这两个本地包使用
单次 allow-untrusted；不要更改全局信任或加入不明软件源。

新服务默认仅绑定本机 15353；示例上游 5301/5302 是占位地址。先配置真实上游、
CN 规则，执行 `... check -c /etc/diversion-dns/config.conf`。启用需设置
`diversion-dns.main.enabled=1`，再显式 enable/start 服务；管理采样对应
`diversion-dns-ui.main.enabled=1`。安装不会修改 dnsmasq 转发、DHCP、nft 或隧道。
用户需要自行按实际网络接入 DNS；这是配置边界，不是自动接管功能。

管理 profile `/etc/diversion-dns-ui/profile.json` 默认 generic，不能推断直连/隧道。
.122/.131 迁移保留已核验 profile/config/policy 指纹，但服务名改为 `diversion-dns`；
新 UCI 的 config_file 指向原配置路径，规则文件与 nft 对象继续使用原位置。
如旧服务负责创建独立 nft 表，先把其幂等 add table/set 定义保存到
`/etc/diversion-dns/nft-init.nft`，再显式设置 `nft_init=1`。首次默认关闭；
服务停止/卸载不会删除 nft 表，也不会 flush 共享规则。失败时拒绝启动解析器。
`.131` 的旧 stop 会删除测试表，迁移必须接续此初始化责任；`.122` 的表由原网络配置管理，保持 nft_init=0。
`cpu=0` 使用程序默认；可指定原 --cpu 值。`memory_limit=0` 不另限地址空间；
可设原字节限制。nofile 固定 1024，`cache_stats` 可保留原 stderr 统计秒数。
不能只复制 DNS 配置而遗漏旧 init 中的资源初始化与运行限制。
.122/.131 的旧手工菜单要先备份并撤下，避免同一路由被多个菜单文件定义。
不向 .1 安装或套用这两个设备的 profile。

## 升级、卸载与回退

包数据库管理所有新文件；配置属于 /etc 保护路径，并附 OpenWrt conffiles 清单。
升级钩子只恢复升级前已运行的本包服务，未启用实例保持停用。启动前检查配置；
升级失败要使用部署备份回退，不要将失败描述成成功。管理包升级会刷新菜单缓存。
卸载只停止/禁用自身服务、移除包拥有的文件；修改过的配置由 APK 保留。
**卸载正在承担 DNS 的核心前，必须先恢复原解析服务/转发目标**，否则客户端会失去 DNS。
不使用强制覆盖或绕过依赖移除；先卸载管理包，再移除核心。

.122/.131 先演练“未激活安装→卸载→重装”，确认旧 DNS 不受影响，再显式迁移服务。
保留旧二进制、旧 init、配置和完整包清单，准备定时回退后执行迁移。
单独验证包拥有权、服务重启/升级配置保留、真实 DNS、页面和卸载流程。
正式验收报告写入 validation；CI 只证明同 SDK/QEMU 与 mock 检查，不替代真机。

## 构建与源码

`build-openwrt-apk.py --managed` 只在 GitHub 调用，仍需原有 SDK/PCRE2 SHA 校验及
完整 C/QEMU 测试。`scripts/managed-packages.py` 校验两包元数据、hooks、依赖、
载荷 hash/mode、提取结果与原 ELF 完全一致；UI 的主路由控制器仅为 mock 测试参考，
不进入 APK，八个未部署网络操作始终拒绝。UI 来源及原文件摘要见 IMPORT.md。

原生打包格式依据：[apk mkpkg](https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-mkpkg.8.scd)
与 [OpenWrt 包生成逻辑](https://github.com/openwrt/openwrt/blob/main/include/package-pack.mk)。
