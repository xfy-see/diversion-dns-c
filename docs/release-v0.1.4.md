# diversion-dns-c v0.1.4

版本号 `0.1.4`，OpenWrt APK `0.1.4-r1`，CLI 显示 `mosdns-c 0.1.4 fixed-splitter`。本版汇总 v0.1.3 之后合入 main 的缓存优化（PR #18）、常用域名维护（#25）、运行统计（#27）、managed APK（#28）、隐私整理（#30）及受保护升级与恢复（#31）。发布不会自动安装到设备或切换生产出口。

## 缓存与持续统计

- 可分别配置 CN/foreign 的额外过期窗口，刷新超时或 SERVFAIL 时保留仍在硬期限内的正答案。有效 NXDOMAIN、NODATA 和地址变更仍按缓存语义撤销或替换旧结果；支持按域名禁用过期答案，适合 DDNS 等动态名称。
- 新增热点预刷新、按字节限制容量、为境外条目保留容量份额，以及只存查询名称、不存 IP 的限速重启预热。新选项默认关闭；不能与不兼容的旧 lazy 配置混用。详见[配置契约](fixed-splitter.md)。
- `cache_keep_file` 可限速维护一份常用境外域名 A/AAAA 名单，失败退避、恢复后重新刷新。默认关闭，单条后台查询串行执行；不会预连接网站、维护 HTTPS RR 或改变路由，也不能保证所有名单条目始终新鲜。名单与访问驱动的重启预热独立，详见[定时维护说明](scheduled-cache-keep.md)。
- 可选 `stats_file` 和 `stats` 命令导出有界 JSON：缓存命中、RT、成功率、错误、CN/foreign × A/AAAA/其他 × UDP/TCP 分组、最近区间与访问 Top 50。默认关闭，不新增网络监听端口；快照包含域名，默认权限 0600，建议写入临时存储。

统计的成功率指完整回复提交本机网络栈，不证明客户端收到或网站可打开；RT 不含客户端网络、TCP 握手及读帧时间。分位数是直方图桶上界估计，Top 50 超出候选容量后是带误差界的近似值。统计有固定容量和运行开销，重启开始新周期，不能代替同流量性能对照或长期稳定性验收。完整口径见[运行统计](runtime-stats.md)。

## OpenWrt 安装包与管理能力

两个 SDK 目标 `aarch64_cortex-a53`、`mipsel_24kc` 均提供以下三种包：

| 包 | 安装内容与边界 |
|---|---|
| `diversion-dns-c-lite` | 仅动态 POSIX-lite 程序，保留既有裸程序安装方式；没有 init、LuCI 或自动 DNS 接管。 |
| `diversion-dns-c` | 核心程序、procd 服务、UCI 与示例配置。默认 `enabled=0`，需配置规则、监听器及上游后显式启用；声明 nftables 依赖。 |
| `luci-app-diversion-dns` | 配套状态、DNS 指标、查询/检查/诊断、受保护升级与恢复工具及可选管理操作；依赖同一版本核心包。监控默认关闭，未配置能力不应当作可用出口。 |

APK 均未签名，须先核对来源、摘要、包身份与目标 ABI；不能将接受未签名包当作真实性校验。POSIX-lite 使用受限 ASCII 正则，不等价于 PCRE2；PCRE2 下载包仍保留 PCRE2，关闭 Unicode/JIT。已有裸程序或手工部署迁移到 managed 包时，应先处理程序路径、配置和服务所有权，避免重复监听或两套守护同时管理。不要将两个核心包当作两份需同时启用的服务。

LuCI 的包元数据是 `noarch`，正式下载名仍带构建该包的 SDK 架构，避免两个构建来源互相覆盖。其 JSON 清单记录真实元数据和摘要；选择与核心包相同 SDK 来源的配套文件。详情、依赖和显式启用步骤见 [managed APK 说明](../packaging/managed/README.md)。

可选出口切换只管理本地显式配置的既有 WireGuard 接口/peer，核对运行状态及新连接实际出口，验证失败执行回退。它不创建隧道、不自动接管 LAN，也不是通用 PBR 替代品。真实出口、端点及设备身份保存在本地私有配置，示例地址不能直接用于生产。

## 升级保护与恢复

受保护升级工具在安装前验证包摘要、身份和依赖，保存配置及旧 APK，并启动独立恢复守护；安装后通过健康检查才提交。提交、超期判断及回滚共用状态锁，获得锁后重读状态，终态不再重复回滚。回滚开始后的其他恢复调用不会重复执行回滚，崩溃接管前先停止经身份校验的所属安装进程组，避免多个 APK 操作同时写包数据库。

恢复入口独立于 LuCI/监控服务，事务期间保留冻结的恢复程序和启动入口；UI 被停止、安装进程退出或普通重启后仍可处理未完成事务。不能把这项恢复设计或隔离测试当成真实断电下包数据库必然可恢复的保证。升级及回退可能短暂中断 DNS，不承诺零中断。

健康检查先核对 procd 进程身份及该进程拥有的 UDP/TCP listener，再分别向本地监听地址发随机 `.invalid` 查询；检查完整匹配的 ID、question、QR/opcode 和报文边界。任意匹配的 RCODE（包括 SERVFAIL）均可证明报文处理路径响应，因此无需公网解析成功。探针仍可能产生上游 DNS I/O；它不证明上游或真实网站健康。

每种传输采用 8 秒绝对期限，UDP/TCP 合计最多约 16 秒 I/O 等待；只探测一个已确认的服务实例，结束后重新核对进程及 socket 所有权。只监听却不处理报文、错误响应、超时或身份改变会拒绝提交。当前仅支持 IPv4 数字监听配置；自定义队列期限、极端调度或超过探针限额的报文可能触发保护回滚。

`openwrt-recovery-v0.1.4.tar.gz` 另保留既有定制部署的 DNS 降级自动恢复覆盖层。它与 managed APK 升级事务恢复的用途不同，依赖特定现有脚本/服务布局；不得在未知设备直接覆盖安装，先读[覆盖层部署说明](../deployment/openwrt-recovery/README.md)。

## 隐私与升级准备

真实设备/出口身份改由本地配置提供，测试采用合成数据，新增发布前及 CI 隐私扫描。迁移工具离线读取旧配置并写出权限受限的本地文件，不联网、不重启服务。扫描不是任意编码秘密检测，也不会清除已经公开的 Git 历史、旧资产或他人克隆；见[隐私与迁移](privacy.md)。

升级前应保留当前配置、规则、私有身份文件、已校验旧包及回退入口，并确认目标固件、架构、剩余空间和依赖。旧实验包 `0.2.0-r1` 的包版本仍高于本次 `0.1.4-r1`，不能据版本号假定是普通升级。现有运行状态与配置需按实际部署迁移，不要用仓库示例覆盖。

回退到不识别新选项的旧程序前，先撤下新增的缓存、定时维护、统计等配置键；否则旧版会因未知键拒绝启动。保留私有证据，不把设备配置、原始日志或访问域名上传到公开 issue。

## 验证范围与已知问题

已有双架构真机验证对应 PR #31 候选提交 `3f658e4a52694075ab42557224e0d2acb454ca19`，不是本次最终 `0.1.4-r1` APK。该候选在 MIPS/ARM64 上完成受控安装、包与进程身份校验、配置保护检查，以及隔离网络命名空间内的健康探针验证：

- 上游不回答时，真实 UDP/TCP 请求取得 SERVFAIL，健康探针可通过；这里验证报文路径而非公网解析。
- 丢弃 UDP 响应时，新检查拒绝提交；旧的仅 listener 检查仍会通过。
- 丢弃 TCP 服务端报文时，新检查拒绝提交；此场景也丢弃 SYN-ACK，包含连接建立失败，不应描述为仅测试已建立连接上的回复停顿。
- 隔离对象清理和生产配置/路由保护检查通过。首次私有测试脚本失败及修正后的成功记录均保留；短时采样不等于 24 小时验收，也未重新完成浏览器登录后的完整页面验收。

发布前的最终提交必须由 GitHub 构建和独立校验；准确的提交、源码树、run/attempt、资产摘要及通过的检查见 `release-verification.json`。公开 Release 和最终包验收是不同状态：截至本说明编写时，0.1.4 新包尚未完成真机验收，生产主路由未部署本版。本版不宣称新的 QPS/P99 成绩或持续运行时长；此前性能结果不能自动用于这些新包。

仍未解决：

- [#32：回滚后新增配置残留](https://github.com/xfy-see/diversion-dns-c/issues/32)。恢复旧文件不保证删除新包新增的配置、片段或 `.apk-new`；已有哈希校验也不能发现所有新增残留。不要据此宣称逐字节还原了整个配置目录，勿未经所有权核对批量删除。
- [#33：查询、检查及诊断共用任务锁与状态](https://github.com/xfy-see/diversion-dns-c/issues/33)。并发操作仍可能互相阻塞或混淆提示；等待当前任务结束再启动另一项，后台查询改造未完全解决资源隔离。
- IPv6/主机名 listener 健康配置、真实断电/重启及完整升级期间的断网恢复需继续验收；`rollback_failed` 的后续监控和卸载后的持久恢复入口清理也仍有边界。不要在升级事务活动时卸载相关包。

## 下载内容

正式资产共 24 项，发布时全部来自精确提交并核对摘要：

- `SHA256SUMS`
- `RELEASE-NOTES.md`
- `release-verification.json`
- `openwrt-recovery-v0.1.4.tar.gz`
- `diversion-dns-c-lite-0.1.4-r1_aarch64_cortex-a53.apk`
- `diversion-dns-c-0.1.4-r1_aarch64_cortex-a53.apk`
- `luci-app-diversion-dns-0.1.4-r1_aarch64_cortex-a53.apk`
- `managed-packages-aarch64_cortex-a53.json`
- `buildinfo-aarch64_cortex-a53.json`
- `verification-aarch64_cortex-a53-v0.1.4.tar.gz`
- `diversion-dns-c-lite-0.1.4-r1_mipsel_24kc.apk`
- `diversion-dns-c-0.1.4-r1_mipsel_24kc.apk`
- `luci-app-diversion-dns-0.1.4-r1_mipsel_24kc.apk`
- `managed-packages-mipsel_24kc.json`
- `buildinfo-mipsel_24kc.json`
- `verification-mipsel_24kc-v0.1.4.tar.gz`
- `pcre2-native-linux-amd64-v0.1.4.tar.gz`
- `pcre2-native-macos-arm64-v0.1.4.tar.gz`
- `pcre2-static-linux-amd64-v0.1.4.tar.gz`
- `pcre2-static-linux-arm64-v0.1.4.tar.gz`
- `posix-lite-native-linux-amd64-v0.1.4.tar.gz`
- `posix-lite-native-macos-arm64-v0.1.4.tar.gz`
- `posix-lite-static-linux-amd64-v0.1.4.tar.gz`
- `posix-lite-static-linux-arm64-v0.1.4.tar.gz`

`buildinfo-*` 及 `managed-packages-*` 记录各 SDK 来源、包身份与摘要；验证包保留源码、逐文件哈希和 CI 证据。先将下载文件与 GitHub 资产 digest、`SHA256SUMS` 和清单交叉核对，再按仓库验证器检查 payload。已有 tag/release 不会覆盖；先上传完整草稿并复核，最后公开正式版本。GitHub 自动生成的 Source code 下载不计入上述 24 项自定义资产。
