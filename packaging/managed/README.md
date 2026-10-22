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
测试机 A/测试机 B 迁移保留已核验 profile/config/policy 指纹，但服务名改为 `diversion-dns`；
新 UCI 的 config_file 指向原配置路径，规则文件与 nft 对象继续使用原位置。
如旧服务负责创建独立 nft 表，先把其幂等 add table/set 定义保存到
`/etc/diversion-dns/nft-init.nft`，再显式设置 `nft_init=1`。首次默认关闭；
服务停止/卸载不会删除 nft 表，也不会 flush 共享规则。失败时拒绝启动解析器。
`测试机 B` 的旧 stop 会删除测试表，迁移必须接续此初始化责任；`测试机 A` 的表由原网络配置管理，保持 nft_init=0。
`cpu=0` 使用程序默认；可指定原 --cpu 值。`memory_limit=0` 不另限地址空间；
可设原字节限制。nofile 固定 1024，`cache_stats` 可保留原 stderr 统计秒数。
不能只复制 DNS 配置而遗漏旧 init 中的资源初始化与运行限制。
测试机 A/测试机 B 的旧手工菜单要先备份并撤下，避免同一路由被多个菜单文件定义。
不向 .1 安装或套用这两个设备的 profile。

## 升级、卸载与回退

包数据库管理所有新文件；配置属于 /etc 保护路径，并附 OpenWrt conffiles 清单。
升级钩子只恢复升级前已运行的本包服务，未启用实例保持停用。启动前检查配置；
升级失败要使用部署备份回退，不要将失败描述成成功。管理包升级会刷新菜单缓存。
卸载只停止/禁用自身服务、移除包拥有的文件；修改过的配置由 APK 保留。
**卸载正在承担 DNS 的核心前，必须先恢复原解析服务/转发目标**，否则客户端会失去 DNS。
不使用强制覆盖或绕过依赖移除；先卸载管理包，再移除核心。

测试机 A/测试机 B 先演练“未激活安装→卸载→重装”，确认旧 DNS 不受影响，再显式迁移服务。
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

## 可选的受管双 WireGuard 出口

`/etc/diversion-dns-ui/routing.json` 默认 `enabled=false`。显式启用后才开放
AWS、NoBrand 和上次出口回滚。该适配器只移动既有接口两个 peer 的默认前缀，
不创建隧道、不接管 LAN、不修改 DNS、防火墙、主路由或其他 peer。
本地配置需要 `interface`、`table`、`families`（4/6）、`initial` 和
`exits.aws` / `exits.nobrand`，每个出口包含 `peer` 公钥及对应 `ipv4` / `ipv6`
预期公网地址。地址和公钥不得提交到仓库。测试可配置 `namespace`，页面会明确
标注隔离范围；这样的结果不代表 LAN 已切换。无 namespace 时，探测目标的实际
策略路由必须走受管接口，否则拒绝成功。

运行状态分别读取配置选择、每个地址族默认 peer 和目标表默认路由。切换前保存
独立副本，确认独立 guardian 已启动后才修改；新 HTTPS 请求还必须返回预期地址。
失败或 worker 超时会恢复旧 peer/选择。遇到第三方改动时保留 `rollback_failed`
证据，拒绝覆盖未知状态。此时应先处理冲突，再恢复；不能把它视为已经恢复。
monitor 也会检查超期事务。其他未部署的代理/应急功能仍禁用。

## 有旧包保障的升级

设备页面的域名查询通过 `query-start` / `query-status` 执行后台任务。
多地址回答在较慢的设备上可能需要约一分钟；页面按任务标识轮询完整结果，
不重复提交，也不将其他查询的结果显示在当前输入下。查询和检测共用任务锁。
等待超过 120 秒或工作进程退出时显示失败；仍存活的任务保留锁，避免叠加负载。
同步 `query` 命令保留给本地诊断。查询只推断新连接的路径，不证明网站实际访问成功。

root 工具 `/usr/libexec/diversion-dns-upgrade` 接收
`/root/diversion-upgrade/<transaction-id>` 和 `start` / `status` / `rollback`。
目录及 `old`、`new` 子目录必须属于 root、权限 0700；其中放置已按精确 CI
提交/run/attempt 验证的两套 APK。`plan.json` 的 `old` 和 `new` 分别使用对应
`managed-packages.json` 的完整对象。首次部署可从已核验的新包载荷取得该脚本，
用绝对路径运行；不会在准备完成前改服务。

准备阶段核对旧版本、ELF 摘要、两套 APK 摘要/元数据、仅涉及本项目两包的安装计划，
压缩备份应用配置，并记录 network/firewall/dhcp 的摘要及服务运行状态。
`cache_warm_file` 是退出时会更新的运行数据：保留在备份内并单独记录，不要求
内容摘要在重启前后相同。配置文件、规则文件和静态租约仍严格核对；此工具要求
预热路径为规范化绝对路径，且不能与配置或静态输入重叠。
准备成功并确认 guardian 已运行后才安装。健康失败会安装旧 APK、恢复应用配置和
原服务运行状态；network/firewall/dhcp 只检查，绝不覆盖管理员的并发修改。
验收需要核对实际包版本、二进制、配置与 DNS 请求，不能只看 APK 命令退出码。
备份含本地配置，必须保持私有。

切换和升级应串行进行。保留手动回退目录，不要在事务进行时卸载管理组件。
准备阶段还会建立独立于 UI 的启动恢复入口：将已核验的恢复脚本复制到
`/root/diversion-upgrade/recovery/`，并创建仅指向该私有目录的固定 rc.d 链接。
后台恢复读取事务内冻结的 `guard.lua`，因此 UI 停止、未启用或包回退移除了新脚本
均不会移除这个启动恢复入口。没有活动事务时不启动后台循环；有活动事务时每 5 秒检查。
UI monitor 只向独立 procd 实例请求启动恢复；不会在 UI 自己的进程树内执行回退，
避免恢复时重启 UI 把正在安装旧包的进程一起杀掉。重复请求声明同一实例，不执行 restart。
首次从不带此能力的版本升级，必须从同一份已核验产物一起取得 guard、
`diversion-dns-upgrade-arm` 、`diversion-dns-upgrade-health.lua` 及其三个同目录模板，不能只复制单个 Lua 文件。
遇到已有入口指向别处、恢复脚本被修改或不完整的准备目录时拒绝覆盖，保留现场供检查。
此机制支持正常重启后的恢复路径；突然断电导致存储未落盘、文件系统损坏等仍不是
已验证保证。真实设备、故障注入及浏览器验收结果另见私有 validation 报告。

升级钩子使用 APK 自身的数据库锁，不再增加可因 SIGKILL 残留的 mkdir 锁。
守护恢复会强制重装核验过的旧包，即使数据库仍记录旧版本，以修复中断时的部分写入。
若模拟修复因本项目两包的 broken 状态返回 1，仅在计划明确重装这些包且没有
求解错误时继续；其他包损坏、未知错误、旧钩子残留锁均保留错误并停止，不自动删除。

受保护升级通过内部环境标记让新版包钩子保留旧服务运行；新包载荷、原配置摘要及新程序配置检查全部通过后，再由守护流程重启先前运行的服务。直接调用 APK 的生命周期行为不变。升级 worker 退出或进入暂停状态时提前恢复，不等待 300 秒总期限。恢复旧版时，旧版钩子仍可能短暂停止服务，因此这不是零中断升级承诺；断电和重启也需要另行验收。

APK 默认清理安装脚本环境；守护安装使用 `env -i` 仅传入 PATH 和内部延后重启标记，并显式开启 `--preserve-env`。模拟脚本测试之外，还应在实际 APK 执行前后比较服务 PID，确认钩子没有提前重启旧服务。

升级状态的提交、超期判断及回滚共享内核文件锁。恢复方拿锁后重读状态；自动恢复不会撤销已提交事务，也不会重复已完成或已失败的回滚。回滚期间持锁，其他恢复请求只等待，不再杀回滚进程。手动 `rollback` 仍允许撤销成功提交或明确重试失败回滚。准备阶段与出口切换也使用同一把锁，避免活动标记覆盖。

升级健康门槛检查已验证的包/ELF、配置、服务运行状态及该 resolver 进程拥有的本地 UDP/TCP 监听；不再要求公网域名同时返回 A/AAAA 正答案。因此外部解析失败和没有 IPv6 外网不会单独触发升级回退。这是本地监听就绪校验，不代表上游或真实 DNS 请求成功；上游和真实请求仍需部署后另行诊断。当前支持 IPv4 监听 profile。

本轮仍未处理新版本新增配置文件在回退后可能残留，以及诊断/查询共享任务锁的问题；不能将上述并发修复解读为这些问题也已解决。
