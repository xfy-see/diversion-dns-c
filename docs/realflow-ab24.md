# 真实 DNS 同流量 A/B 与 HTTPS 验证

这套工具复制现有 C DNS 入口的查询到两个影子实例，保留原始报文、重复访问和到达时间。它不回答生产客户端，也不接管 53 端口。测试数据仅保存在设备与本地私有目录，不能提交查询历史或原始抓包到 GitHub。

本轮比较正式版 v0.1.3（`f740af4502de536f1f128654ff10e13882788193`）与 PR #18 缓存修复版（`19c9d7ca67e068eaae14527b91125afb3ca51a2d`），使用已验证的 ARM64 静态 POSIX-lite 包。候选显示版本号仍为 0.1.1，身份以提交、run/attempt、树和 payload 摘要为准。

## 拓扑与配置

本次选择主路由 .1 的两个隔离进程，监听 127.0.0.1:15461/15462。生产 dnsmasq cache 为 0、转发到 C 的 127.0.0.1:15363；采集器只读 loopback 上该端口的 IPv4 请求。生产 C 的健康检查 nonce 单独排除。LAN/VPN/路由器自身最终转发到该入口的查询均可能包含其中，但捕获位置无法再可靠区分原始客户端来源；本地 dnsmasq 直接回答的区域与应用内 DoH/DoT 不在此流量中。

.131 的可用内存较少，且其公网 53 请求会被 .1 的现有规则截获；直接在那里运行会引入生产缓存。当前拓扑可让 A/B 都直接绑定 .1 的 wg_vpn 和 mark 1，不增加绕过生产策略的规则。该选择不等于对 .131 或 .122 的性能结论。

A/B 相同：worker=2/组、完整规则快照、cache_size=8192、cache_lazy_ttl=0、nftset_fast=0、相同 CN/foreign 上游，独立 nft timeout sets。B 调优：stale foreign=60 秒、CN=0、prefetch=10%、foreign reserve=50%；已知 DDNS 名单禁用 stale。cache_max_bytes=0，两边仍以相同条目预算限制；启动预热文件关闭。C 的逐请求 trace 两边都开启，仅用于影子测量。

先运行候选新选项关闭的短对照，再运行调优短测；验收后重新启动 A/B 从空缓存开始连续 86400 秒。不得在中途重启或清缓存后仍宣称同一次连续测试。共享递归上游会互相预热，A/B 起发顺序交替且保留发送偏差；首次冷查询不宜据此单独宣称提速。

## 工具

- `realflow-capture`：AF_PACKET+BPF，保留原始 flags/EDNS/所有 QTYPE，TCP 重组、内核时间戳、丢包和未覆盖计数；有界输出队列，绝不向生产客户端发送响应。
- `realflow-runner`：同一事件成对派发、有界队列、实际 wire_sent 与调度分开、HMAC 标识、15 分钟状态与私有原始证据；每条 TCP 问题新建连接，因此不保持生产 TCP 连接生命周期。
- `realflow-bounded`：为监督读命令建立独立进程组；超时仅终止该组，不依赖设备缺失的 timeout applet。
- `openwrt-realflow-run.sh`、`openwrt-realflow-lease.sh`、`openwrt-realflow-metrics.lua`：主监督和独立租期，不自动重启，按 PID/starttime/exe 回收本任务；结束后删除本任务 nft 表。
- `openwrt-realflow.init`：私有目录内以唯一名称显式启动的 procd 模板，不设开机启用或 respawn。
- `realflow_report.py`：只读离线汇总，按到达时间重算全天、首小时、稳定阶段和 15 分钟窗口，输出聚合结果。

Go 工具只在 GitHub 编译并执行 race、协议和实际 loopback 捕获冒烟。下载前核验 head/run/attempt、Actions ZIP digest，解包后核验所有 manifest 文件和 Go 源码。C 程序继续使用各自已验证产物，不能用工具构建提交冒充 C 程序提交。

## 业务与资源

HTTPS 端点由私有 sites.json 明确指定，每站每 15 分钟成对访问；首次等 15 分钟。探针将返回 IP 固定连接，保持 Host/SNI、校验证书、绑定 wg_vpn/mark1，不继承代理、不跟随重定向。分别记录 DNS/TCP/TLS/TTFB/限长响应体耗时。它是 HTTP GET，不能宣称浏览器完整渲染。探针域名被标记，主流量分析可排除其缓存预热影响。A/AAAA 与 DNS IPv4 传输、网站 IPv4/IPv6 分开记录；缺地址或请求失败不能自动改换端点隐藏。

资源护栏：每个 C 的虚拟地址空间 128 MiB；Go GOMEMLIMIT=32MiB 为软限制，另监控 RSS。进程低优先级，单进程 RSS 96 MiB、合计 256 MiB；主路由保留 768 MiB 可用内存；目录上限 512 MiB、数据盘剩余至少 256 MiB、conntrack 小于 52428。每 10 秒检查、60 秒保存资源样本。没有启用全局 cgroup 控制器，不能把这些描述为 cgroup 硬配额。任何异常使测试停止并保存原证据；实际阈值与环境必须在最终私有 plan 中冻结。

采集仅覆盖生产 C 入口 IPv4 DNS 传输；IP 分片、未见 SYN 的 TCP 流等单列未覆盖。丢包、队列满、时序缺口、单边发送失败及提前 EOF 都使完整性不通过。错误/超时/漏发与成功延迟并列；缓存命中从 C trace 判断，不按快慢猜测。基线缺少的淘汰等细分标记 unavailable。候选 stderr 无原生时间戳，按带采样时间的累计快照做近似窗口差分；trace 1 MiB 缓冲意味着运行中快照有滞后，最终须正常退出后再汇总。

## 证据与完成

原始目录 0700、文件 0600。保留 app/tool 各自身份、最终配置、规则快照、boot ID、保护摘要、抓包及发送核算、逐请求响应、HTTPS、trace、资源、清理与租期结果。不得只保存平均值，或以无流量无错误作为性能通过。24 小时结束后先停止并验证仅本任务资源回收，再下载归档、核验每文件摘要，最后产生报告；真实故障注入与物理重启另行验收。
