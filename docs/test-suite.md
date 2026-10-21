# C 分流程序自动化测试集

这份文档定义测试范围、自动化入口和验收标准；它不是某个版本的通过报告。机器可读目录位于 [`tests/scenarios/catalog.json`](../tests/scenarios/catalog.json)。目录中的 `automated` 表示存在执行实现，实际通过与否必须查看本次输出；`planned` 和 `manual` 始终明确列为未覆盖。

## 入口与执行层次

运行环境要求 **Python 3.12 或更新版本**（安全归档提取及现有验证器依赖）。统一入口为 `python3 scripts/testsuite.py`，提供 `list`、`plan`、`run` 和 `summarize`。先查看 `--help` 及相应子命令的 `--help`，再生成计划；计划不等于执行。设备入口另有 `scripts/suite_device.py`，公网协议探测由 `scripts/suite_network.py` 执行。所有结果应使用新目录，保留旧轮次和失败数据。

| Profile | 目的 | 依赖与边界 |
| --- | --- | --- |
| `portable` | 单元、域名、配置、协议、缓存、服务和 nft 模拟契约 | 同架构、校验通过的 CI bundle；复用 `scripts/validate.py` |
| `kernel` | nft 真实内核、并发和故障回归 | Linux root、新建自有 netns；不能在主路由根命名空间直接运行 |
| `network` | 真实 DNS、HTTP(S)、WebSocket | 配置明确端点、地址族、预期结果；不自动选取公网服务 |
| `device-smoke` | 检查设备隔离执行链路 | 明确两台设备与已验证二进制；低负载短场景 |
| `device-performance` | 五种冷热/UDP/TCP 场景 | 受控 LAN 上游和独立端口；与公网响应速度分开 |
| `ablation` | 多版本正序、倒序比较 | 默认正序 3 轮、倒序 3 轮；相同参数、每轮原始样本 |
| `stability` | 持续网络连接或 DNS 分段观测 | DNS 服务进程不重启，客户端负载分片存在观测间隔 |
| `release` | 汇总交付覆盖范围 | 可执行项之外仍包含人工验收项；未覆盖不能算全通过 |

同一个 portable bundle 只运行一次完整 `validate.py`，目录中的多个功能条目是这次执行的覆盖映射，不应为每一条重复执行整个 suite。内核条目同理可按两个现有内核程序分组。只有实际执行记录能把相应条目标为通过。

## 产物与执行前提

C 构建继续在 GitHub Actions 完成，本机不调用 C 编译器、Make 构建或 Zig，也不安装 C 编译环境。执行前保存以下身份链：

1. 仓库、完整 commit、workflow run ID/attempt、job 状态和下载归档摘要。
2. 产物 manifest、源树身份、每个载荷的 SHA256，以及对应 APK 与 ELF 的一致性。
3. 目标架构、ABI、动态加载器和运行库兼容性；设备 ELF 不能因为文件名包含 `mipsel` 就认定正确。
4. 执行前后的二进制摘要、版本号、主机/内核/boot ID 与配置摘要。

`artifacts.py` 负责 bundle 内容校验；设备 adapter 使用显式固定摘要和验证回执。离线摘要校验不能独立认证 GitHub job 已成功，下载步骤的 run/attempt 和原始验证证据必须一并保存。APK 首装、升级和卸载属于另外的部署验收；性能测试只解包/暂存到隔离目录，不能把临时执行称为已完成 APK 安装验证。

A2/A3 等故意回退功能的实验版本需要单独标注预期失败和授权范围。测试失败不能在汇总时删掉，也不能把“实验包可运行”写成“可发布”。

## 功能、协议和故障覆盖

| 领域 | 自动化覆盖 | 证据来源 |
| --- | --- | --- |
| DNS 报文 | A/AAAA、ID/question、边界/长度/压缩指针、畸形报文、EDNS、UDP 截断与 TCP fallback | `dns_test`、fixed integration |
| 配置/分流 | full/domain/keyword/regexp、大小写、CN-site/默认境外、跨组 CNAME、非法配置、check 无绑定/写集副作用 | config/engine/domain fixtures |
| 缓存 | 冷/热、A/AAAA 隔离、负缓存、标志位、TTL 老化、过期刷新、禁用缓存 | cache tests、fixed integration |
| TCP | 半包、pipeline、重复连接、TCP 上游、并行客户端、活动查询不受空闲超时误伤 | fixed integration |
| 异常上游 | 静默、错误 ID/question、仅错误回答、传输失败后合法请求 | fixed integration |
| nft 模拟契约 | 名称/注入拒绝、元数据、超时/失败、普通/interval/fast、无地址回答、调用次数 | `nft_cli_contract.json`、netlink driver |
| nft 真实内核 | 永久元素、续期不缩短、TTL 限制、重启/flush/recreate、双族隔离、256 条上限、批量并发、外部写者 | `nft_kernel_test.py` |
| 队列/连接防护 | H1 队列隔离、H3 并发写入、M3 小栈、R1 过期/合并、R2 慢读、M5 限额、interval 重叠、上游伪造 | `nft_kernel_cli_test.py` 的八组场景 |
| 内存与未定义行为 | 下载的 native/static 和 ASan/UBSan profiles 分别执行 | `validate.py` 每条命令日志 |

真实内核入口要求 `DIVERSION_OWNED_NETNS=1`，并验证初始 nft 表为空。这个环境标志本身并不创建隔离，调用者必须先创建自有 namespace。不能在正式根 namespace 设置标志后直接运行。小栈场景在普通 glibc 程序通过，不代表已验证 musl；必须有相应已构建产物和独立结果。

上游 ID/端口观测只能证明受控样本中行为发生变化；它不是随机数熵的完整安全审计。IPv6 每 IP 限额按完整地址实现，现有单 IP 场景不代表已覆盖同一 `/64` 内分布式慢连接。

## 五种设备性能场景

| 场景 ID | 目标负载 | 查询与缓存 | 每轮准备 |
| --- | --- | --- | --- |
| `cold-udp-a` | 500 QPS × 5 秒 | UDP、唯一域名、A、冷缓存 | 新测试进程；清空自有 IPv4/IPv6 set |
| `cold-udp-aaaa` | 500 QPS × 5 秒 | UDP、唯一域名、AAAA、冷缓存 | 同上 |
| `cold-tcp-mixed` | 100 QPS × 5 秒 | TCP、唯一域名、A/AAAA 各半、冷缓存 | 同上；不预热测量名字 |
| `hot-tcp-mixed` | 100 QPS × 5 秒 | TCP、A/AAAA 各半、已预热 | 同上；预热后再计时 |
| `hot-udp-mixed` | 2000 QPS × 45 秒 | UDP、A/AAAA 各半、已预热、TTL=30 秒 | 同上；跨越一次 TTL 到期刷新 |

这是对旧四场景消融的补充：增加真正的冷 TCP，把原先预热的 TCP 场景明确命名为热 TCP。冷 TCP 客户端本身是否使用持久连接和上游采用 UDP/TCP，必须在配置/报告中分别记录，不能只写“TCP”。

`device-smoke` 使用低负载短场景（默认每项 20 QPS、1 秒），只判断执行链路与基本行为。该 profile 不能证明 45 秒 TTL 刷新或目标吞吐通过。性能参数是场景定义而非跨设备统一硬门限；需要改变时在配置中显式设置，并保留最终生效配置。

受控上游应返回可计算的唯一 A/AAAA 地址；冷查询后检查实际地址成员，不只看元素总数。当前五场景固定为 **CN-site + nftset_fast=1** 的主要路径基准，不能推广成所有规则组合。目录另外保留四个 `planned` 性能维度：纯境外不写集对照、普通/interval set 与 fast 开关矩阵、冷热比例/缓存关闭/超容量工作集、阶梯加压和降载恢复。已有功能测试覆盖部分配置，不等于设备性能矩阵已经执行。

## 严格 QPS 与尾延迟判定

每场景都要输出 `planned`、`sent`、`succeeded`、`failed`、`unsent` 及原因。**严格到达率通过要求 `planned == sent == succeeded`、`failed == 0`、`unsent == 0`，且发送时隙符合设定的迟到容忍值。** 客户端忙导致 `inflight_limit` 和调度迟到导致 `scheduler_late` 都属于目标负载未实现，不因服务端收到的请求全部成功而算通过。

功能与压力指标分开：可以同时得到“已发送请求全部回答正确”和“严格 2000 QPS 未通过”。吞吐以实际成功数除以测量时间计算；不能把目标 QPS 当成实际吞吐。

P50/P99/max 基于成功回答的延迟，必须同时展示超时、错误和漏发数量，避免只统计成功者掩盖问题。当前统计使用历史设备工具的 `floor((N-1)*p)` 排序取样算法；报告同时写明样本数与计时范围。各版本同场景取 **六次单轮 P99 的中位数**，不是把六轮全部请求混合后算一个 P99；附正序/倒序结果和每轮最大值，保留原始逐请求样本。

TCP 主统计包含初次建连；额外排除前 0.5 秒只能作为诊断视图，不能覆盖主值。热 UDP 分别输出整个 45 秒、前 10 秒、末 10 秒，以确认 TTL 刷新后没有热路径回退。漏发时切片要基于计划时隙，而非简单用成功样本数组序号代替时间。

版本/设备之间相比较，保持 CPU/worker 数、构建 profile、正则后端、缓存容量、规则、nft 模式、fixture、客户端并发和连接复用方式一致。绝对门限与相对基线门限应显式配置；没有预注册门限的历史对比是测量结论，不能事后选一个有利阈值写成通过。

## 真实请求与双栈覆盖

DNS 类型与 IP 传输族是两个独立维度：

| 维度 | 取值 |
| --- | --- |
| DNS QTYPE | A / AAAA |
| DNS 客户端传输 | UDP / TCP |
| DNS 服务器连接族 | IPv4 / IPv6 |
| 应用目的区域 | CN / 境外 |
| 应用连接族 | IPv4 / IPv6 |
| 应用协议 | HTTP(S) / WebSocket |

“用 IPv4 DNS 服务器查到 AAAA”只证明 AAAA 解析，不能证明 IPv6 DNS 传输或 IPv6 网站访问。每个请求保存实际连接地址、地址族、协议、状态、耗时和预期断言。

端点完全来自显式配置。HTTP 不继承本机代理作为路由证据；如果应用层成功而不记录设备路由/mark/出口，结果只叫请求可用。HTTP/WS 使用 DNS 回答中第一个符合指定地址族的地址，不能证明所有返回地址可用；HTTP 不自动跟随重定向，并只读取配置上限内的响应体前缀，`body_complete` 明确是否已经读取完整响应。HTTP GET 不等于真实浏览器完整渲染。WebSocket 需要完成握手并持续保活/交互，记录断开、超时、样本和持续时长，不能只以一次 101 响应宣称稳定。

用户此前提供的 `ws://192.0.2.60:8800`（文档占位，执行前替换为本地授权端点） 只有 IPv4 字面地址，不能据此构造国内 IPv6 覆盖。没有支持 IPv6 的国内端点时，国内 IPv6 项必须显示未覆盖。公共服务限速、下线或业务变化属于真实失败证据，需要与 DNS/路由故障区分，不擅自轮换另一个端点来隐藏失败。

## 持续测试与资源安全

当前设备自动化的稳定性模式保持同一个 C 服务进程，默认累计运行 30 段 × 60 秒负载，分片间不重启 C 服务、不清空 set，并采集资源快照。客户端每片重新启动，因此分片间有观测间隔，**不能称连续无间断的 1800 秒固定到达率或同一 TCP 连接稳定性测试**。报告必须保存服务进程身份、各片实际时间和间隔；逐片失败不能用平均值掩盖。无分片间隔的 1800 秒 DNS 到达率测试仍标为 `planned`；WebSocket 同一连接持续测试按网络配置单独执行。

设备测试使用独立高端口、自有临时目录、随机标识 nft table 和受限 cgroup。先记录生产程序/配置哈希和 boot ID，配置两端内存/conntrack 安全阈值及固定租期 watchdog。连接中断时只回收本次拥有的资源；异常结束保存证据后执行清理并验证生产完整性。遇到异常重启、生产哈希改变、OOM 或安全阈值中止，停止压力，不能自动重跑掩盖异常。

不清空系统 conntrack，不安装实验 APK，不接管正式 53 端口，不更改主路由或 VPN 策略。获取不到的指标标记 `unavailable`，不能以零代替。CPU/FD/内存等指标只声明采集器确实输出的部分；完整同进程泄漏诊断需要额外实现。

conntrack 保存测量前后的全局计数和采样时间。全局净变化会受其他连接和自然超时影响；`/proc/net/nf_conntrack` 枚举差集会有重复或重新可见的旧元组，不能称精确新建 socket 数，也不能直接拆分 socket 系统调用与连接跟踪的耗时。需要分离这两种成本时，应另做受控追踪/NOTRACK 实验。

## 结果与未覆盖项

结果至少保留：最终配置/计划、版本与产物身份、每条命令及日志、原始请求样本、每轮统计、nft JSON、资源前后状态、功能/严格负载两个判断、异常与清理结果。不要覆盖旧报告或只保存最终平均值。自动化退出失败与覆盖不全是不同状态；报告应同时说明哪项失败、哪项未运行及原因。

下列项目在目录中保留明确的人工/后续入口，默认自动化不修改正式设备来完成它们：

- CN-site/CN-IP 四种组合的实际 mark/路由/出口，包括 LAN、路由器自身和外部 WireGuard VPN 三种来源。
- APK 首装/升级/卸载、配置保留、正式 DNS 接管、备份和回退。
- 隧道故障、DNS 降级、PPPoE 重拨、DDNS 与恢复机制的业务演练。
- 重启后的持久化、真实浏览器页面渲染、IPv6 `/64` 分布式连接限制。
- 随机性安全审计、设备系统调用追踪和受控 NOTRACK 性能拆分。

目录里有这些场景，不代表已经执行过它们。发布结论必须附具体 commit、run、设备和日期；历史 `测试机 A` 六版本数据只能作为历史基线，不能冒充本次版本的验证。

## 统一入口示例

```sh
python3 scripts/testsuite.py list --profile release
python3 scripts/testsuite.py plan --profile ablation --output /absolute/path/ablation-plan.json
python3 scripts/testsuite.py run --profile portable --config /absolute/path/portable.json --output /absolute/path/new-portable-run
python3 scripts/testsuite.py run --profile ablation --config /absolute/path/device.json --output /absolute/path/new-ablation-plan
python3 scripts/testsuite.py run --profile ablation --config /absolute/path/device.json --output /absolute/path/new-ablation-run --execute-device
python3 scripts/testsuite.py summarize --input /absolute/path/run-one --input /absolute/path/run-two --output /absolute/path/new-summary
```

`portable.json` 的 `artifact` 对象需提供 `bundle`、`checkout`、`expected_commit`、`expected_run_id`、`expected_run_attempt`、`expected_archive_sha256`，以及下载时保存的 `workflow` 和 `jobs` 元数据。`jobs` 必须包含四种所需 native/static 目标的成功 job、唯一 job ID，并匹配相同 run ID/attempt；workflow 也必须是同一提交、同一次运行且成功。不得用占位 SHA 或把当前源码目录当成历史产物对应 checkout。设备配置模板与脚本参数以仓库中对应示例及 `--help` 为准。

`release` 汇总要求各报告的 profile 与对应标签一致，同一份报告不能重复充当多个要求；设备报告必须匹配 `release.expected_devices` 中明确的目标地址。人工/计划项仍显示 `skip`，不会因为自动报告齐备而变成自动通过。

统一入口保存 `plan.json`、生效 `config.json`、`result.json`、`REPORT.md` 和 `evidence.json`；后者固定本次证据文件摘要。`summarize` 先检查已有报告摘要，拒绝被改过的结果。执行状态与退出码区分通过、失败、未执行/覆盖不全，不能用只生成计划的退出状态当成设备通过。

## 显式网络配置示例

下面使用本地 fixture 地址，示范结构，不会代填国内/境外公网端点。实际 URL 需要由运行者明确提供。`family` 是 DNS 服务器连接族，HTTP/WebSocket 的 `answer_family` 是目标应用连接族；它们可以不同。

```json
{
  "network": {
    "dns": [{
      "id": "dns-udp4-aaaa",
      "server": "127.0.0.1", "port": 15491,
      "transport": "udp", "family": 4,
      "name": "fixture.test", "qtype": "AAAA",
      "expected_rcode": 0, "require_address": true
    }],
    "http": [{
      "id": "http-fixture-ipv4",
      "url": "http://fixture.test:18080/",
      "dns_server": "127.0.0.1", "dns_port": 15491,
      "dns_transport": "udp", "dns_family": 4,
      "answer_family": 4, "expected_status": [200]
    }],
    "websocket": [{
      "id": "ws-fixture-ipv4",
      "url": "ws://fixture.test:18081/",
      "dns_server": "127.0.0.1", "dns_port": 15491,
      "dns_transport": "udp", "dns_family": 4,
      "answer_family": 4, "duration": 1800,
      "ping_interval": 10, "timeout": 5
    }]
  }
}
```

```sh
python3 scripts/suite_network.py --config /absolute/path/network.json --output /absolute/path/new-network-result.json
python3 scripts/suite_device.py --config /absolute/path/device.json --output /absolute/path/new-device-result --profile ablation
```

第二条设备命令默认只检查计划，不发 SSH；执行设备测试需在审阅配置后明确加 `--execute`。网络入口读取显式端点后会发送请求，不能当作 dry-run。网络结果有真实失败时退出 1；必需端点缺失/跳过导致覆盖不全时退出 2；所有已要求的项实际通过时退出 0。HTTP 保留 Host/SNI 并校验证书、不继承环境代理、不自动跟随重定向。
