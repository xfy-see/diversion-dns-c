# 尾延迟归因（诊断，默认关闭）

用途：在固定负载下把短时尾延迟拆分到 (a) 压测客户端调度/并发上限、(b) 服务端排队
（入队→worker 取走）、(c) 上游 I/O、(d) nft 写入（fast 与 CLI 路径，区分等待与实际 I/O）、
(e) TTL 过期后的刷新。它不改变任何 DNS/EDNS、缓存、nft 或上游随机化（M4）语义，也不改变
原有负载和通过标准；`load.go` + `suite_metrics.py` 仍是唯一判定依据。

## 开关

服务端：启动时设置 `DIVERSION_TRACE=/path/trace.tsv` 才开启。未设置时打点只是一次线程局部
指针读取（恒为 NULL）或一次全局布尔判断，不取时钟、不写文件。

每行（制表符分隔，首行 `#diversion-trace v1 ...` 为表头）：

`kind lane flags id qtype qname resends attempts recv dispatched enqueue pickup engine0 up_send up_recv nft0 nft_io nft1 engine1 reply`

* `kind`：`Q` 客户端请求；`R` 过期命中触发的后台刷新（无客户端）。
* `lane`：0 cached、1 cn、2 foreign、3 事件循环直接回复。
* 时间：CLOCK_MONOTONIC 纳秒，0 表示未发生。`up_send/up_recv` 包住整个 `md_forward_q`
  （含建 socket/连接、重发与 TC→TCP 回退）；`nft_io` 为 CLI 路径取得串行令牌后、fast 路径成为
  批次 leader 时；fast 路径的非 leader 只有 `nft0/nft1`（全部为等待 leader）。
* `flags` 位见 `c/include/mosdns.h` 中 `MD_TF_*`。 `MD_TF_NFT_SKIP`（1<<14，`nft_skip`）表示该回答因热命中跳过窗口未访问内核。`--plan compare` 在多个构建间轮换顺序比较热/冷/500 QPS/nftset_fast=0，并记录 `DIVERSION_NFT_STATS` 计数与 trace 中的内核 nft I/O、>2ms 次数。
* 每行在回复发出后由 worker（UDP）或事件循环（TCP 写完）写入 1 MiB 缓冲文件；跟随者
  （合并的相同查询）复制主请求的阶段时间并带 follower 标志。

客户端：`benchmarks/suite/diagload.go`（仅在 GitHub Actions 编译，产物在 suite-helpers
artifact 的 `<arch>/diagload`）。工作负载与 `load.go` 相同（名字、ID、类型、cold cookie、
`-unique/-offset`），额外记录每个请求的计划时刻、worker 取走、TCP 建连、发送、接收时刻，
并允许 `-workers` 到 2048 与 `-predial`，用来区分客户端并发上限造成的伪尾延迟。

## 分析

`scripts/tail_attribution.py --client client.json --trace trace.tsv --output out.json`
按 (id, qname, qtype) + 时间窗口一一配对，输出各阶段 P50/P99/P99.9/max（floor((N-1)p)，
与 suite_metrics 一致）、按类别（fresh/stale hit、miss、follower × lane）分组、尾部
（e2e ≥ P99）主导成分统计、100 ms 时间序列与最高尖峰时间片。TCP 另给出排除首次建连样本的
辅助统计（不替代全量统计）。

## 运行

`scripts/tail_attribution_run.py` 只能在新建且自有的 netns 中以 root 运行（与 kernel 档相同，
`DIVERSION_OWNED_NETNS=1`），复刻 `suite_device.py` 的设备配置与五个场景及 500 QPS 稳定性负载，
在回环上使用 CI 产物中的 static 程序与 suite-helpers。绝不连接任何路由器。x86/回环结果不能
代表 MIPS 设备的绝对数值，只用于定位相对瓶颈。
