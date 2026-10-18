# 持续运行统计

固定分流程序支持可选运行统计，不需要抓取或回放一天流量。默认关闭，不新增网络监听端口。它适合长期运行观察和故障定位；不能代替版本间同流量因果对照、客户端收包或网站访问验收。

配置：

```ini
stats_file=/tmp/diversion-dns-stats.json
stats_interval=60
```

`stats_interval` 范围 5–3600 秒，默认 60。启动、每个间隔和正常退出时原子替换一次 JSON；只保存当前累计和最近 60 个实际区间，不追加无限日志。默认约一小时趋势；有调度延迟时以每段真实 duration 为准。建议 `/tmp`，避免持续写路由器闪存。没有跨进程累加或自动恢复，重启以 pid/started_unix/uptime 开启新统计周期；异常退出最多丢失一个导出区间，final=false，读取时应核对时间新鲜度。stats 文件含访问域名，权限0600，不记录客户端IP或原始请求。

查看/导出（安装的程序名可能为 diversion-dns-c-lite）：

```sh
diversion-dns-c-lite stats
diversion-dns-c-lite stats --file /tmp/diversion-dns-stats.json
```

输出 JSON，`jq '.total' /tmp/diversion-dns-stats.json` 查看总览；`jq '.top50' ...` 查看排行。读取命令不加载配置、不打开DNS监听、不清零统计。若需长期留存，可外部定时复制快照；不要直接累计多份重叠的 total。

## 口径

- `received_valid = total.completed + inflight`：完整且通过结构校验的前台查询。畸形UDP、TCP不完整/超时等在events单列，不假装它们是有效域名请求。尚未进入程序的内核丢包无法计数。
- `success_rate = success / completed`：已向本机网络栈完整提交 NOERROR 或 NXDOMAIN，且本地处理无错误。NXDOMAIN单列；NOERROR包括空答案和TC截断响应。不是“域名存在率”或客户端收到率。响应RCODE计数独立，其他RCODE不算成功。无样本比率为null。
- `cache_hit_rate = (fresh + stale) / completed`；缓存来源按最终执行路径统计，可能与dispatch时的cache_engine计数有细小差异（排队期间过期/另一个请求填充）。关闭缓存或未进入缓存路径归disabled_or_unchecked。后台刷新、固定预热不计入前台成功率/RT/Top。
- `rt` 从完整请求解析完成到完整回复提交内核，失败则到放弃/结算；包括排队、执行及TCP写等待，不含客户端链路、TCP握手/读帧时间。`queue` 为收取完整请求到worker取出的时间（含dispatch），`service` 为worker处理/立即回复路径耗时；跟随查询统计等待共享响应的执行部分。RT样本包括失败，避免只展示成功请求。
- 平均值和最大值直接累计；P50/P90/P95/P99是固定直方图的**桶上界估计**，不能按精确分位数解读。超过最大32秒桶的分位数为null，尾桶计数和实际max保留。histogram_upper_ms公开全部桶界，histogram为非累计桶。
- breakdown 按CN/foreign × A/AAAA/other × UDP/TCP给出相同指标。recent_intervals是最近60段全局指标，累计分组值位于breakdown。qps_lifetime按收到的有效请求/运行秒数，区间completed_qps按完成数/真实段长。
- errors 为请求的主要终态原因：队列满/过期、上游失败/总超时、nft失败、执行期限、响应校验、内存、发送失败、客户端断开、停机。上游内部丢弃的坏包/单次竞争失败不逐包统计，总失败会计数；程序生成的SERVFAIL与上游RCODE可结合errors判断。多个错误同时发生时终端发送/断开原因优先。
- events 为连接/无有效请求级事件，可能与请求错误重叠，不能与completed相加。正常空闲TCP关闭不是读超时；收到部分帧后触发期限才计读超时。
- cache_engine包括CN/foreign缓存占用、miss原因、refresh/prefetch/重启warm/固定keep计数；这些子系统计数与前台快照不是同一锁下的事务快照。nft汇总写入/跳过/事务。process提供CPU累计时间和峰值RSS，不冒充当前RSS。

## Top 50 与开销

按已完成的有效前台请求域名（小写、合并所有QTYPE/传输）排行，错误请求也在内，后台预热不在内。使用1024候选的Space-Saving最小堆和哈希表，正常更新无需扫描全表。未发生替换时exact=true；超过容量后exact=false，输出count_estimate/count_lower_bound/error_bound，排行可能近似。不是无误差的全域名精确排行榜。

内存有固定上限：1024域名、60区间和12分组直方图；不保存逐请求日志。每次有效请求增加时钟和短互斥锁开销，开启时需实测设备性能。写盘/排序在专用线程完成，不在DNS线程做文件I/O。失败导出计入export_failures并打日志，DNS仍继续。已有输出必须是本用户的普通stats文件；拒绝软链接及任意其他文件；同一路径仅允许一个进程写入。

移除stats_file和stats_interval并重启即可关闭；回退旧程序前也先移除这两项。不删除历史统计文件，它会保留旧的pid/时间/final状态。
