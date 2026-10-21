# OpenWrt DNS 降级后的自动恢复

这是针对具有匹配布局的主路由 现有定制部署的脚本覆盖层，依赖 `/etc/diversion-dns-c/`、本机 C DNS 的 `15363` 端口，以及现有策略和守护服务。它不是通用 APK 安装器，不更新 C 可执行文件，也不适用于未经核对的其他安装布局。

保留现有 `dns-mode.sh`、`apply-policy.sh`、`enable-rescue.sh`、`refresh-monitor.sh` 和 DDNS 配置。降级仍由已有 `fallback_dns` 切换到 ISP DNS；本改动补充探测、自动回切及中断恢复，不增加境外流量自动绕过隧道走 WAN 的规则。

## 文件与安装位置

| 仓库文件 | 设备安装位置 |
| --- | --- |
| `common.sh` | `/etc/diversion-dns-c/common.sh` |
| `guard.sh` | `/etc/diversion-dns-c/guard.sh` |
| `recover.sh` | `/etc/diversion-dns-c/recover.sh` |
| `rollback.sh` | `/etc/diversion-dns-c/rollback.sh` |
| `dns-probe.lua` | `/etc/diversion-dns-c/dns-probe.lua` |
| `diversion-dns-c.init` | `/etc/init.d/diversion-dns-c` |

需要 OpenWrt 的 `procd`、UCI、`flock`、`nft`、Lua 和 `nixio`。既有守护服务应继续调用上述 `guard.sh`；部署前核对实际路径、配置、端口及依赖。

## 自动恢复条件与流程

只有服务健康检查触发的降级才会写入 `recovery-auto`，内容必须为 `service-health`，并且策略检查正常时才自动尝试恢复。手工降级、来源不明的旧 `degraded` 标记，或其他内容的授权文件，都保持降级，避免覆盖管理员选择。

1. 守护发现符合条件的降级后，先安排至少 120 秒的冷却期。正常轮询间隔为 20 秒，实际开始时间受轮询和探测耗时影响。
2. 保持客户端 DNS 使用 ISP，启动 C DNS，在独立端口 `15363` 验证候选服务。
3. 连续进行三轮国内、境外的 A / AAAA 查询，每轮间隔 10 秒。查询使用 `qq.com` 和 `example.com` 下的随机子域，避免缓存掩盖上游故障；安装的域名规则必须将两者分别归为国内、境外。
4. 三轮都成功后，将 dnsmasq 转发改为 `127.0.0.1#15363`，缓存设为 0，再通过客户端入口 `53` 验证新鲜查询和固定域名正答案。固定域名分别是国内 `www.baidu.com` 和境外 `example.com`。
5. 验证成功才清除降级和事务标记，写入 `recovered`；失败则恢复此前的 DNS 设置。后续重试间隔依次为 60、120、240、480、900 秒，最大 900 秒。持续健康 600 秒后重置失败次数，避免反复切换。

健康探测接受匹配查询的 `NOERROR` 或 `NXDOMAIN`，拒绝 `SERVFAIL`、超时及截断回答。最后的固定域名探测必须取得所请求类型的地址记录，仅有 CNAME 或空回答不算成功。启动就绪检查只确认进程能够响应，不能替代后续上游健康检查。

A / AAAA 均经本机 IPv4 DNS 传输查询。这验证两种记录类型，不证明 IPv6 DNS 传输、IPv6 隧道或真实网页连接可用。域名本身不再提供相应正答案时，会阻止自动回切，需要核对探测目标，不能据此直接判定整个服务故障。

## 中断与回退保护

`/etc/diversion-dns-c/recovering/` 是持久事务目录，保存切换前 dnsmasq 的 `server` 列表和 `cachesize`；`switching` 标记先于配置修改落盘。失败只恢复这两个设置，不导入整份旧 DHCP 配置，避免覆盖其他 DHCP 改动。

恢复脚本、守护和降级脚本共用部署锁。异常退出或重启遗留事务时，init 允许 C 服务启动，守护跳过通常的启动等待，优先恢复原 DNS 配置。若备用 DNS 恢复不完整，则保留事务和 C 进程并记录 `CRITICAL`，下一轮继续修复，避免提前停止仍可能承接查询的 C 服务。

手工降级并禁止自动回切：

```sh
/etc/diversion-dns-c/rollback.sh
```

手工触发一次完整恢复验证：

```sh
/etc/diversion-dns-c/recover.sh
```

不要直接删除 `degraded` 或 `recovering` 来强制恢复，也不要为旧的未知原因降级补写 `service-health` 标记。手工恢复仍需通过相同的探测和最终验证。

## 部署与脚本撤回

先备份上述六个目标的内容、权限和原先是否存在，以及当前 UCI DNS 设置、守护配置、运行标记和文件哈希。保存独立的撤回脚本，并在变更前安排设备端定时撤回；验证成功后再取消。

在设备上暂存新文件，检查 shell 语法、Lua 可加载性和依赖；暂停守护并确认没有正在执行的恢复事务，再逐个同文件系统原子替换。六个文件的替换整体不是单一原子操作，因此必须保持守护暂停，直到全部到位。保留原 C 二进制和既有策略脚本，完成读回哈希校验后再启动守护。

撤回覆盖层时，停止新守护，先用新恢复脚本的 `--reconcile` 处理未完成事务，确认 DNS 可用后恢复原脚本、权限和服务状态；原先不存在的覆盖文件才可删除。事务恢复失败时先处理 DNS 故障，不应强行移除保护。`rollback.sh` 是切换到备用 DNS 的操作，不等于撤回脚本版本。

## 状态与验收

运行时退避状态在 `/var/run/diversion-dns-recovery/state`，字段依次为启动 ID、失败次数、下次尝试的单调时钟秒数、持续健康起点。重启后旧运行时计时不沿用；持久事务仍会被处理。

```sh
cat /var/run/diversion-dns-recovery/state
ls -ld /etc/diversion-dns-c/degraded /etc/diversion-dns-c/recovery-auto \
  /etc/diversion-dns-c/recovering /etc/diversion-dns-c/recovered
logread -e diversion-dns-c
uci -q get 'dhcp.@dnsmasq[0].server'
uci -q get 'dhcp.@dnsmasq[0].cachesize'
```

状态文件不存在不代表故障；应同时检查当前 DNS 配置、真实查询和日志。`recovered` 记录最近一次成功时间，不单独证明当前健康。

验收需覆盖自动降级与恢复、三轮中途失败、最终验证失败、手工降级保持、退避与稳定期重置、锁竞争、切换期间退出或重启、恢复失败保留 C，以及策略、DDNS、正常客户端 DNS 不受影响。脚本测试和真机结果必须分别记录；本说明本身不代表这些测试已经通过。
