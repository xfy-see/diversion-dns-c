# C 实现对测试方案的覆盖

最新第二、三层的分版本进度见[当前测试状态](../optimization/c-profiles-20261009/STATUS.md)。以下主要记录初版第一层入口与边界；后续实际矩阵、30分钟、路由和页面结果各自保留原始证据，未完成项目不由本机通过补称完成。

本轮依据 [测试方案](../docs/testing-plan-131.md) 的三层结构执行。以下区分本地受控功能覆盖、受控基准及真实设备行为；历史 Go/Rust 成绩不计作 C 成绩。

## 第一层：功能回归

2026-10-09，macOS ARM64 的 native 和 ASan/UBSan 构建均通过新补充的 5 组 C 回归与 5 项端到端回归，未出现 sanitizer 诊断。端到端和上游单元测试只使用临时 IPv4 loopback 监听。ASan/UBSan 结果不替代专门的堆泄漏或长时间稳定性检查。

| 方案要求 | 现有入口 | 本轮补充 |
|---|---|---|
| 共享域名数据 | `domain_fixture.py` + `domain_driver.c` | 保留既定 4 项 Unicode/RE2 专项跳过；PCRE2 不冒充完整 RE2 兼容。 |
| DNS ID、Question、标志 | `dns_test.c`、`integration.py` | `plan_regression_test.c` 逐项测试 QR、QTYPE、QCLASS 校验及 reject 的 RD/CD 保留、AD/AA/TC 清除；`plan_integration.py` 对 UDP/TCP 回答检查完整 header 与 Question。 |
| RR owner、class、类型、地址、TTL | `dns_test.c`、`integration.py` | `plan_regression_test.c` 校验压缩 owner、class 和 RDATA；`plan_integration.py` 独立解码 A/AAAA 及 CHAOS class 回答，校验所有字段。 |
| NXDOMAIN/SOA 响应语义 | 原有 NXDOMAIN 只覆盖无 SOA 回答 | 两个新套件检查压缩 SOA owner、MNAME、RNAME、serial/refresh/retry/expire/minimum，以及 UDP 冷查询到 TCP 缓存重播的 ID/标志/Question/TTL 保留。固定 30 秒 NXDOMAIN 保留策略按 C/Go minimal 兼容行为断言。 |
| 响应复制 | 原有缓存主要验证命中、TTL 和 ID | 新 C 测试在插入后修改原包、读取后修改返回包，再读确认缓存数据独立；新端到端测试确认 stale 回答与刷新后的新地址互不改写。 |
| 缓存、lazy、sequence | `cache_domain_test.c`、`engine_test.c`、`integration.py` | 新 C 测试检查 stale TTL=5、保留边界、刷新去重与容量释放；新端到端测试等待真实后台刷新并确认地址和 TTL 更新。sequence 仍复用原有 jump/goto/return/AND/negation/递归回归。 |
| UDP 截断转 TCP | `dns_test.c`、`integration.py` | 原有实际 UDP TC 回退、部分 TCP frame、EDNS 大小限制、连续 TCP frame 与 pipeline 用例继续执行。 |
| 资源关闭、超时 | 原有 active query 不受 idle timeout 中断 | 新 C 测试验证 5 秒黑洞上游超时后 fd 数量恢复，竞速获胜后关闭仍在等待的 TCP 交换；新端到端测试验证 TCP idle/未完成 body 关闭、停服释放两种监听，SIGTERM 等待正在执行的 lazy refresh 后再销毁 engine/cache。 |
| 配置和支持边界 | `engine_test.c`、`integration.py` | 继续验证 check 不创建 listener、不加载 domain 文件，以及显式拒绝不支持的插件/传输/API/持久化参数。 |

执行整个第一层：

```sh
make -C c -j4 test
make -C c -j4 test BUILD=../.build/c-asan SANITIZE=1
```

单独运行补充项：

```sh
make -C c ../.build/c-native/tests/plan_regression_test
./.build/c-native/tests/plan_regression_test
python3 c/tests/plan_integration.py .build/c-native/mosdns-c
```

## 目标设备的第一层入口

`plan_regression_test.c` 不依赖 Python、互联网或生产配置，只需对应目标的 C/PCRE2/libyaml 构建产物与 loopback socket；可在 131 的独立临时目录直接运行测试二进制。超时用例约需 5 秒，竞速用例使用临时 UDP/TCP 端口，不创建 nft 表/集合、不设置 mark、不改变 resolver 或接口。`plan_integration.py` 需要 Python 3 和已链接的 C 主程序，亦只使用临时端口与临时配置。

目标设备测试须记录架构、固件/内核、boot ID、构建参数和产物 SHA256，不能用本机通过或 Linux 编译结果替代目标运行结果。nftset、SO_MARK、SO_BINDTODEVICE 的实际行为应由隔离 Linux 内核用例及真实分流记录单独覆盖。

## 第二、三层及保护恢复

本文件的新回归只对应第一层，尚不能证明以下项目完成：

- 同份 111,361 行 CN-site、相同查询内容/固定查询次数、受控 LAN 上游，以及 cache1024/lazyTTL0 下的成对性能矩阵。
- QPS、P50/P95/P99、CPU、RSS/HWM、cgroup 内存峰值/事件、固定到达率及长期稳定性。
- 131 实际 DNS 上游、SO_MARK/接口绑定与出口、真实 A/AAAA 缓存重播写回集合、元素自然过期。
- QQ/淘宝复杂页面及 16 并发重播，学习集合独立直连分支，公网 IPv6 页面传输。
- 设备保护状态与精确恢复。真实设备测试必须检查 boot ID、kernel/OOM、resolver/listener/config、路由/nft/WireGuard/cgroup，并保存失败原始记录。

本轮第二、三层的实际进度及证据由总体测试报告记录；不能从上述本地通过推断它们已完成。
