# diversion-dns-c

独立的 C11/POSIX DNS 分流程序，从 mosdns C r12 导入后专用于 CN-site 场景。源码仍在 `c/`；运行时已去掉 YAML、插件图和 sequence，改用有界 `key=value` 配置与固定请求链。

原始问题名匹配 CN 规则后，走共享缓存及唯一 CN/foreign 上游组；CN 回答包含缓存命中都经过原有 nft 最终处理。保留数字 UDP/TCP 上游、TCP 持久连接、TTL/LRU/lazy 缓存、Linux mark/接口绑定和 domain/full/keyword/regexp。没有跨组 fallback、热重载、服务安装或系统 DNS 接管。GPL-3.0-or-later。运行时不依赖 YAML；历史 YAML 配置仅作迁移输入与证据保留。

## v0.1.3

[下载 v0.1.3](https://github.com/xfy-see/diversion-dns-c/releases/tag/v0.1.3) · [发布说明与升级注意](docs/release-v0.1.3.md)

v0.1.3 增加现有 OpenWrt 定制部署的 DNS 降级自动恢复覆盖层：备用 DNS 保持服务，候选 C 连续三轮通过国内/境外 A/AAAA 验证才回切；恢复失败退避重试，手动降级保持不动。覆盖层单独提供 `openwrt-recovery-v0.1.3.tar.gz`，适用布局与依赖见 [部署说明](deployment/openwrt-recovery/README.md)。源码清理还移除了未使用的 vendored libyaml。

双架构 `0.1.3-r1` APK 仍只包含程序，不会自动安装覆盖层或接管 DNS。C 请求处理行为与 v0.1.2 一致；这次没有新的性能提升声明。正式发布以 Release 已公开且校验信息齐备为准。

## v0.1.2（历史版本）

[下载 v0.1.2](https://github.com/xfy-see/diversion-dns-c/releases/tag/v0.1.2) · [发布说明与升级注意](docs/release-v0.1.2.md)

v0.1.2 包含上游 UDP 随机 ID/源端口、DNS 解析复用、nft 并发回读与批处理、热命中跳过窗口及首次 TCP 停顿优化。`udp_sport_reuse` 默认关闭，`nftset_hit_window_ms` 默认 1000。功能实测与性能指标分别报告：冷查询 P99 尚无稳定提升结论，严格速率存在未通过轮次，详见发布说明。

双架构 `0.1.2-r1` APK 仍未签名，只包含程序，不自动配置服务或接管 DNS。正式发布以对应 Release 已公开且校验信息齐备为准；本源码分支本身不证明已经发布。

上一正式版本：[v0.1.1](https://github.com/xfy-see/diversion-dns-c/releases/tag/v0.1.1) · [历史发布说明](docs/release-v0.1.1.md)。

## v0.1.0（上一版本）

[下载 v0.1.0](https://github.com/xfy-see/diversion-dns-c/releases/tag/v0.1.0) · [发布说明与迁移边界](docs/release-v0.1.0.md)

包含 `aarch64_cortex-a53` / `mipsel_24kc` 两个架构的 `0.1.0-r1` 动态 POSIX-lite APK，以及 PCRE2/lite 验证包、SHA256、buildinfo 与源码。APK 仍是实验性未签名包，无 init、配置、LuCI 或自启动。相对历史测试包 `0.2.0-r1`，包管理器将本次视为降版本；先备份配置与规则，不要强制覆盖用户配置。本次新版本未做用户实机验收。

## 配置与运行

从精确提交的 CI 下载并验证产物后，在仓库根目录运行：

```sh
/path/to/mosdns-c check -c c/examples/minimal.conf
/path/to/mosdns-c start -c c/examples/minimal.conf --cpu 4
```

默认读取 [config.conf](config.conf)。`check` 现在会加载全部 CN 规则文件并编译 regexp，不打开 listener、不查询上游、不写 nft；规则文件缺失也会失败。相对路径基于进程工作目录或 `-d` 指定目录。

- [完整配置与迁移契约](docs/fixed-splitter.md)：全部键、限制、固定路由、缓存/nft 语义及部署前检查
- [历史集成优化与验收记录](https://github.com/xfy-see/diversion-dns-c/blob/d9c4645109e97395d766a5c4a81223b39caf6249/docs/integrated-validation-20261010.md)：可选 POSIX-lite、`-Os`/LTO、OpenWrt 动态包及各自测试边界
- [C 运行与验证说明](c/README.md)：依赖、服务限制、CI 和历史验证边界
- [历史本地验证](https://github.com/xfy-see/diversion-dns-c/blob/d9c4645109e97395d766a5c4a81223b39caf6249/docs/specialized-validation-20261009.md) 与 [历史同机体积对照](https://github.com/xfy-see/diversion-dns-c/blob/d9c4645109e97395d766a5c4a81223b39caf6249/docs/specialized-size.md)：通过项、限制和复现依据
- [构建依赖边界](docs/build-dependencies.md)与[历史专用实现体积证据](https://github.com/xfy-see/diversion-dns-c/blob/d9c4645109e97395d766a5c4a81223b39caf6249/docs/specialized-size.md)：移除的运行时依赖及本次测量范围
- [最小配置](c/examples/minimal.conf) 与 [Linux site-only 配置](c/examples/site-only.conf)
- [离线迁移工具](scripts/migrate-site-config.py)：仅接受经完整校验的历史 site-only 等价图，拒绝未知/重复字段和其他控制流；可选 PyYAML 不进入运行时

```sh
python3 scripts/migrate-site-config.py docs/go-profiles-site-only.yaml -o /tmp/site-only.conf
```

旧 YAML、graph 测试及性能资产仍保留为历史证据，不是当前运行配置或新测量。迁移后仍需 `check` 和真实 Linux 环境验收。

## 后续修改与编译

本地修改、提交、push 后，由 [GitHub Actions](../../actions) 自动编译和执行回归，生成：

| 产物 | 内容 |
|---|---|
| macOS 27 ARM64 native | Xcode 27 runner 构建，native 和 ASan/UBSan 测试程序及匹配的 sanitizer runtime |
| Linux x86_64 native | Linux native/ASan/UBSan 程序和测试程序 |
| Linux ARM64 static | 固定 Zig 0.14.1、PCRE2 10.48，静态 musl 程序和全部测试程序 |
| Linux x86_64 static | 同样固定依赖的静态 musl 程序和全部测试程序 |

同一工作流还显式构建并验证 POSIX-lite：native/sanitizer 覆盖 macOS ARM64 和 Linux x86_64，静态 musl 覆盖 Linux ARM64/x86_64。它们分别保存在 `experimental-lite-*` Actions 产物中，并在 manifest 内记录 backend；默认产物仍为 PCRE2，lite 不进入原有 CI 预发布；正式版本（v0.1.0 至 v0.1.3）另行收录经过同源验证的 lite 包。OpenWrt APK 另走 [SDK 实验流程](packaging/openwrt/README.md)。

每个正式版本由各自的一次性发布 job（`release-010`、`release-011`、`release-012`、`release-013`）发布，只在 `VERSION` 与该版本一致时运行；它还等待双 APK job，并独立验证下载内容；已有 tag/release 一律不覆盖。v0.1.3 还显式核验同一 main 提交的 kernel、delivery 及独立测试套件，并提供带源码摘要清单的自动恢复覆盖包。

main 分支的四个编译/测试 job 成功后，delivery job 会生成 `ci-<commit>-run<id>-attempt<n>` 预发布版本。四个同源 `.tar.gz` 下载包与 `SHA256SUMS` 可以直接从 GitHub Releases 下载，无需 Actions 登录；它们保留 Actions 包内同一份文件。

每包绑定 commit、run ID/attempt、完整 Git 源码树及逐文件 SHA256。独立保留 CI 测试日志。默认本地工作流不调用 C 编译器，只有用户明确授权时例外；常规本机测试直接运行下载的程序。

Linux static 包还在 `builds/static/size/` 保存 `mosdns-c.unstripped`、`mosdns-c.map`、`mosdns-c.mapped` 和 `attribution.json`。正常发布的 `builds/static/mosdns-c` 仍按原参数剥离；CI 用同一条 LLD 链接命令额外生成 map，并要求带 map 的已剥离文件与发布文件 SHA256 完全相同。应用、固定 PCRE2 依赖和测试使用 `-Os -flto`，仍保留静态 musl、原 stack 与 unwind 策略。JSON 按真正保留下来的输入节区计数：LTO 合并的项目、PCRE2 及 runtime 输入列为 `mixed_lto`，不硬拆为各自字节；依赖配置、精确链接输入和诊断 ELF 符号另行验证。未合并输入及历史非 LTO 产物继续按项目代码、PCRE2 和 musl/启动/编译器支持归类。当前产物不编译或链接 libyaml（源树已移除该 vendored 依赖）；历史产物归因仍保留 libyaml 分类，并单列合并常量、链接器生成内容及对齐/文件元数据；`bss_bytes` 是内存节区，不计入磁盘文件。未剥离 ELF 另供符号检查，不能假定其代码字节与使用 `-s` 的发布链接完全相同。

## 下载后的完整本地校验

先确认精确提交对应的四个 CI job 全部成功，从对应 CI 预发布版本下载同次 run/attempt 的 `.tar.gz`（用 release asset 的 digest/`SHA256SUMS` 校验），或通过 GitHub 插件/CLI 下载 Actions ZIP。以 macOS ARM64 包为例：

```sh
commit=$(git rev-parse HEAD)
run_id=实际运行ID
python3 scripts/artifacts.py extract \
  --archive /path/to/native-macos-arm64.tar.gz \
  --expected-commit "$commit" --expected-run-id "$run_id" \
  --archive-sha256 对应下载文件的SHA256 \
  --checkout . --output ".artifacts/$commit-macos-arm64"
python3 scripts/validate.py \
  --bundle ".artifacts/$commit-macos-arm64" --checkout . \
  --output "validation/$commit-macos-arm64"
```

验证器拒绝提交不符、文件哈希不符、非预期平台、重复条目、目录穿越和链接。目录必须新建，失败记录不得覆盖。当前校验范围是每 profile 五个 C suite（含固定配置/引擎测试）、domain fixture 70 断言（4 个 Unicode/RE2 专项明确跳过）、固定分流服务回归、18 个 nft CLI 语法/回执/失败路径检查和 CLI smoke。验证器按 bundle suite 标识选择新旧测试，历史产物仍使用其原有 graph/plan 测试。macOS 包会分别运行 native 与 ASan/UBSan，Darwin 不启用 LSAN。

Linux ARM64 包用于目标设备的独立校验。CI/mock 回归不会改生产配置，也不证明真实 NFT 内核写入、实际出口、QPS 或 30 分钟稳定性；这些要按变更范围另做设备测试。

## 已导入的性能基线

历史 r12 在 ARM64、两 worker/2 CPU 配额/32 MiB、受控 LAN UDP 上游、完整 CN-site、cache1024/lazyTTL0 下的冷缓存六轮中位数：

| 前端/并发 | QPS | P99 ms |
|---|---:|---:|
| UDP/1 | 779 | 3.456 |
| UDP/4 | 2496 | 3.891 |
| TCP/1 | 685 | 3.755 |
| TCP/4 | 2492 | 3.942 |

这是迁移前独立测量的记录，不是 GitHub 新构建产物的成绩。原始证据保留在原本地工作区，不能用初版或 CI 的编译成功代替实机结果。

详细协作规则见 [AGENTS.md](AGENTS.md)。旧仓库的编译缓存清理记录和首轮 CI 下载验证结果另保留在本地 `migration/` 与 `validation/` 证据目录。

## Linux TCP 启动延迟

服务在创建 worker 之前预扩容文件描述符表，避免首次接入一批 TCP 连接时由内核扩容等待阻塞事件循环。按连接上限、监听器及 worker/刷新任务估算容量，并受现有 `RLIMIT_NOFILE` 约束；不提高系统上限，不保留额外 socket。预扩容失败会记录警告并沿用原行为，非 Linux 平台不执行。

默认 4 个 worker/组、128 个 TCP 连接时，目标描述符为 930，Linux 通常预留 1024 项；32 位系统描述符指针数组约 4 KiB，另有少量位图与管理信息。这是内核内存，不能只用进程 RSS 评估。较大配置需要更多空间，超出预留容量或外部继承大量描述符时仍可能再次扩容。新连接延迟应与复用连接的冷 DNS 延迟分别记录，保留整轮启动样本。

## 自动化验收

统一测试入口、场景矩阵与使用方式见 [自动化测试集](docs/test-suite.md)。
运行 `python3 scripts/testsuite.py plan --profile release` 可查看交付覆盖清单；
设备测试默认仅生成计划，使用独立端口、集合和资源限额，执行前需配置已验证产物及 SSH 主机密钥。
