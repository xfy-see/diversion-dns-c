# `-Os` + LTO：本地构建与回归记录（2026-10-10）

> Historical component-level experiment: the results and publication status below refer to the original isolated run. See [the integrated validation record](../docs/integrated-validation-20261010.md) for the combined branch and its fresh tests.

## 范围

从 `59b8d4a90d9b9b1ee219afd5291b19632423afed` 建立隔离分支完成本地实现、测试和提交。
没有推送 GitHub、运行远端 CI、合并或部署。默认仍为 PCRE2 10.48，8-bit、静态、
禁用 Unicode/JIT；`REGEX_BACKEND=posix-lite` 仍需显式选择。

- 原生 Make、固定 PCRE2 依赖、实际 Linux release/profile builder 与 regex 比较脚本
  使用 `-Os -flto`，链接同步开启 LTO，独立 nft CLI 自编译测试也保持一致
- ASan/UBSan 保留 `-O1`、frame pointer；所有测试断言显式启用
- Linux 发布保留静态 musl、section GC、strip、1 MiB `PT_GNU_STACK` 与原 unwind 策略
- 不改运行时 C 逻辑，不替换 regex，不改 printf/浮点格式化，不关闭展开表
- LTO 的 `.lto.o` 记入 `mixed_lto`，不把项目/依赖/runtime 的合并结果硬拆成独立占比
- 保留 exact LLD replay、整文件 SHA-256 相同和诊断 ELF 分配节布局校验；独立验证
  PCRE2 配置、精确输入库路径及最终诊断 ELF 的存留 PCRE2 符号，lite 拒绝两者
- LTO 会内联部分入口（实测 `pcre2_match_8`），所以不要求每个公开函数名存留；
  可执行的 domain/差分测试另外验证 compile/match 行为
- 修复独立 release 测试包的既有缺口：`nft_cli_test.py` 结束时读取 `c/plugin/nftset.c`
  记录源码哈希，该文件现在从同一冻结源码复制，回归测试核对字节一致

## 同工具链静态文件尺寸

同一官方 Zig 0.14.1、musl 与 PCRE2 来源，对比上一轮同源 `-O2` 基线。
下列均为完整 stripped static ELF 文件大小，不是压缩大小、归档大小或 RSS。

| Backend | 目标 | 原 `-O2` | `-Os -flto` | 减少 |
|---|---|---:|---:|---:|
| PCRE2（默认） | ARM64 | 224,216 B | 199,056 B | 25,160 B / 11.22% |
| PCRE2（默认） | x86_64 | 245,320 B | 205,896 B | 39,424 B / 16.07% |
| posix-lite（实验） | ARM64 | 167,168 B | 151,464 B | 15,704 B / 9.39% |
| posix-lite（实验） | x86_64 | 164,640 B | 148,240 B | 16,400 B / 9.96% |

两个实际 release builder 的 PCRE2 文件均与比较脚本的对应产物逐字节相同。

| 目标 / Backend | SHA-256 |
|---|---|
| ARM64 PCRE2 | `5f14bfb3b6b6ee63eebfb306e4facee20372ceb897459457bf27b205a518bdae` |
| x86_64 PCRE2 | `1e79ece230f9579daf3c6b4d626d7513abe26779c033570d20edc050d35806fc` |
| ARM64 posix-lite | `1787b89cba987cd4042736c9aaba0bca479221f688796209c759a1cc2acdd78b` |
| x86_64 posix-lite | `7f0357425ec9d042bf2c87ab1c6d742d31eecfd5e685ddef7676fe718b7daf49` |

Zig 可执行文件 SHA-256：
`9df4f1d2eaa7c6ee7649d0e13853ad40deed5d94e643e9ff2a2bab52ffd9feee`。
工具来源仍由官方下载索引、归档摘要及归档内可执行文件三者核验；没有重新安装全局工具链。
最终两个 release 的冻结输入树摘要均为
`077018c2a338522060b590638509a0e8dc6bb49d7e5f2d0bcd14c583a0a2fdba`。

## 已执行验证

- Python verifier / backend isolation / build contract：71 项通过
- GCC 14 native PCRE2 与 lite：完整 Make unit + integration 通过
- GCC 14 ASan/UBSan PCRE2 与 lite：完整 Make unit + integration 通过
- 每组完整测试包含 12 项 loopback integration、18 项 nft CLI mock、157 项无 socket
  netlink 断言、8 线程 / 43,200 次共享 frozen regex 匹配及 backend-specific domain fixture
- native 与 x86_64 musl 各完成 81,089 次 portable differential comparison：
  unexpected differences 为 0；原有 2 项 PCRE2 MATCHLIMIT 预算差异仍显式记录，
  31 项限制/有意差异和 4 项 anchor 回归验证保留
- x86_64 musl PCRE2 与 lite：完整 Make unit + integration 通过
- 独立 nft 自编译入口：native 与 ASan/UBSan 各 18 项检查通过
- 实际 x86_64 release 输出目录：不借助源码 checkout 的 9 个验证命令通过，包含
  5 个 C test、domain fixture、nft CLI、12 项 integration 和 version；nft 使用已编译 driver
- 4 组 comparison + 2 组 release 的应用/测试共 48 个 ELF：目标架构正确、无
  `INTERP` / `NEEDED`，全部保留 1 MiB GNU_STACK
- 全部应用 map replay 哈希与发布文件一致、诊断分配节布局相同，磁盘归因字节对账，
  `unattributed` 为 0
- 独立审查本轮构建改动、最终 snapshot、71 项 Python 测试及独立 nft 闭环，无剩余发现

## 验证边界

- ARM64 仅交叉编译与 ELF 核验；本轮没有 ARM 执行或模拟运行
- 原生测试是本环境 GCC 14。为保留现有 C 源码而使用已有的
  `-Wno-error=misleading-indentation` 测试覆盖选项；sanitizer 使用 `-fno-pie -no-pie`
  避免本环境 PIE/ASan 地址布局问题。这些覆盖没有写入产品默认构建配置
- LSan 因 ptrace/sandbox 环境不兼容而关闭；没有声明泄漏检查通过
- 没有本地 Clang、macOS 或远端 CI 结果，不能以 GCC 测试代替这些平台验收
- 没有真实 kernel nft、路由器、QPS/p99、CPU/RSS 或长稳测试，不能声称无性能代价
- 本次独立审查限于构建改动；不追认之前 regex 实验尚未完成的独立最终实现审查

## 本地原始证据

以下路径均位于本分支 worktree；构建入口拒绝覆盖已有输出目录。

- `.build/comparison-final/manifest.json`：冻结源码、完整命令、PCRE2 配置、两个架构和 backend
- `.build/comparison-final/<target>/<backend>/size/`：map、诊断 ELF、逐字节一致的 replay 和归因
- `.build/comparison-final/x86_64-linux-musl/differential.json`：musl 差分记录
- `.build/release-final-{x86_64,aarch64}-linux-musl/manifest.json`：实际发布入口构建
- `.build/evidence/python-tests-final.log`、`native-final-rerun.log`、各 native/asan 日志
- `.build/evidence/native-differential.json`：native 差分记录
- `.build/evidence/standalone-compile-{native,asan}/result.json`：独立自编译入口
- `.build/evidence/release-standalone-final.json`：独立 release 9 条命令与退出状态
- `.build/evidence/release-nft-cli-final/result.json`：18 项检查及冻结源码摘要
- `.build/evidence/final-audit.json`：48 个 ELF、尺寸、哈希、静态身份与 stack 验证

保留先前的 `comparison` / `release-x86_64-linux-musl` 失败记录（过窄的公开符号名校验）、
已成功的 `comparison-02` / `release-02-*` 和独立 nft 缺文件失败记录，未将失败样本覆盖成成功。
