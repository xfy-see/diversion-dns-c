# diversion-dns-c

独立的 C11/POSIX DNS 分流程序，从 mosdns C r12 导入后专用于 CN-site 场景。源码仍在 `c/`；运行时已去掉 YAML、插件图和 sequence，改用有界 `key=value` 配置与固定请求链。

原始问题名匹配 CN 规则后，走共享缓存及唯一 CN/foreign 上游组；CN 回答包含缓存命中都经过原有 nft 最终处理。保留数字 UDP/TCP 上游、TCP 持久连接、TTL/LRU/lazy 缓存、Linux mark/接口绑定和 domain/full/keyword/regexp。没有跨组 fallback、热重载、服务安装或系统 DNS 接管。GPL-3.0-or-later；未参与构建的历史 libyaml 源码和原 MIT 许可证保留。

## 配置与运行

从精确提交的 CI 下载并验证产物后，在仓库根目录运行：

```sh
/path/to/mosdns-c check -c c/examples/minimal.conf
/path/to/mosdns-c start -c c/examples/minimal.conf --cpu 4
```

默认读取 [config.conf](config.conf)。`check` 现在会加载全部 CN 规则文件并编译 regexp，不打开 listener、不查询上游、不写 nft；规则文件缺失也会失败。相对路径基于进程工作目录或 `-d` 指定目录。

- [完整配置与迁移契约](docs/fixed-splitter.md)：全部键、限制、固定路由、缓存/nft 语义及部署前检查
- [集成优化与验收记录](docs/integrated-validation-20261010.md)：可选 POSIX-lite、`-Os`/LTO、OpenWrt 动态包及各自测试边界
- [C 运行与验证说明](c/README.md)：依赖、服务限制、CI 和历史验证边界
- [本次本地验证](docs/specialized-validation-20261009.md) 与 [同机体积对照](docs/specialized-size.md)：通过项、限制和复现依据
- [构建依赖边界](docs/build-dependencies.md)与[专用实现体积证据](docs/specialized-size.md)：移除的运行时依赖及本次测量范围
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

同一工作流还显式构建并验证 POSIX-lite：native/sanitizer 覆盖 macOS ARM64 和 Linux x86_64，静态 musl 覆盖 Linux ARM64/x86_64。它们分别保存在 `experimental-lite-*` Actions 产物中，并在 manifest 内记录 backend；默认产物仍为 PCRE2，lite 不进入现有自动 release。OpenWrt APK 另走 [SDK 实验流程](packaging/openwrt/README.md)。

main 分支的四个编译/测试 job 成功后，delivery job 会生成 `ci-<commit>-run<id>-attempt<n>` 预发布版本。四个同源 `.tar.gz` 下载包与 `SHA256SUMS` 可以直接从 GitHub Releases 下载，无需 Actions 登录；它们保留 Actions 包内同一份文件。

每包绑定 commit、run ID/attempt、完整 Git 源码树及逐文件 SHA256。独立保留 CI 测试日志。默认本地工作流不调用 C 编译器，只有用户明确授权时例外；常规本机测试直接运行下载的程序。

Linux static 包还在 `builds/static/size/` 保存 `mosdns-c.unstripped`、`mosdns-c.map`、`mosdns-c.mapped` 和 `attribution.json`。正常发布的 `builds/static/mosdns-c` 仍按原参数剥离；CI 用同一条 LLD 链接命令额外生成 map，并要求带 map 的已剥离文件与发布文件 SHA256 完全相同。应用、固定 PCRE2 依赖和测试使用 `-Os -flto`，仍保留静态 musl、原 stack 与 unwind 策略。JSON 按真正保留下来的输入节区计数：LTO 合并的项目、PCRE2 及 runtime 输入列为 `mixed_lto`，不硬拆为各自字节；依赖配置、精确链接输入和诊断 ELF 符号另行验证。未合并输入及历史非 LTO 产物继续按项目代码、PCRE2 和 musl/启动/编译器支持归类。当前产物不编译或链接 libyaml，历史产物归因仍保留其原分类，并单列合并常量、链接器生成内容及对齐/文件元数据；`bss_bytes` 是内存节区，不计入磁盘文件。未剥离 ELF 另供符号检查，不能假定其代码字节与使用 `-s` 的发布链接完全相同。

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
