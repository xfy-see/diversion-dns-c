# diversion-dns-c

独立的 C11/POSIX DNS 分流程序，从 mosdns C r12 导入，保留 `coremain → plugin → pkg` 分层和 YAML plugin/sequence 模型。源码在 `c/`，不包含 Go/Rust 应用。

支持域名规则、UDP/TCP 上游、TCP 持久连接、有界 TTL/LRU/lazy 缓存、sequence 控制流、Linux socket mark/接口绑定和 nftset 地址学习。完整能力和兼容边界见 [C 文档](c/README.md)。GPL-3.0-or-later；内置 libyaml 保留原 MIT 许可证。

## 后续修改与编译

本地修改、提交、push 后，由 [GitHub Actions](../../actions) 自动编译和执行回归，生成：

| 产物 | 内容 |
|---|---|
| macOS ARM64 native | 本机可运行的程序、native 和 ASan/UBSan 测试程序及 sanitizer runtime |
| Linux x86_64 native | Linux native/ASan/UBSan 程序和测试程序 |
| Linux ARM64 static | 固定 Zig 0.14.1、PCRE2 10.48，静态 musl 程序和全部测试程序 |
| Linux x86_64 static | 同样固定依赖的静态 musl 程序和全部测试程序 |

每包绑定 commit、run ID/attempt、完整 Git 源码树及逐文件 SHA256。独立保留 CI 测试日志。实际本地工作流不调用 C 编译器；本机测试直接运行下载的程序。

## 下载后的完整本地校验

先确认精确提交对应的四个 CI job 全部成功，通过 GitHub 插件或 GitHub CLI 下载同次 run/attempt 的 Actions ZIP。以 macOS ARM64 包为例：

```sh
commit=$(git rev-parse HEAD)
run_id=实际运行ID
python3 scripts/artifacts.py extract \
  --archive /path/to/macos-arm64.zip \
  --expected-commit "$commit" --expected-run-id "$run_id" \
  --archive-sha256 GitHub_artifact_digest \
  --checkout . --output ".artifacts/$commit-macos-arm64"
python3 scripts/validate.py \
  --bundle ".artifacts/$commit-macos-arm64" --checkout . \
  --output "validation/$commit-macos-arm64"
```

验证器拒绝提交不符、文件哈希不符、非预期平台、重复条目、目录穿越和链接。目录必须新建，失败记录不得覆盖。校验范围是每 profile 五个 C suite、domain fixture 70 断言（4 个 Unicode/RE2 专项明确跳过）、16 个服务测试、5 个 plan 测试、15 个 nft CLI 语法/回执路径检查和 CLI smoke。macOS 包会分别运行 native 与 ASan/UBSan，Darwin 不启用 LSAN。

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
