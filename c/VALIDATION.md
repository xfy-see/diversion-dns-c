# C 验证记录

最新构建和实机测试按版本保存在[当前测试状态](../optimization/c-profiles-20261009/STATUS.md)，包含 ARM64 完整链接、实际查询、RSS/HWM、nft/路由与清理证据。以下初版记录保留为历史，本机通过和交叉编译不代替当前 Linux 内核测试。

# C 初版验证记录

2026-10-09 在本机 macOS ARM64 验证。C 实现没有部署或安装为系统服务。

| 验证 | 结果 |
|---|---|
| Native 严格编译 | Apple Clang 21、C11、Wall/Wextra/Wpedantic/Werror，通过 |
| 三个 C 单元套件 | DNS/upstream、domain/cache/nftset parser、engine，全部通过 |
| 端到端 mock | 14 项通过，含实际 UDP/TCP 分流、缓存、lazy 刷新、连续 TCP 帧、并发、TC 回退、错误 ID 过滤、active query 不被 idle timeout 中断 |
| 共享域名 fixture | 11 案例、70 断言通过；明确跳过 4 项 Unicode/RE2 专项，仅检查匹配结果/加载错误，不检查 fixture 的 expected_len |
| ASan/UBSan | 同一套单元、共享 fixture 和 14 项端到端测试通过，无 sanitizer 错误 |
| Linux musl 交叉编译 | Zig 0.14.1：ARM64/x86_64 各 9 个实现与 3 个单元测试编译单元，共 24 项通过，含 Linux nftset/mark/interface 分支 |
| 配置检查 | C 示例和原 Go site-only 示例均通过；缺少规则文件及占用 listener 端口不阻碍 check |

执行命令：

```sh
make -C c -j4 test
make -C c -j4 test BUILD=../.build/c-asan SANITIZE=1
./.build/c-native/mosdns-c check -c c/examples/minimal.yaml
./.build/c-native/mosdns-c check -c docs/go-profiles-site-only.yaml
```

本机日志与输入/产物 SHA-256 保存在忽略的构建目录：

- `.build/c-validation/native.log`
- `.build/c-validation/asan-ubsan.log`
- `.build/c-validation/manifest.json`
- `.build/c-linux-check/manifest.json`：逐个记录工具版本/摘要、目标、命令、源文件/对象摘要和退出码，全部源文件已与当前输入重新核对。

Native debug 可执行文件为 673,240 字节，静态链接 PCRE2/libyaml，动态依赖只有 macOS libSystem。这个数值未去除调试信息，不与其他语言或架构的 release 产物比较。

Linux 记录仅证明对象编译，没有目标 PCRE2 库的完整链接或 Linux 实际运行。实际 nftset 内核写入、元素 timeout、SO_MARK/SO_BINDTODEVICE 出口、路由器运行、性能和长期稳定性未在本轮验证。初版的语法/平台/传输兼容边界见 [README](README.md)。
