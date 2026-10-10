# 专用分流版本：本地体积对照（2026-10-09）

测量平台为 Linux x86_64、GCC 14.2.0，动态依赖仅 `libc.so.6`。
PCRE2 10.48 以同一份关闭 Unicode/JIT 的静态库链接。此处不是 ARM64 或
Linux musl 完全静态发布包的结果，也不代表设备吞吐、内核 NFT 或长期稳定性。

基线提交：`2992cb7917ae5de5a5e97e58ae72182ac15e0c1d`。当前源码从工作区冻结后构建；
精确输入文件 SHA-256、依赖哈希和产物哈希见 [JSON 记录](specialized-native-size-20261009.json)。

## 同参数对照

| 应用编译参数 | 基线（字节） | 专用版（字节） | 减少 |
|---|---:|---:|---:|
| `-O2 -g`，随后 strip | 322,840 | 220,376 | 102,464（31.74%） |
| `-Os -DNDEBUG` + section GC，随后 strip | 273,720 | 208,088 | 65,632（23.98%） |

标准构建未剥离时：基线 813,904 字节，专用版 453,856 字节。带调试信息的
数字受路径及调试元数据影响，以上剥离对照更适合比较应用体积。

两版共同添加 `-std=c11 -Wall -Wextra -Wpedantic -Werror`、
`-Wno-error=misleading-indentation -pthread`。旧代码在 GCC 14 上存在
misleading-indentation 警告；首次严格失败日志完整保留。只将这一类既有
警告降级，其他警告仍作为错误；仓库 CI 的 clang/Zig 严格参数未放宽。

size profile 额外设置 `-ffunction-sections -fdata-sections`，链接使用
`-Wl,--gc-sections`；两版均用同一个 `strip --strip-all`。PCRE2 构建参数
保持一致，没有将不同依赖版本或 Unicode/JIT 配置的结果混在一起。

## 依赖移除检查

- 标准基线中 `nm --defined-only` 发现 127 个 `yaml_` 符号；专用版为 0
- size profile 基线为 53 个 `yaml_` 符号；专用版为 0
- 两版均保留 PCRE2 符号；当前原生/静态构建清单不再包含 libyaml 源码
- 本次是整体固定流程与配置简化后的差值，不能把所有减少字节都归因给 libyaml

## 原始证据与复现

本次 `.build/local-evidence/` 保留初次、严格失败、告警兼容及最终构建的命令、
stdout/stderr、`size`、`nm`、`file`、`readelf -d` 输出和 SHA-256。
基线在 `.build/baseline-source/`，当前冻结源码在 `.build/specialized-final-source/`；
各轮二进制互不覆盖。以上为本地证据目录，不是已下载的 GitHub CI 产物。

复现须在相同主机/工具链条件下，从基线 `git archive` 和当前源码快照，使用
[依赖构建说明](build-dependencies.md) 中的固定 PCRE2；分别为两版创建新
BUILD 目录，传入 JSON 中的完整 CFLAGS/LDFLAGS，先执行 `make -C c all`，
再对副本执行 `strip --strip-all`。不要把调试文件或另一架构的静态文件与
上述字节数直接比较。
