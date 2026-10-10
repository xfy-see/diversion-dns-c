# 专用分流版本的构建依赖

当前运行路径是固定的 `key=value` 配置和内外分流逻辑。原生 Makefile、
ASan/UBSan 和 Linux musl 静态构建均不编译或链接 libyaml，也不读取 YAML。

## 依赖与许可证

- 项目代码：GPL-3.0-or-later，见根目录 [LICENSE](../LICENSE)
- PCRE2：固定 10.48，8-bit 静态库；关闭 Unicode、JIT、16-bit、32-bit。
  上游许可证为 `BSD-3-Clause WITH PCRE2-exception`。构建时从已校验的
  官方源码归档复制 `LICENCE.md` 和 `AUTHORS.md`，所有新 CI bundle 的
  `builds/<profile>/licenses/` 均携带这两份原文
- libc、线程与编译器运行库：原生程序由目标系统提供；Linux 静态版本使用
  固定 Zig 0.14.1 所带 musl/启动和编译器支持。具体链接输入保留在静态
  manifest 和尺寸归因报告中
- libyaml 0.2.5：只为历史源码、测试与已存证据保留在 `c/vendor/libyaml/`。
  它的 MIT 许可证仍随源码保留，当前程序不包含该库

PCRE2 官方归档：
`https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz`

SHA-256：`ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888`

原生和静态依赖构建入口均拒绝其他摘要；Makefile 不回退到系统 PCRE2。
运行 `cache_domain_test` 还会查询实际链接的 PCRE2，确认 Unicode/JIT 已关闭。

## 当前与历史校验

当前五组 C 测试为 `dns_test`、`cache_domain_test`、`fixed_config_test`、
`fixed_engine_test`、`nft_netlink_test`；此外运行 `domain_driver` 共享规则
fixture、`fixed_integration.py` 和 `nft_cli_driver` 的 18 项 CLI 语法/失败检查。
原生、sanitizer 和静态 bundle 采用相同的当前套件。

旧 `engine_test`、`plan_regression_test`、YAML 集成测试及输入不删除。
验证器仍识别完整的历史 plugin/sequence bundle，并使用其中的历史测试与
`minimal.yaml`；当前 bundle 使用 `minimal.conf`。不接受混搭或缺失的测试集合。

## 尺寸记录

静态发布保留完整的链接 map、字节相同的 map 重放文件、未剥离诊断文件和
归因 JSON；新静态构建要求 `disk_bytes.libyaml` 为零。归因器保留这一历史
分类，便于重读旧证据，不能因源树仍有 libyaml 就把它算作当前运行依赖。

原生本地与 Linux musl 静态产物、x86_64 与 ARM64、带调试符号与剥离文件
必须分别记录。只比较编译器、依赖、优化及剥离参数相同的前后版本；编译或
体积结果不替代目标设备 NFT、路由、吞吐和长期稳定性验收。
