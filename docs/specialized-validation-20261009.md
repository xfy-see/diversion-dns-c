# 固定分流器本地验证（2026-10-09）

## 范围与源码

本次依用户对该项目的本地测试授权，在 dot 云端 Linux x86_64 上实现并验证。
没有使用用户 Mac，没有访问或修改路由器，没有推送、合并或触发 GitHub CI。

基线：`2992cb7917ae5de5a5e97e58ae72182ac15e0c1d`。该提交在既有
`5c5f0fc349938cde853aed2255f7b6631fa188f6` 上新增中文模块契约文档，已保留。
最后远端核验时 main 为 `2992cb7`，`optimize/pcre2-no-unicode` 为 `5c5f0fc`。
应用源码及体积对应的精确哈希见 [尺寸 JSON](specialized-native-size-20261009.json)。

固定引擎替换通用 YAML/plugin/sequence 入口；`pkg/dns.c`、`pkg/upstream.c`、
`pkg/domain.c`、`plugin/cache.c`、`plugin/nftset.c`、`pkg/server.c` 保持基线实现。
无 Unicode/JIT 的 PCRE2 10.48 官方源码归档按固定 SHA-256 校验后本地编译；
未安装新的大型工具链。

## 最终结果

| 检查 | Native | ASan/UBSan |
|---|---|---|
| dns_test | 通过 | 通过 |
| cache_domain_test（含实际 PCRE2 profile） | 通过 | 通过 |
| fixed_config_test | 通过 | 通过 |
| fixed_engine_test（mock upstream/nft/clock） | 通过 | 通过 |
| nft_netlink_test | 157 断言通过 | 157 断言通过 |
| 共享域名 fixture | 11 例 / 70 断言通过 | 11 例 / 70 断言通过 |
| 字节正则与 Unicode 拒绝 | 7 例、5 类拒绝 / 34 断言通过 | 同左 |
| fixed_integration.py | 12 例通过 | 12 例通过 |
| nft CLI grammar/错误/超时 | 18 例通过 | 18 例通过 |

另有 62 个纯 Python 测试全部通过，其中 33 个迁移器测试；`git diff --check` 通过。
默认 `config.conf` 与 `c/examples/minimal.conf` 的真实规则加载检查及 version smoke 通过。
实际历史 `docs/go-profiles-site-only.yaml` 转换成功，保留 TCP idle 默认值 10 秒。
独立复核发现 standalone 静态测试包漏复制共享 integration.py，已修复：构建器统一
复制测试依赖，新增干净目录导入回归，并在实际 helper 复制后的独立目录重跑 12 个集成案例。
完整 Linux 示例依赖外部真实规则、接口、mark 路由和 nft 集合，未当作真实部署配置启动。

### 新增重点

- 单值重复、未知/空键值、非法数字/IP、NUL、控制字符、4096 字节行和 1 MiB 文件边界
- 列表各 64 项及 UDP/TCP 合计 64 监听限制，重复规范化监听地址拒绝
- 整行注释；规则路径内 `#`、`;`、`=` 保持字面值
- `check` 真正加载规则、保留配置/规则文件行号，不开监听/上游连接或写 nft
- CN/foreign 原始 QNAME 正负对照、两方向 CNAME、A/AAAA、负响应
- 新鲜/stale 缓存仍走 CN nft；nft 失败与后续缓存命中重试；无跨出口回退
- cache key/配置实例隔离、禁用缓存、lazy 刷新去重和销毁 join
- 旧的粗粒度 5 秒规则边界截止时间、NULL error 参数
- UDP/TCP、持久连接、部分帧、并发、TC→TCP、错 ID/问题响应过滤、超时/传输失败
- 实际 mock nft 子进程非零退出、错误 metadata、5 秒截止超时，无真实内核写入
- 迁移器只接受完整验证的支持子集；重复字段/alias/未知 graph、超大整数、surrogate 等拒绝

## 明确限制

1. LeakSanitizer 开启时报告此云端的 ptrace 环境限制，不能运行。最终 ASan/UBSan
   使用 `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1` 和 `UBSAN_OPTIONS=halt_on_error=1`。
   不能声称 LSAN/泄漏检查通过；Linux CI 仍保持原有 LSAN 开启设置。
2. GCC 14 对原有紧凑写法产生 misleading-indentation 告警，基线严格编译先失败。
   前后对照与本地回归仅用 `-Wno-error=misleading-indentation` 降级这一类告警，
   其他 `-Werror` 保留。新 engine 无该告警；没有更改 CI 的 clang/Zig 严格参数。
3. 共享 fixture 的 4 个既有 Unicode/RE2 差异案例按明确原因跳过；没有声明完整 Go
   matcher 兼容。PCRE2 普通字节正则保留，Unicode 指令确实被拒绝。
4. PCRE2 静态库使用既定普通构建；本地 sanitizer 覆盖项目编译单元，第三方库不是
   独立的全库 sanitizer 构建。
5. 尚未执行此改动的 GitHub 四平台 CI、ARM64/static-musl/macOS 运行、真实 nft 内核
   更新、SO_MARK/接口出口、防泄漏路由、目标设备 QPS/RSS 或长稳测试。
   x86_64 本地大小不代表 ARM64 发布大小。

## 可复现命令和证据

依赖构建方法及 SHA-256 见 [构建依赖](build-dependencies.md)。本次依赖输出目录为
`.build/pcre2-local-specialized`。两个独立 BUILD 目录避免 native/sanitizer 互相污染：

```sh
make -C c --jobserver-style=pipe -j4 \
  BUILD=../.build/specialized-native-tests \
  PCRE2_PREFIX=../.build/pcre2-local-specialized \
  CFLAGS='-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -Wno-error=misleading-indentation -pthread' test

ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
make -C c --jobserver-style=pipe -j4 \
  BUILD=../.build/specialized-sanitize-tests \
  PCRE2_PREFIX=../.build/pcre2-local-specialized SANITIZE=1 \
  CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -Wno-error=misleading-indentation -pthread -fsanitize=address,undefined -fno-omit-frame-pointer' test

python3 -m unittest discover -s tests -v
```

`--jobserver-style=pipe` 为当前 GNU Make 的云端并行运行设置，不是跨平台必需参数。
本地原始日志位于 `.build/local-evidence/`：`native-complete.*`、
`sanitizer-complete.*`、`python-reviewed.*`、`standalone-reviewed.*`、`remote-head-final.txt`；包含较早失败及修复后
重跑的日志，未覆盖失败证据。测试二进制和 nft 子进程调用记录仍保留在各 BUILD 目录。
尺寸另有冻结输入、完整命令、nm/size/readelf/strip 输出，见 [体积对照](specialized-size.md)。
