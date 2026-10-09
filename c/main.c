/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 命令行入口负责选项检查、工作目录切换和引擎生命周期；网络收发由服务器模块负责。 */
#include "mosdns.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    puts("mosdns-c minimal: version | check [-c config] [-d directory] | start [-c config] [-d directory] [--cpu workers]");
}
int main(int argc, char **argv) {
    if (argc == 1 || !strcmp(argv[1], "help") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage(); return 0;
    }
    if (!strcmp(argv[1], "version")) {
        if (argc != 2) { fputs("version takes no arguments\n", stderr); return 1; }
        puts("mosdns-c 0.1.0 minimal"); return 0;
    }
    bool check = !strcmp(argv[1], "check");
    if (!check && strcmp(argv[1], "start")) {
        fprintf(stderr, "unsupported command: %s\n", argv[1]); return 1;
    }
    const char *config = "config.yaml", *dir = NULL;
    unsigned workers = 4;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(); return 0; }
        if (i + 1 >= argc) { fprintf(stderr, "missing value: %s\n", argv[i]); return 1; }
        if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) config = argv[++i];
        else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--dir")) dir = argv[++i];
        else if (!strcmp(argv[i], "--cpu") && !check) {
            char *end; errno = 0; const char *s = argv[++i];
            unsigned long n = strtoul(s, &end, 10);
            if (errno || !*s || *end || n < 1 || n > 64) {
                fputs("--cpu must be between 1 and 64\n", stderr); return 1;
            }
            workers = (unsigned)n;
        } else { fprintf(stderr, "unknown option: %s\n", argv[i]); return 1; }
    }
    /* 先切换目录，使配置、include 和规则文件使用同一套相对路径基准。 */
    if (dir && chdir(dir)) { fprintf(stderr, "chdir: %s\n", strerror(errno)); return 1; }
    char err[MD_ERROR_SIZE] = {0};
    md_engine *e = md_engine_load(config, check, err);
    if (!e) { fprintf(stderr, "%s\n", err); return 1; }
    /* check 只验证支持的配置和引用，不启动监听器，也不加载规则文件。 */
    if (check) {
        puts("configuration valid (no listeners or nft writes; rule files and runtime resources not checked)");
        md_engine_free(e); return 0;
    }
    /* 客户端提前断开 TCP 时，把写失败交给正常错误路径处理，避免进程被 SIGPIPE 终止。 */
    signal(SIGPIPE, SIG_IGN);
    int result = md_server_run(e, workers, err);
    /* md_server_run 返回后工作线程已退出，再释放引擎并等待可能的缓存刷新。 */
    md_engine_free(e);
    if (result) fprintf(stderr, "%s\n", err);
    return result ? 1 : 0;
}
