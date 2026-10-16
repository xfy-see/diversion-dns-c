#!/usr/bin/env python3
"""Run P0 CN-priority acceptance on one isolated OpenWrt device.

This is an opt-in device harness, not a unittest discovered by CI. It requires
already authenticated GitHub source/binary receipts and pins the SSH host key.
It uses a private /tmp directory, unprivileged DNS ports, and an nft table with
NO hooks. Production UCI and init scripts are never invoked. The service/UCI
adapters are fixtures; DNS probes, C processes and nft transactions are real.
No compiler, package installation, interface change, or global flush is used.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
IP1 = ("223.5.5.0/24\n119.29.29.0/24\n114.114.114.0/24\n180.76.76.0/24\n101.2.1.0/24\n101.3.1.0/24\n"
       "2400:3200::/32\n2402:4e00::/32\n2401:1000::/32\n2401:2000::/32\n2401:3000::/32\n")
IP2 = IP1 + "101.1.1.0/24\n2401:3800::/32\n"
SITE1 = "domain:qq.com\ndomain:baidu.com\ndomain:cn.test\ndomain:bilibili.com\ndomain:163.com\ndomain:jd.com\n"
SITE2 = SITE1 + "domain:douban.com\n"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def pinned(record):
    p = Path(record["path"])
    require(p.is_file() and not p.is_symlink(), "missing/symlink pinned file: " + str(p))
    raw = p.read_bytes()
    require(SHA.fullmatch(record.get("sha256", "")) and sha(raw) == record["sha256"],
            "pinned digest mismatch: " + str(p))
    return raw


def load_config(path):
    cfg = json.loads(Path(path).read_text())
    require(cfg.get("schema_version") == 1, "configuration schema_version must be 1")
    host = cfg["target"]
    ipaddress.IPv4Address(host["address"])
    require(host["address"] in ("192.168.100.122", "192.168.100.131"),
            "this approval scope only permits .122/.131")
    argv = host["ssh"]
    require(argv[0] == "ssh" and argv[-1] == "root@" + host["address"], "SSH destination mismatch")
    require("-F" in argv and argv[argv.index("-F") + 1] == "/dev/null", "SSH must ignore ambient config")
    options = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-o"]
    for value in ("BatchMode=yes", "StrictHostKeyChecking=yes"):
        require(value in options, "required SSH option: " + value)
    known = [v.partition("=")[2] for v in options if v.startswith("UserKnownHostsFile=")]
    require(len(known) == 1 and Path(known[0]).is_file(), "pinned known_hosts required")
    require(re.fullmatch(r"[a-f0-9-]{36}", host["expected_boot"]), "expected boot ID required")
    require(host["production_files"], "explicit protected production paths required")
    require(all(p.startswith("/") and "\n" not in p for p in host["production_files"]), "bad protected path")
    source = cfg["source"]
    require(COMMIT.fullmatch(source["commit"]) and COMMIT.fullmatch(source["tree"]), "full source identity required")
    receipt = json.loads(pinned(source["receipt"]))
    require(receipt.get("source_commit") == source["commit"]
            and receipt.get("source_tree") == source["tree"]
            and receipt.get("source_payload_verified") is True
            and receipt.get("workflow_passed") is True
            and int(receipt.get("run_id", 0)) > 0
            and int(receipt.get("run_attempt", 0)) > 0,
            "source receipt does not attest exact successful workflow/source payload")
    root = Path(source["path"]).resolve()
    # The supplied source may be an artifact extraction without .git. Its
    # authenticated receipt must bind every script executed on the target.
    names = ["common.sh", "guard.sh", "recover.sh", "rollback.sh", "dns-probe.lua", "cn-data.lua", "cn-data.sh", "cn-policy.sh", "diversion-dns-c.init"]
    scripts = {}
    for name in names:
        rel = "deployment/openwrt-recovery/" + name
        p = root / rel
        require(p.is_file() and not p.is_symlink(), "missing candidate script " + rel)
        raw = p.read_bytes()
        require(receipt.get("files", {}).get(rel) == sha(raw), "candidate differs from source receipt: " + rel)
        scripts[name] = raw
    binary = pinned(cfg["binary"])
    require(binary.startswith(b"\x7fELF"), "router executable must be ELF")
    breceipt = json.loads(pinned(cfg["binary"]["receipt"]))
    if cfg["binary"]["receipt"].get("key"):
        breceipt = breceipt[cfg["binary"]["receipt"]["key"]]
    require(breceipt.get("elf_sha256") == sha(binary)
            and breceipt.get("source_payload_verified") is True
            and breceipt.get("release_verifier_passed") is True,
            "binary receipt missing payload/release verification")
    require(COMMIT.fullmatch(breceipt.get("source_commit", "")) and int(breceipt.get("run_id", 0)) > 0,
            "binary commit/run identity missing")
    for key in ("c_port", "frontend_port", "fixture_port"):
        require(type(cfg.get(key)) is int and 1024 <= cfg[key] <= 65535, "unprivileged " + key + " required")
    require(len({cfg[k] for k in ("c_port", "frontend_port", "fixture_port")}) == 3, "ports must differ")
    ipaddress.IPv4Address(cfg["fixture_address"])
    if cfg.get("full_datasets"):
        pinned(cfg["full_datasets"]["ip"])
        pinned(cfg["full_datasets"]["site"])
        require(16 <= int(cfg["full_datasets"].get("memory_limit_mib", 24)) <= 64,
                "full dataset memory limit must be 16..64MiB")
    cfg["_scripts"], cfg["_binary"] = scripts, binary
    cfg["_verification"] = dict(source=receipt, binary=breceipt,
                                source_receipt_sha256=source["receipt"]["sha256"],
                                binary_receipt_sha256=cfg["binary"]["receipt"]["sha256"])
    return cfg


class Fixture:
    """Bounded actual UDP DNS fixture; only the authorized router may query."""
    def __init__(self, address, port, peer):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, port))
        self.socket.settimeout(.2)
        self.peer = peer
        self.cn_ok = True
        self.foreign_ok = True
        self.rows = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if peer[0] != self.peer:
                continue
            try:
                labels, pos = [], 12
                while packet[pos]:
                    length = packet[pos]
                    require(0 < length <= 63, "bad fixture query label")
                    labels.append(packet[pos + 1:pos + 1 + length].decode("ascii"))
                    pos += length + 1
                end = pos + 5
                qtype, qclass = struct.unpack("!HH", packet[pos + 1:end])
                require(end == len(packet) and qclass == 1 and qtype in (1, 28), "unsupported fixture query")
                name = ".".join(labels).lower()
                domestic = name == "localhost" or any(name == x or name.endswith("." + x)
                    for x in ("qq.com", "baidu.com", "cn.test", "bilibili.com", "163.com"))
                enabled = True if name == "localhost" else (self.cn_ok if domestic else self.foreign_ok)
                row = dict(time=time.time(), name=name, qtype=qtype, domestic=domestic, replied=enabled)
                self.rows.append(row)
                if not enabled:
                    continue
                value = 1 + int(sha(name.encode())[:4], 16) % 65534
                answer = (ipaddress.IPv4Address((198 << 24) | (18 << 16) | value).packed if qtype == 1
                          else ipaddress.IPv6Address((0xfdab << 112) | value).packed)
                response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + packet[12:end]
                response += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(answer)) + answer
                self.socket.sendto(response, peer)
            except (IndexError, ValueError, UnicodeError, struct.error):
                continue

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.socket.close()
        self.thread.join(2)


def query(address, port, name, qtype, timeout=9):
    ident = int.from_bytes(os.urandom(2), "big")
    question = b"".join(bytes([len(s)]) + s.encode() for s in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
    packet = struct.pack("!HHHHHH", ident, 0x100, 1, 0, 0, 0) + question
    start = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((address, port))
        sock.send(packet)
        raw = sock.recv(65535)
    require(len(raw) >= 12 + len(question) and raw[:2] == packet[:2], "bad DNS response")
    fields = struct.unpack("!HHHHHH", raw[:12])
    require(raw[12:12 + len(question)] == question, "question changed")
    return dict(name=name, qtype=qtype, rcode=fields[1] & 15, answers=fields[3],
                elapsed_ms=(time.monotonic() - start) * 1000, wire_hex=raw.hex())


class Suite:
    def __init__(self, cfg, output):
        self.cfg, self.output = cfg, output
        self.token = uuid.uuid4().hex[:16]
        self.root = "/tmp/ddns-p0-" + self.token
        self.table = "ddns_p0_" + self.token
        self.base = self.root + "/base"
        self.rows, self.calls = [], []
        self.started = False
        self.before = None
        self.fixture = None
        self.env = dict(DIVERSION_DNS_BASE=self.base,
            DIVERSION_DNS_RUN=self.root + "/run", DIVERSION_DNS_INITDIR=self.root + "/init.d",
            DIVERSION_DNS_LOCK=self.root + "/deploy.lock", DIVERSION_CN_TABLE=self.table,
            DIVERSION_DNS_POLICY_TABLE=self.table, DIVERSION_CN_MIN4="4", DIVERSION_CN_MIN6="2",
            DIVERSION_CN_MINSITE="4", DIVERSION_CN_BINARY=self.root + "/app",
            DIVERSION_DNS_C_PORT=str(cfg["c_port"]), DIVERSION_DNS_FRONTEND_PORT=str(cfg["frontend_port"]),
            DIVERSION_DNS_GUARD_STARTUP="0", DIVERSION_DNS_GUARD_INTERVAL="1",
            P0_ROOT=self.root, P0_FIXTURE=cfg["fixture_address"] + ":" + str(cfg["fixture_port"]),
            P0_C_PORT=str(cfg["c_port"]), P0_FRONT_PORT=str(cfg["frontend_port"]),
            PATH=self.root + "/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        if cfg.get("lua_module"):
            module = cfg["lua_module"]
            require(module["path"].startswith("/tmp/") and module["path"].endswith("/nixio.so"), "test module must be temporary")
            require(SHA.fullmatch(module["sha256"]), "module digest required")
            self.env["LUA_CPATH"] = str(Path(module["path"]).parent) + "/?.so;;"

    def rem(self, command, data=None, expected=0, timeout=40):
        if self.started:
            command = ("test \"$(cat " + self.root + "/owner)\" = " + self.token + " || exit 90; "
                       "echo $(( $(date +%s) + 300 )) > " + self.root + "/lease; " + command)
        command = "set -eu; " + command
        proc = subprocess.run(self.cfg["target"]["ssh"] + [command], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        row = dict(command=command, returncode=proc.returncode,
                   stdout=proc.stdout.decode(errors="replace"), stderr=proc.stderr.decode(errors="replace"))
        self.calls.append(row)
        save(self.output / "commands.json", self.calls)
        if expected is not None:
            require(proc.returncode == expected, "remote command failed: " + row["stderr"][-2000:] + row["stdout"][-2000:])
        return row

    def shell(self, command, **kw):
        prefix = "env " + " ".join(shlex.quote(k + "=" + v) for k, v in self.env.items())
        return self.rem(prefix + " sh -c " + shlex.quote("set -eu; " + command), **kw)

    def put(self, name, raw, mode=0o600):
        require(re.fullmatch(r"[a-zA-Z0-9_./-]+", name) and ".." not in name, "bad relative stage path")
        if isinstance(raw, str):
            raw = raw.encode()
        destination = self.root + "/" + name
        self.rem("cat > " + destination + "; chmod " + oct(mode)[2:] + " " + destination, data=raw)
        require(self.rem("sha256sum " + destination)["stdout"].split()[0] == sha(raw), "remote staging digest mismatch")

    def snapshot(self):
        paths = self.cfg["target"]["production_files"]
        raw = self.rem("cat /proc/sys/kernel/random/boot_id; sha256sum " + shlex.join(paths)
                       + "; printf '\\nTABLES\\n'; nft -j list tables; printf '\\nMEMORY\\n'; cat /proc/meminfo; "
                       "printf '\\nPROCESSES\\n'; ps w; printf '\\nADDRESSES\\n'; ip -4 addr show; "
                       "printf '\\nCONNTRACK\\n'; cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true")["stdout"]
        head, rest = raw.split("\nTABLES\n", 1)
        lines = head.splitlines()
        require(lines[0] == self.cfg["target"]["expected_boot"], "device rebooted; stop")
        require(len(lines[1:]) == len(paths), "protected hash list incomplete")
        require("inet " + self.cfg["target"]["address"] + "/" in rest, "SSH endpoint lacks expected LAN address")
        tablejson = json.loads(rest.split("\nMEMORY\n")[0])
        tables = sorted((x["table"]["family"], x["table"]["name"]) for x in tablejson["nftables"] if "table" in x)
        memory = re.search(r"MemAvailable:\s+(\d+)", rest)
        require(memory and int(memory[1]) >= 16000, "less than 16MiB memory available")
        return dict(boot=lines[0], hashes=lines[1:], tables=tables, raw=raw)

    def script(self, name, *args, **kw):
        return self.shell(shlex.join([self.base + "/" + name] + list(args)), **kw)

    def current(self):
        return self.rem("readlink " + self.base + "/cn-data/current")["stdout"].strip().split("/")[-1]

    def generation(self):
        return self.base + "/cn-data/generations/" + self.current()

    def audit(self):
        self.script("cn-data.sh", "audit-runtime", "--force", timeout=90)

    def assert_cn(self, prefix):
        rows = []
        for qtype in (1, 28):
            row = query(self.cfg["target"]["address"], self.cfg["c_port"], prefix + ".qq.com", qtype)
            require(row["rcode"] == 0 and row["answers"] > 0, "CN DNS failed")
            rows.append(row)
            value = 1 + int(sha(row["name"].encode())[:4], 16) % 65534
            addr = str(ipaddress.IPv4Address((198 << 24) | (18 << 16) | value) if qtype == 1
                       else ipaddress.IPv6Address((0xfdab << 112) | value))
            setname = "cn_site4" if qtype == 1 else "cn_site6"
            self.rem("nft get element inet " + self.table + " " + setname + " '{ " + addr + " }'")
        return rows

    @contextmanager
    def case(self, name):
        row = dict(id=name, status="running", started_utc=datetime.now(timezone.utc).isoformat())
        self.rows.append(row)
        try:
            yield row
            row["status"] = "pass"
        except Exception as exc:
            row["status"] = "fail"
            row["error"] = str(exc)
            raise
        finally:
            row["completed_utc"] = datetime.now(timezone.utc).isoformat()
            save(self.output / "cases.json", self.rows)

    def prepare(self):
        self.before = self.snapshot()
        save(self.output / "before.json", self.before)
        self.rem("test ! -e " + self.root + "; test ! -e /tmp/ddns-suite.lock; "
                 "! nft list table inet " + self.table + " >/dev/null 2>&1; "
                 "test -z \"$(netstat -ln 2>/dev/null | awk '$4 ~ /:(" + str(self.cfg["c_port"]) + "|"
                 + str(self.cfg["frontend_port"]) + ")$/ {print}')\"")
        self.rem("set -eu; mkdir -m700 " + self.root + "; echo " + self.token + " > " + self.root + "/owner; "
                 "mkdir " + " ".join(self.root + "/" + p for p in ("base", "run", "init.d", "bin", "input", "state")))
        self.started = True
        self.put("cleanup.sh", self.cleanup_body(), 0o700)
        self.put("watch.sh", '#!/bin/sh\ntrap "" HUP\n'
                 'while [ -f "' + self.root + '/owner" ]; do\n'
                 ' sleep 10\n'
                 ' [ "$(date +%s)" -lt "$(cat ' + self.root + '/lease 2>/dev/null || echo 0)" ] || { '
                 'sh ' + self.root + '/cleanup.sh; exit; }\ndone\n', 0o700)
        self.rem("sh -c 'trap \"\" HUP; echo $$ > " + self.root + "/watch.pid; exec sh " + self.root
                 + "/watch.sh' > " + self.root + "/watch.log 2>&1 < /dev/null &")
        for name, raw in self.cfg["_scripts"].items():
            self.put("base/" + name, raw, 0o700)
        self.put("app", self.cfg["_binary"], 0o700)
        if self.cfg.get("lua_module"):
            module = self.cfg["lua_module"]
            require(self.rem("sha256sum " + shlex.quote(module["path"]))["stdout"].split()[0] == module["sha256"], "nixio module digest differs")
        self.shell("lua -e 'assert(require(\"nixio\").socket(\"inet\",\"dgram\"))'")
        for name, text in self.adapters().items():
            self.put(name, text, 0o700)
        self.put("base/cn-ip.txt", IP1)
        self.put("base/cn-site.txt", SITE1)
        table = "inet " + self.table
        sets = ("add table " + table + "\n"
                "add set " + table + " cn4 { type ipv4_addr; flags interval; auto-merge; }\n"
                "add set " + table + " cn6 { type ipv6_addr; flags interval; auto-merge; }\n"
                "add element " + table + " cn4 { " + ", ".join(x for x in IP1.splitlines() if ":" not in x) + " }\n"
                "add element " + table + " cn6 { " + ", ".join(x for x in IP1.splitlines() if ":" in x) + " }\n"
                "add set " + table + " cn_site4 { type ipv4_addr; flags timeout; timeout 1h; }\n"
                "add set " + table + " cn_site6 { type ipv6_addr; flags timeout; timeout 1h; }\n"
                "add set " + table + " vpn_clients4 { type ipv4_addr; }\n"
                "add set " + table + " vpn_clients6 { type ipv6_addr; }\n"
                + "".join("add chain " + table + " " + n + "\n" for n in ("classify", "split", "guard", "router_output", "router_guard", "dns_redirect")))
        self.put("base/sets.nft", sets)
        self.rem("touch " + self.root + "/owns-table; nft -f " + self.base + "/sets.nft")
        policy = "".join("add chain " + table + " " + n + "\nadd rule " + table + " " + n + " counter return\n"
                         for n in ("classify", "split", "guard", "router_output", "router_guard", "dns_redirect"))
        self.put("base/policy.nft", policy)
        self.script("apply-policy.sh")
        config = ("listen_udp=0.0.0.0:" + str(self.cfg["c_port"]) + "\nlisten_tcp=127.0.0.1:" + str(self.cfg["c_port"])
                  + "\ncn_domain_file=" + self.base + "/cn-site.txt\ncn_upstream=" + self.env["P0_FIXTURE"]
                  + "\nforeign_upstream=" + self.env["P0_FIXTURE"] + "\ncache_size=64\ncache_lazy_ttl=0\nnftset_fast=1\nnftset_hit_window_ms=0\n"
                  + "nftset_ipv4=inet," + self.table + ",cn_site4,ipv4_addr,32\nnftset_ipv6=inet," + self.table + ",cn_site6,ipv6_addr,128\n")
        self.put("base/config.conf", config)
        self.put("state/servers", "127.0.0.1#" + str(self.cfg["c_port"]) + "\n")
        self.put("state/cachesize", "0\n")
        self.rem("touch " + self.base + "/active")
        self.shell(self.root + "/init.d/diversion-dns-c start; " + self.root + "/init.d/dnsmasq restart", timeout=15)
        time.sleep(.3)
        self.assert_cn("prepare")

    def adapters(self):
        init = '''#!/bin/sh
set -eu
R=$P0_ROOT
name=$(basename "$0")
case "$name" in diversion-dns-c) role=app; cfg="$R/base/config.conf";; dnsmasq) role=front; cfg="$R/front.conf";; *) exit 90;; esac
printf '%s %s\\n' "$name" "$*" >> "$R/service-calls"
stop() {
 if [ -f "$R/$role.pid" ]; then
  p=$(cat "$R/$role.pid")
  if kill -0 "$p" 2>/dev/null; then
   [ "$(readlink /proc/$p/exe)" = "$R/app" ] || exit 91
   kill "$p"
   n=0; while kill -0 "$p" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 1; n=$((n+1)); done
   ! kill -0 "$p" 2>/dev/null || exit 92
  fi
  rm "$R/$role.pid"
 fi
}
start() {
 if [ -f "$R/fail-restart-once" ] && [ "$role" = app ]; then rm "$R/fail-restart-once"; return 1; fi
 if [ "$role" = front ]; then
  upstream=$(cat "$R/state/servers" | tr '#' ':')
  cat > "$cfg" <<EOF
listen_udp=127.0.0.1:$P0_FRONT_PORT
listen_tcp=127.0.0.1:$P0_FRONT_PORT
cn_domain_file=$R/base/cn-site.txt
cn_upstream=$upstream
foreign_upstream=$upstream
cache_size=0
EOF
 fi
 # procd launches services independently; emulate that descriptor boundary so
 # the fixture daemon cannot inherit and retain a recovery/data flock.
 sh -c 'trap "" HUP; exec 7>&- 9>&-; echo $$ > "$1"; exec "$2" start -c "$3" --cpu 1' sh "$R/$role.pid" "$R/app" "$cfg" > "$R/$role.log" 2>&1 < /dev/null &
 sleep 1
 p=$(cat "$R/$role.pid"); kill -0 "$p"
}
case "${1:-}" in
 start) if [ -f "$R/$role.pid" ] && kill -0 "$(cat "$R/$role.pid")" 2>/dev/null; then exit 0; fi; start;;
 stop) stop;; restart) stop; start;; status) test -f "$R/$role.pid" && kill -0 "$(cat "$R/$role.pid")";; *) exit 93;; esac
'''
        uci = '''#!/bin/sh
set -eu
R=$P0_ROOT
printf '%s\\n' "$*" >> "$R/uci-calls"
while [ "${1:-}" = -q ] || [ "${1:-}" = -Q ]; do shift; done
op=$1; shift
[ "$op" != commit ] || { [ "$1" = dhcp ]; exit; }
key=${1%%=*}; value=${1#*=}
case "$key" in 'dhcp.@dnsmasq[0].server') file="$R/state/servers";; 'dhcp.@dnsmasq[0].cachesize') file="$R/state/cachesize";; *) exit 94;; esac
case "$op" in get) cat "$file";; delete) rm -f "$file";; set) printf '%s\\n' "$value" > "$file";; add_list) printf '%s\\n' "$value" >> "$file";; *) exit 95;; esac
'''
        fallback = '''#!/bin/sh
fallback_dns() {
 set_dns "$(printf '%s' "$P0_FIXTURE" | tr ':' '#')" 1500 || return 1
 "$initdir/diversion-dns-c" stop || return 1
 date > "$base/degraded"
}
'''
        scripts = {"init.d/diversion-dns-c": init, "init.d/dnsmasq": init, "bin/uci": uci,
                   "bin/logger": '#!/bin/sh\nprintf "%s\\n" "$*" >> "$P0_ROOT/events.log"\n',
                   "base/dns-mode.sh": fallback}
        scripts["base/apply-policy.sh"] = '''#!/bin/sh
set -eu
printf '%s\\n' apply-policy.sh >> "$P0_ROOT/policy-calls"
for chain in classify split guard router_output router_guard dns_redirect; do
 if nft list chain inet "$DIVERSION_DNS_POLICY_TABLE" "$chain" >/dev/null 2>&1; then
  nft flush chain inet "$DIVERSION_DNS_POLICY_TABLE" "$chain"
 fi
done
nft -c -f "$DIVERSION_DNS_BASE/policy.nft"
nft -f "$DIVERSION_DNS_BASE/policy.nft"
'''
        for name in ("refresh-monitor.sh", "enable-rescue.sh"):
            scripts["base/" + name] = '#!/bin/sh\nprintf "%s\\n" "' + name + '" >> "$P0_ROOT/policy-calls"\nexit 0\n'
        return scripts

    def cleanup_body(self):
        return '''#!/bin/sh
set -u
R=%s
test "$(cat "$R/owner" 2>/dev/null)" = %s || exit 90
for role in guard front app; do
 if [ -f "$R/$role.pid" ]; then
  p=$(cat "$R/$role.pid")
  case "$p" in ''|*[!0-9]*) exit 91;; esac
  if kill -0 "$p" 2>/dev/null; then
   case "$(tr '\\0' ' ' < /proc/$p/cmdline)" in *"$R/"*) kill "$p";; *) exit 92;; esac
  fi
 fi
done
# A timed-out SSH invocation may leave a recovery/init child behind after its
# tracked guard exits. Stop only commands naming this exact owned directory;
# never use a global process name or kill another test's resolver.
owned_command() {
 case "$1" in
  *"$R/base/guard.sh"*|*"$R/base/recover.sh"*|*"$R/base/rollback.sh"*|*"$R/base/cn-data.sh"*|*"$R/base/cn-data.lua"*|*"$R/base/cn-policy.sh"*|*"$R/init.d/"*|"$R/app "*) return 0;;
  *) return 1;;
 esac
}
owned_pids=
for file in /proc/[0-9]*/cmdline; do
 p=${file#/proc/}; p=${p%%/*}
 [ "$p" != "$$" ] && [ "$p" != "$PPID" ] || continue
 cmd=$(tr '\\0' ' ' < "$file" 2>/dev/null) || continue
 if owned_command "$cmd"; then
  printf 'TERM %%s %%s\\n' "$p" "$cmd" >> "$R/cleanup-processes.log"
  kill "$p" 2>/dev/null || true
  owned_pids="$owned_pids $p"
 fi
done
sleep 1
for p in $owned_pids; do
 if [ -f "/proc/$p/cmdline" ]; then
  cmd=$(tr '\\0' ' ' < "/proc/$p/cmdline" 2>/dev/null) || continue
  if owned_command "$cmd"; then kill -KILL "$p" 2>/dev/null || true; fi
 fi
done
sleep 1
for p in $owned_pids; do
 if [ -f "/proc/$p/cmdline" ]; then
  cmd=$(tr '\\0' ' ' < "/proc/$p/cmdline" 2>/dev/null) || continue
  owned_command "$cmd" && exit 96
 fi
done
if [ -f "$R/full-group" ]; then
 G=$(cat "$R/full-group")
 [ "$G" = /sys/fs/cgroup/ddns_p0_full_%s ] || exit 94
 if [ -d "$G" ]; then echo 1 > "$G/cgroup.kill"; rmdir "$G" || exit 95; fi
 rm "$R/full-group"
fi
sleep 1
if [ -f "$R/owns-table" ]; then
 if nft list table inet %s >/dev/null 2>&1; then nft delete table inet %s || exit 93; fi
 rm "$R/owns-table"
fi
date > "$R/cleaned"
''' % (self.root, self.token, self.token, self.table, self.table)

    def data_cases(self):
        with self.case("seed-existing-valid-data") as row:
            self.script("cn-data.sh", "seed", sha(IP1.encode()), sha(SITE1.encode()), timeout=90)
            first = self.current()
            row["generation"] = first
            self.audit()
        invalid = [
            ("empty-ip", "", SITE1), ("empty-site", IP1, ""),
            ("partial-ip", "223.5.5.0/24\n", SITE1), ("partial-site", IP1, "domain:qq.com\n"),
            ("invalid-ip", IP1 + "999.1.1.0/24\n", SITE1),
            ("invalid-site", IP1, SITE1 + "domain:bad..example\n"),
            ("foreign-ip-injection", IP1 + "1.1.1.0/24\n", SITE1),
            ("foreign-site-injection", IP1, SITE1 + "domain:example.com\n"),
            ("broad-ip-injection", IP1 + "0.0.0.0/0\n", SITE1),
        ]
        for name, ip, site in invalid:
            with self.case("reject-" + name) as row:
                self.put("input/ip", ip); self.put("input/site", site)
                result = self.script("cn-data.sh", "stage", self.root + "/input/ip", self.root + "/input/site",
                                     sha(ip.encode()), sha(site.encode()), expected=None, timeout=90)
                require(result["returncode"] != 0, "bad dataset accepted: " + name)
                require(self.current() == first, "invalid stage changed active generation")
                self.audit()
                row["reject_stderr"] = result["stderr"]
        with self.case("reject-hash-mismatch"):
            self.put("input/ip", IP2); self.put("input/site", SITE2)
            result = self.script("cn-data.sh", "stage", self.root + "/input/ip", self.root + "/input/site",
                                 "0" * 64, sha(SITE2.encode()), expected=None, timeout=90)
            require(result["returncode"] != 0 and self.current() == first, "unverified download accepted")
        with self.case("atomic-update-and-explicit-rollback") as row:
            result = self.script("cn-data.sh", "stage", self.root + "/input/ip", self.root + "/input/site",
                                 sha(IP2.encode()), sha(SITE2.encode()), timeout=90)
            second = result["stdout"].strip().splitlines()[-1]
            require(SHA.fullmatch(second) and second != first, "new generation identity invalid")
            self.script("cn-data.sh", "activate", second, timeout=90)
            require(self.current() == second, "update did not activate")
            self.audit(); row["updated_queries"] = self.assert_cn("updated")
            self.script("cn-data.sh", "rollback", timeout=90)
            require(self.current() == first, "rollback did not restore previous dataset")
            self.audit(); row["rollback_queries"] = self.assert_cn("rollback")
        with self.case("failed-restart-rolls-back-data-and-kernel"):
            self.rem("touch " + self.root + "/fail-restart-once")
            result = self.script("cn-data.sh", "activate", second, expected=None, timeout=90)
            require(result["returncode"] != 0 and self.current() == first, "restart failure not rolled back")
            self.audit(); self.assert_cn("restart-rollback")
        with self.case("live-empty-and-partial-set-repair"):
            self.rem("nft flush set inet " + self.table + " cn4; nft flush set inet " + self.table + " cn6")
            self.audit()
            self.rem("nft delete element inet " + self.table + " cn4 '{ 223.5.5.0/24 }'")
            self.audit()
        with self.case("deleted-static-set-repair"):
            self.rem("nft delete set inet " + self.table + " cn6")
            self.audit()
        with self.case("replaced-disk-file-restores-owned-link"):
            self.rem("rm " + self.base + "/cn-site.txt; : > " + self.base + "/cn-site.txt")
            self.audit()
            require(self.rem("readlink " + self.base + "/cn-site.txt")["stdout"].strip() == "cn-data/current/cn-site.txt", "damaged disk link not repaired")
            self.assert_cn("disk-repair")
        with self.case("interrupted-activation-reconciles-after-volatile-state-loss"):
            # Equivalent on-disk interruption point: valid pending(old,new),
            # current=new, kernel=new. Clear only the owned /tmp state dir.
            self.script("cn-data.sh", "activate", second, timeout=90)
            self.rem("printf '%s\\n' '" + first + " " + second + "' > " + self.base + "/cn-data/pending; "
                     "rm -f " + self.root + "/run/state " + self.root + "/run/cn-audit-time")
            self.script("cn-data.sh", "reconcile", timeout=90)
            require(self.current() == first, "pending transaction did not restore known-good generation")
            self.rem("test ! -e " + self.base + "/cn-data/pending")
            self.audit(); self.assert_cn("reconciled")
        with self.case("corrupt-active-snapshot-restores-independent-previous"):
            self.script("cn-data.sh", "activate", second, timeout=90)
            self.rem(": > " + self.generation() + "/cn-site.txt")
            self.audit()
            require(self.current() == first, "corrupt active snapshot not rolled back")
            self.assert_cn("snapshot-repair")
        with self.case("consecutive-snapshot-corruption-retains-independent-recovery") as row:
            for turn in range(2):
                before = self.current()
                previous = self.rem("readlink " + self.base + "/cn-data/previous")["stdout"].strip().split("/")[-1]
                require(SHA.fullmatch(previous) and previous != before, "CN recovery copies alias the same generation")
                self.shell("lua " + self.base + "/cn-data.lua verify " + self.base + "/cn-data/generations/" + previous)
                self.rem(": > " + self.generation() + "/cn-site.txt")
                self.audit()
                after = self.current()
                standby = self.rem("readlink " + self.base + "/cn-data/previous")["stdout"].strip().split("/")[-1]
                require(after != before and SHA.fullmatch(standby) and standby != after,
                        "snapshot recovery did not retain an independent standby")
                self.script("cn-data.sh", "check-start")
                self.shell("lua " + self.base + "/cn-data.lua verify " + self.base + "/cn-data/generations/" + standby)
                row.setdefault("recoveries", []).append(dict(before=before, current=after, previous=standby))
                row.setdefault("queries", []).extend(self.assert_cn("repeat-snapshot-" + str(turn)))

    def guard_cases(self):
        with self.case("foreign-blackhole-preserves-cn-process-and-learning") as row:
            pid = self.rem("cat " + self.root + "/app.pid")["stdout"].strip()
            before_calls = self.rem("cat " + self.root + "/service-calls")["stdout"]
            self.fixture.foreign_ok = False
            for i in range(4):
                self.script("guard.sh", "--once", timeout=30)
                row.setdefault("queries", []).extend(self.assert_cn("foreign-outage-" + str(i)))
            require(self.rem("cat " + self.root + "/app.pid")["stdout"].strip() == pid, "foreign failure restarted/stopped C")
            require(self.rem("cat " + self.root + "/service-calls")["stdout"] == before_calls, "foreign failure invoked DNS service adapter")
            self.rem("test -f " + self.root + "/run/foreign-degraded; test ! -e " + self.base + "/degraded; test ! -e " + self.base + "/recovery-auto")
        with self.case("foreign-recovery-does-not-restart-cn"):
            self.fixture.foreign_ok = True
            self.shell('. "$DIVERSION_DNS_BASE/common.sh"; foreign_health_tick force', timeout=30)
            self.rem("test ! -e " + self.root + "/run/foreign-degraded")
            require(self.rem("cat " + self.root + "/app.pid")["stdout"].strip() == pid, "foreign recovery restarted C")
            self.assert_cn("foreign-recovered")
        with self.case("cn-failure-still-arms-whole-service-fallback"):
            self.fixture.cn_ok = False
            self.shell("sh -c 'trap \"\" HUP; echo $$ > " + self.root + "/guard.pid; exec " + self.base
                       + "/guard.sh' > " + self.root + "/guard.log 2>&1 < /dev/null &")
            deadline = time.monotonic() + 70
            while time.monotonic() < deadline:
                # Fallback probe requires localhost; fixture answers it even
                # during CN failure once fallback action begins below.
                state = self.rem("test -f " + self.base + "/degraded && test \"$(cat " + self.base
                                 + "/recovery-auto 2>/dev/null || true)\" = service-health", expected=None)
                if state["returncode"] == 0:
                    break
                time.sleep(1)
            self.rem("test -f " + self.base + "/degraded; test \"$(cat " + self.base + "/recovery-auto)\" = service-health")
            self.rem("p=$(cat " + self.root + "/guard.pid); kill \"$p\"; rm " + self.root + "/guard.pid")
            deadline = time.monotonic() + 10
            while True:
                ready = self.rem("exec 8>" + self.root + "/deploy.lock; flock -n 8", expected=None)
                if ready["returncode"] == 0:
                    break
                require(time.monotonic() < deadline, "fallback child retained deployment lock")
                time.sleep(.2)
        with self.case("cn-recovery-succeeds-while-foreign-is-still-blackholed"):
            self.fixture.cn_ok = True
            self.fixture.foreign_ok = False
            self.script("recover.sh", "--automatic", timeout=65)
            self.rem("test ! -e " + self.base + "/degraded; test ! -e " + self.base + "/recovering; test ! -e " + self.base + "/recovery-auto")
            self.assert_cn("cn-recovered")
            self.rem("test -f " + self.root + "/run/foreign-degraded")
        self.fixture.foreign_ok = True

    def policy_cases(self):
        with self.case("seed-explicit-owned-chain-baseline"):
            self.script("cn-policy.sh", "seed")
            self.script("cn-policy.sh", "audit-runtime")

        for mode in ("empty", "changed", "missing"):
            with self.case("repair-" + mode + "-owned-chain"):
                if mode == "empty":
                    command = "nft flush chain inet " + self.table + " classify"
                elif mode == "changed":
                    command = "nft add rule inet " + self.table + " classify counter accept"
                else:
                    command = "nft delete chain inet " + self.table + " classify"
                self.rem(command)
                self.script("cn-policy.sh", "audit-runtime")
                self.script("cn-policy.sh", "audit-runtime")
        with self.case("repair-corrupt-owned-policy-source"):
            self.rem(": > " + self.base + "/policy.nft")
            self.script("cn-policy.sh", "audit-runtime")
            self.rem("test -s " + self.base + "/policy.nft")
        with self.case("refuse-untrusted-policy-snapshot"):
            self.rem("cp " + self.base + "/cn-policy/current/policy.nft " + self.root + "/saved-policy; "
                     ": > " + self.base + "/cn-policy/current/policy.nft")
            calls = self.rem("cat " + self.root + "/policy-calls")["stdout"]
            result = self.script("cn-policy.sh", "audit-runtime", expected=None)
            require(result["returncode"] != 0, "corrupt policy snapshot accepted")
            require(calls == self.rem("cat " + self.root + "/policy-calls")["stdout"], "untrusted snapshot invoked apply helper")
            self.rem("cp " + self.root + "/saved-policy " + self.base + "/cn-policy/current/policy.nft")
            self.script("cn-policy.sh", "audit-runtime")
        with self.case("refuse-changed-approved-apply-helper"):
            self.rem("cp " + self.base + "/apply-policy.sh " + self.root + "/saved-helper; "
                     "printf '%s\\n' '# modified' >> " + self.base + "/apply-policy.sh")
            result = self.script("cn-policy.sh", "audit-runtime", expected=None)
            require(result["returncode"] != 0, "modified apply helper executed")
            self.rem("cp " + self.root + "/saved-helper " + self.base + "/apply-policy.sh")
            self.script("cn-policy.sh", "audit-runtime")
        for item in ("apply-policy.sh", "cn-policy/current/policy.nft"):
            with self.case("cn-repair-refuses-unsafe-policy-" + item.split("/")[-1]) as row:
                pid = self.rem("cat " + self.root + "/app.pid")["stdout"].strip()
                calls = self.rem("cat " + self.root + "/service-calls")["stdout"]
                self.rem("cp " + self.base + "/" + item + " " + self.root + "/saved-policy-component; "
                         "printf '%s\\n' '# corrupt' >> " + self.base + "/" + item + "; "
                         "rm " + self.base + "/cn-site.txt; : > " + self.base + "/cn-site.txt")
                result = self.script("cn-data.sh", "audit-runtime", "--force", expected=None, timeout=90)
                require(result["returncode"] != 0, "CN repair bypassed managed policy rejection")
                require(self.rem("cat " + self.root + "/app.pid")["stdout"].strip() == pid, "unsafe policy triggered C restart")
                require(self.rem("cat " + self.root + "/service-calls")["stdout"] == calls, "unsafe policy invoked init service")
                row["cn_during_policy_fault"] = self.assert_cn("unsafe-policy-" + str(len(self.rows)))
                self.rem("cp " + self.root + "/saved-policy-component " + self.base + "/" + item)
                self.audit()
                self.script("cn-policy.sh", "audit-runtime")
                self.assert_cn("safe-policy-" + str(len(self.rows)))
        with self.case("unrecoverable-cn-and-policy-damage-preserves-c-with-rescue") as row:
            current = self.current()
            previous = self.rem("readlink " + self.base + "/cn-data/previous")["stdout"].strip().split("/")[-1]
            require(SHA.fullmatch(previous) and previous != current, "combination test needs two independent generations")
            row["damaged_generations"] = [current, previous]
            self.script("cn-data.sh", "check-start")
            self.shell("lua " + self.base + "/cn-data.lua verify " + self.base + "/cn-data/generations/" + previous)
            pid = self.rem("cat " + self.root + "/app.pid")["stdout"].strip()
            service_calls = self.rem("cat " + self.root + "/service-calls")["stdout"]
            policy_calls = self.rem("cat " + self.root + "/policy-calls")["stdout"].splitlines()
            for label, identity in (("current", current), ("previous", previous)):
                path = self.base + "/cn-data/generations/" + identity + "/sets.nft"
                self.rem("cp " + path + " " + self.root + "/input/combined-" + label + ".sets; : > " + path)
            self.rem("nft flush chain inet " + self.table + " classify")
            result = self.script("cn-data.sh", "audit-runtime", "--force", expected=None, timeout=90)
            require(result["returncode"] != 0, "both invalid CN recovery copies unexpectedly accepted")
            self.script("guard.sh", "--once", timeout=60)
            after_calls = self.rem("cat " + self.root + "/policy-calls")["stdout"].splitlines()
            require(after_calls.count("apply-policy.sh") == policy_calls.count("apply-policy.sh"),
                    "guard policy repair read unverified CN data")
            require(after_calls.count("enable-rescue.sh") > policy_calls.count("enable-rescue.sh"),
                    "guard did not request emergency containment")
            require(self.rem("cat " + self.root + "/app.pid")["stdout"].strip() == pid,
                    "combined data/policy failure restarted or stopped C")
            require(self.rem("cat " + self.root + "/service-calls")["stdout"] == service_calls,
                    "combined data/policy failure changed DNS services")
            self.rem("test ! -e " + self.base + "/degraded; test ! -e " + self.base + "/recovering")
            row["queries_during_failure"] = self.assert_cn("combined-data-policy-failure")
            for label, identity in (("current", current), ("previous", previous)):
                self.rem("cp " + self.root + "/input/combined-" + label + ".sets "
                         + self.base + "/cn-data/generations/" + identity + "/sets.nft")
            self.audit()
            self.script("cn-policy.sh", "audit-runtime")
            repaired_calls = self.rem("cat " + self.root + "/policy-calls")["stdout"].splitlines()
            require(repaired_calls.count("apply-policy.sh") == policy_calls.count("apply-policy.sh") + 1,
                    "healthy CN data did not allow the pending chain repair")
            row["queries_after_repair"] = self.assert_cn("combined-data-policy-recovered")

    def init_cases(self):
        probe = ('. "$DIVERSION_DNS_BASE/diversion-dns-c.init"; '
                 'procd_open_instance() { printf "open %s\\n" "$*" >> "$P0_ROOT/procd-calls"; }; '
                 'procd_set_param() { printf "param %s\\n" "$*" >> "$P0_ROOT/procd-calls"; }; '
                 'procd_close_instance() { printf "close\\n" >> "$P0_ROOT/procd-calls"; }; '
                 'start_service')
        with self.case("real-init-managed-start-does-not-reapply-healthy-policy"):
            calls = self.rem("cat " + self.root + "/policy-calls")["stdout"]
            self.shell(probe)
            require(calls == self.rem("cat " + self.root + "/policy-calls")["stdout"], "init reapplied healthy managed policy")
            self.rem("grep -q '^param command /usr/sbin/diversion-dns-c ' " + self.root + "/procd-calls")
        with self.case("real-init-repairs-empty-chain-with-one-approved-apply"):
            calls = self.rem("cat " + self.root + "/policy-calls")["stdout"].splitlines().count("apply-policy.sh")
            self.rem("nft flush chain inet " + self.table + " classify")
            self.shell(probe)
            after = self.rem("cat " + self.root + "/policy-calls")["stdout"].splitlines().count("apply-policy.sh")
            require(after == calls + 1, "init bypassed/repeated approved policy apply")
        with self.case("real-init-refuses-untrusted-helper-before-procd-dispatch"):
            calls = self.rem("cat " + self.root + "/procd-calls")["stdout"]
            self.rem("cp " + self.base + "/apply-policy.sh " + self.root + "/saved-init-helper; "
                     "printf '%s\\n' '# corrupt' >> " + self.base + "/apply-policy.sh")
            result = self.shell(probe, expected=None)
            require(result["returncode"] != 0, "init accepted modified policy helper")
            require(calls == self.rem("cat " + self.root + "/procd-calls")["stdout"], "unsafe init reached procd dispatch")
            self.rem("cp " + self.root + "/saved-init-helper " + self.base + "/apply-policy.sh")
        with self.case("real-init-managed-recovery-transaction-allows-safe-start"):
            self.rem("mkdir " + self.base + "/recovering; touch " + self.base + "/degraded")
            calls = self.rem("cat " + self.root + "/procd-calls")["stdout"]
            self.shell(probe)
            require(calls != self.rem("cat " + self.root + "/procd-calls")["stdout"], "safe transactional init failed to dispatch")
            self.rem("rmdir " + self.base + "/recovering; rm " + self.base + "/degraded")

    def full_size_cases(self):
        data = self.cfg.get("full_datasets")
        if not data:
            return
        self.shell(self.root + "/init.d/diversion-dns-c stop; " + self.root + "/init.d/dnsmasq stop")
        self.put("input/full-ip", pinned(data["ip"]))
        self.put("input/full-site", pinned(data["site"]))
        group = "/sys/fs/cgroup/ddns_p0_full_" + self.token
        self.rem("grep -qw memory /sys/fs/cgroup/cgroup.subtree_control; test ! -e " + group
                 + "; mkdir " + group + "; printf '%s\\n' " + group + " > " + self.root + "/full-group; echo "
                 + str(int(data.get("memory_limit_mib", 24)) * 1024 * 1024)
                 + " > " + group + "/memory.max; echo 0 > " + group + "/memory.swap.max; echo 1 > "
                 + group + "/memory.oom.group; test -f " + group + "/cgroup.kill")
        try:
            def bounded(name, argv):
                self.rem("rm -f " + self.root + "/full.exit")
                command = ("echo $$ > " + group + "/cgroup.procs; " + shlex.join(argv)
                           + "; rc=$?; echo $rc > " + self.root + "/full.exit")
                prefix = "env " + " ".join(shlex.quote(k + "=" + v) for k, v in self.env.items())
                self.rem(prefix + " sh -c " + shlex.quote("trap '' HUP; " + command)
                         + " > " + self.root + "/full-" + name + ".log 2>&1 < /dev/null &")
                samples, deadline = [], time.monotonic() + 180
                try:
                    while True:
                        result = self.rem("cat " + group + "/memory.current " + group + "/memory.peak; "
                                          "awk '/MemAvailable:/ {print $2}' /proc/meminfo; "
                                          "cat " + self.root + "/full.exit 2>/dev/null || true")["stdout"].splitlines()
                        require(len(result) >= 3, "full dataset resource sample missing")
                        samples.append(dict(memory_current=int(result[0]), memory_peak=int(result[1]),
                                            available_kib=int(result[2]), wall=time.time()))
                        require(int(result[2]) >= 16000, "full dataset resource guard: less than16MiB available")
                        if len(result) > 3:
                            require(result[3] == "0", "full dataset command failed; see device log")
                            break
                        require(time.monotonic() < deadline, "full dataset command exceeded180s")
                        time.sleep(.3)
                    events = self.rem("cat " + group + "/memory.events")["stdout"]
                    require(re.search(r"^oom_kill 0$", events, re.M), "full dataset cgroup reached OOM guard")
                    return dict(samples=samples, memory_events=events)
                finally:
                    save(self.output / ("full-resources-" + name + ".json"), samples)
                    self.rem("echo 1 > " + group + "/cgroup.kill")

            out = self.root + "/full-generation"
            second = self.root + "/full-update"
            self.rem("mkdir " + out + " " + second)
            with self.case("full-111361-site-7510-ip-bootstrap-resource-bound") as row:
                row["resources"] = bounded("prepare", ["lua", self.base + "/cn-data.lua", "prepare",
                    self.root + "/input/full-ip", self.root + "/input/full-site", self.base + "/sets.nft", "-", out,
                    data["ip"]["sha256"], data["site"]["sha256"]])
            with self.case("full-dataset-update-resource-bound") as row:
                row["resources"] = bounded("update", ["lua", self.base + "/cn-data.lua", "prepare",
                    self.root + "/input/full-ip", self.root + "/input/full-site", out + "/sets.nft", out, second,
                    data["ip"]["sha256"], data["site"]["sha256"]])
            with self.case("full-dataset-real-kernel-apply-audit-and-rollback") as row:
                row["apply"] = bounded("repair", ["lua", self.base + "/cn-data.lua", "repair", out])
                row["audit"] = bounded("audit", ["lua", self.base + "/cn-data.lua", "audit", out])
                row["rollback"] = bounded("rollback", ["lua", self.base + "/cn-data.lua", "repair", self.generation()])
        finally:
            self.rem("echo 1 > " + group + "/cgroup.kill; sleep 1; rmdir " + group + "; rm " + self.root + "/full-group")

    def cleanup(self):
        if not self.started:
            return dict(status="not-needed")
        result = dict(status="incomplete", remote_root=self.root)
        try:
            self.rem("sh " + self.root + "/cleanup.sh", timeout=30)
            # Keep logs and snapshots before removing only owned resources.
            self.rem("if [ -f " + self.root + "/watch.pid ]; then p=$(cat " + self.root + "/watch.pid); "
                     "case \"$(tr '\\0' ' ' < /proc/$p/cmdline 2>/dev/null)\" in *'" + self.root + "/'*) kill \"$p\";; esac; fi")
            archive = subprocess.run(self.cfg["target"]["ssh"] + ["tar -czf - -C " + self.root + " ."],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            require(archive.returncode == 0, "remote evidence archive failed")
            (self.output / "device-evidence.tgz").write_bytes(archive.stdout)
            after = self.snapshot()
            save(self.output / "after.json", after)
            require(after["hashes"] == self.before["hashes"], "production hashes changed")
            require(after["tables"] == self.before["tables"], "nft table inventory differs after cleanup")
            self.rem("test \"$(cat " + self.root + "/owner)\" = " + self.token + "; rm -rf " + self.root)
            self.started = False
            result = dict(status="pass", production_hashes_unchanged=True, boot_unchanged=True,
                          table_inventory_unchanged=True, evidence_sha256=sha(archive.stdout))
        except Exception as exc:
            result["error"] = str(exc)
        save(self.output / "cleanup.json", result)
        return result

    def execute(self):
        error = None
        cleanup = {}
        try:
            with Fixture(self.cfg["fixture_address"], self.cfg["fixture_port"], self.cfg["target"]["address"]) as fixture:
                self.fixture = fixture
                self.prepare()
                self.data_cases()
                self.policy_cases()
                self.init_cases()
                self.guard_cases()
                self.full_size_cases()
        except Exception as exc:
            error = str(exc)
        finally:
            if self.fixture:
                save(self.output / "fixture-queries.json", self.fixture.rows)
            cleanup = self.cleanup()
        status = "pass" if not error and cleanup.get("status") == "pass" else "fail"
        result = dict(schema_version=1, status=status, error=error, cases=self.rows, cleanup=cleanup,
                      target=self.cfg["target"]["address"], token=self.token, verification=self.cfg["_verification"],
                      limitations=["No production DNS/UCI/routing or WAN/WG fault injection.",
                                   "Service/UCI adapters and procd dispatch callbacks are fixtures; shipped init control flow, UDP DNS, C processes and nft kernel writes are real.",
                                   "Interruption test reconstructs durable transaction state; no device reboot or power cut.",
                                   "A/AAAA use IPv4 DNS transport; no website or performance acceptance."])
        save(self.output / "result.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    cfg = load_config(args.config)
    require(not args.output.exists(), "preserve old evidence: output already exists")
    args.output.mkdir(parents=True)
    save(args.output / "verification.json", cfg["_verification"])
    if not args.execute:
        save(args.output / "result.json", dict(status="planned", completed=False))
        print("Verified inputs only; no device changes or tests executed.")
        return 2
    result = Suite(cfg, args.output).execute()
    print(json.dumps(dict(status=result["status"], cases=len(result["cases"]), error=result["error"], output=str(args.output))))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
