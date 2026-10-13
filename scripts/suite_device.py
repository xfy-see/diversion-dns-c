#!/usr/bin/env python3
"""Isolated two-device DNS benchmarks, using already authenticated binary receipts.

This adapter never builds, installs an APK, changes production DNS, flushes global
conntrack, or accesses GitHub. First authenticate the CI artifact/source with the
repository's artifact tools. Pin that verification receipt in the configuration;
this adapter rechecks the receipt and every executable's bytes before SSH.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import shlex
import statistics
import subprocess
import time
import uuid

from suite_metrics import measure, window, aggregate

SCHEMA = 1
PROFILES = ('device-smoke', 'device-performance', 'ablation', 'stability')
SCENARIOS = (
    dict(id='cold-udp-a', net='udp', type='A', rate=500, seconds=5, unique=True),
    dict(id='cold-udp-aaaa', net='udp', type='AAAA', rate=500, seconds=5, unique=True),
    dict(id='cold-tcp-mixed', net='tcp', type='mixed', rate=100, seconds=5, unique=True),
    dict(id='hot-tcp-mixed', net='tcp', type='mixed', rate=100, seconds=5, unique=False),
    dict(id='hot-udp-mixed', net='udp', type='mixed', rate=2000, seconds=45, unique=False),
)
UNSENT = {'inflight_limit', 'scheduler_late_over_10ms'}
TOKEN = re.compile(r'[a-f0-9]{16}')
SHA = re.compile(r'[a-f0-9]{64}')
COMMIT = re.compile(r'[a-f0-9]{40}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + '\n')


def pinned_file(record, base):
    require(isinstance(record, dict) and SHA.fullmatch(record.get('sha256', '')),
            'file requires pinned SHA256')
    path = Path(record['path'])
    if not path.is_absolute():
        path = base / path
    require(path.is_file() and not path.is_symlink(), 'missing/symlink file: ' + str(path))
    require(path.stat().st_size <= 400 * 1024 * 1024, 'file exceeds size bound')
    raw = path.read_bytes()
    require(digest(raw) == record['sha256'], 'file SHA256 differs: ' + str(path))
    return path.resolve(), raw


def validate_ssh(host):
    address = str(ipaddress.ip_address(host['address']))
    require(ipaddress.ip_address(address).version == 4, 'device transport currently requires IPv4')
    argv = host['ssh']
    require(isinstance(argv, list) and all(isinstance(x, str) and x for x in argv), 'invalid SSH argv')
    require(argv[0] == 'ssh' and argv[-1] == 'root@' + address, 'SSH destination/address differs')
    opts = {}
    i = 1
    while i < len(argv) - 1:
        arg = argv[i]
        if arg == '-T':
            i += 1
            continue
        require(arg in ('-o', '-F', '-i', '-p') and i + 1 < len(argv) - 1,
                'unsupported SSH option: ' + arg)
        value = argv[i + 1]
        if arg == '-F':
            require(value == '/dev/null', 'SSH must ignore ambient config with -F /dev/null')
        elif arg == '-o':
            key, sep, val = value.partition('=')
            require(sep and key not in opts and key in (
                'BatchMode', 'StrictHostKeyChecking', 'UserKnownHostsFile',
                'GlobalKnownHostsFile', 'IdentitiesOnly', 'ConnectTimeout',
                'ServerAliveInterval', 'ServerAliveCountMax'), 'unsupported/duplicate SSH option')
            opts[key] = val
        elif arg == '-p':
            require(value.isdigit() and 1 <= int(value) <= 65535, 'invalid SSH port')
        i += 2
    require('-F' in argv and argv[argv.index('-F') + 1] == '/dev/null', 'SSH requires -F /dev/null')
    require(opts.get('BatchMode') == 'yes' and opts.get('StrictHostKeyChecking') == 'yes',
            'SSH requires BatchMode=yes and StrictHostKeyChecking=yes')
    require(opts.get('UserKnownHostsFile') not in (None, '', '/dev/null'), 'pinned known_hosts required')
    require(Path(opts['UserKnownHostsFile']).is_file(), 'known_hosts file missing')
    require(opts.get('ConnectTimeout', '').isdigit() and 1 <= int(opts['ConnectTimeout']) <= 15,
            'SSH bounded ConnectTimeout required')
    for key, bound in (('ServerAliveInterval', 15), ('ServerAliveCountMax', 3)):
        require(opts.get(key, '').isdigit() and 1 <= int(opts[key]) <= bound, 'bounded ' + key + ' required')
    files = host.get('production_files')
    require(isinstance(files, list), 'production_files must be explicit (can be empty on generator)')
    for value in files:
        require(isinstance(value, str) and value.startswith('/') and '\n' not in value
                and '\x00' not in value, 'invalid production path')
    require(type(host.get('memory_limit_mib')) is int and 8 <= host['memory_limit_mib'] <= 128,
            'memory_limit_mib must be 8..128')
    require(type(host.get('min_available_kib')) is int and host['min_available_kib'] >= 8000,
            'min_available_kib must be at least 8000')
    require(type(host.get('max_conntrack')) is int and host['max_conntrack'] > 0,
            'max_conntrack required')
    return host


def load_config(path, profile):
    path = Path(path).resolve()
    cfg = read_json(path)
    require(cfg.get('schema_version') == SCHEMA, 'configuration schema_version must be 1')
    require(profile in PROFILES, 'invalid profile')
    for role in ('target', 'client'):
        validate_ssh(cfg[role])
    require(cfg['target']['address'] != cfg['client']['address'], 'target/client must be distinct devices')
    require(cfg['target']['production_files'], 'target production binary/config hash guard required')
    for key in ('listen_port', 'fixture_port'):
        require(type(cfg.get(key)) is int and 1024 <= cfg[key] <= 65535, key + ' must be unprivileged')
    require(cfg['listen_port'] != cfg['fixture_port'], 'test ports must differ')
    require(type(cfg.get('cpu', 4)) is int and 1 <= cfg.get('cpu', 4) <= 4, 'cpu must be 1..4')
    require(type(cfg.get('workers', 32)) is int and 1 <= cfg.get('workers', 32) <= 32, 'workers must be 1..32')
    require(type(cfg.get('repeats', 3)) is int and 3 <= cfg.get('repeats', 3) <= 10,
            'ablation repeats must be 3..10 per direction')
    require(cfg.get('fixture_ttl', 30) == 30, 'fixture TTL must be 30 for post-expiry window')
    versions = cfg.get('versions')
    require(isinstance(versions, list) and 1 <= len(versions) <= 12, 'need 1..12 pinned versions')
    names = set()
    verification = {}
    for version in versions:
        name = version.get('name', '')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}', name) and name not in names,
                'invalid/duplicate version name')
        names.add(name)
        require(COMMIT.fullmatch(version.get('commit', '')), 'full commit required')
        require(type(version.get('run_id')) is int and version['run_id'] > 0, 'run_id required')
        binary, raw = pinned_file(version['binary'], path.parent)
        require(raw.startswith(b'\x7fELF'), 'device binary is not ELF')
        receipt_path, receipt_raw = pinned_file(version['receipt'], path.parent)
        receipt = read_json(receipt_path)
        if version['receipt'].get('key'):
            receipt = receipt[version['receipt']['key']]
        require(receipt.get('source_commit') == version['commit']
                and receipt.get('run_id') == version['run_id']
                and receipt.get('elf_sha256') == digest(raw)
                and receipt.get('source_payload_verified') is True, 'receipt identity/payload differs')
        failure = receipt.get('expected_ablation_ci_failure')
        if not receipt.get('release_verifier_passed'):
            require(profile == 'ablation' and bool(failure)
                    and version.get('allow_expected_ci_failure') == failure,
                    'failed CI artifact requires exact ablation-only exception')
        version['_binary_path'] = str(binary)
        verification[name] = dict(commit=version['commit'], run_id=version['run_id'],
                                  binary_sha256=digest(raw), receipt_sha256=digest(receipt_raw),
                                  receipt_path=str(receipt_path), expected_ci_failure=failure)
    for name in ('load', 'fixture'):
        helper = cfg['helpers'][name]
        helper_path, raw = pinned_file(helper, path.parent)
        require(raw.startswith(b'\x7fELF'), name + ' helper is not ELF')
        helper['_path'] = str(helper_path)
    fixture = cfg['helpers']['fixture']
    require(fixture.get('listen_address') == cfg['client']['address']
            and fixture.get('listen_port') == cfg['fixture_port'] and fixture.get('ttl') == 30,
            'fixture compiled address/port/TTL must match configuration')
    args = fixture.get('command_args', [])
    require(args in ([], ['-addr', cfg['client']['address'] + ':' + str(cfg['fixture_port'])]),
            'fixture args must be empty (fixed bind) or exact -addr endpoint')
    limits = cfg.get('latency_limits_ms', {})
    require(isinstance(limits, dict) and all(k in {x['id'] for x in SCENARIOS} | {'stability-hot-udp-mixed'}
            and type(v) in (int, float) and math.isfinite(v) and v > 0 for k, v in limits.items()), 'invalid latency limits')
    require(type(cfg.get('conntrack_settle_below', 2000)) is int and 1 <= cfg.get('conntrack_settle_below', 2000)
            < cfg['target']['max_conntrack'], 'invalid conntrack settle threshold')
    require(type(cfg.get('conntrack_settle_timeout', 260)) is int and 1 <= cfg.get('conntrack_settle_timeout', 260) <= 600,
            'conntrack settle timeout must be 1..600')
    cfg['_verification'] = verification
    return cfg


def plan(cfg, profile):
    versions = [v['name'] for v in cfg['versions']]
    scenarios = [dict(x) for x in SCENARIOS]
    if profile == 'device-smoke':
        for case in scenarios:
            case.update(rate=20, seconds=1)
    if profile == 'stability':
        scenarios = [dict(id='stability-hot-udp-mixed', net='udp', type='mixed', rate=500,
                          seconds=60, unique=False, chunks=30)]
    orders = [(1, 'forward', versions)]
    if profile == 'ablation':
        orders = [(r, direction, versions if direction == 'forward' else versions[::-1])
                  for r in range(1, cfg.get('repeats', 3) + 1)
                  for direction in ('forward', 'reverse')]
    return [dict(round=r, direction=direction, version=version, **case)
            for r, direction, sequence in orders for version in sequence for case in scenarios]


def pct(values, fraction):
    return sorted(values)[int((len(values) - 1) * fraction)] if values else None


def summarize_raw(raw, spec):
    require(isinstance(raw, dict) and isinstance(raw.get('samples'), list), 'load result missing samples')
    require(raw.get('rate') == spec['rate'] and raw.get('seconds') == spec['seconds']
            and raw.get('net') == spec['net'] and raw.get('query_type') == spec['type'],
            'load scenario identity differs')
    out = measure(raw, spec.get('max_p99_ms'))
    out['functional_pass'] = out['response_success']
    out['strict_rate_pass'] = out['strict_qps_pass']
    if spec['seconds'] >= 45 and not spec['unique']:
        out['first10'] = window(raw, 0, 10)
        out['last10'] = window(raw, spec['seconds'] - 10, spec['seconds'])
    return out


def expected_addresses(samples, unique):
    values = {'cn4': set(), 'cn6': set()}
    for sample in samples:
        if sample.get('error'):
            continue
        name = sample.get('name', '')
        if unique:
            require(re.fullmatch(r'q[0-9]+\.cn\.test', name), 'cold query name differs from fixture contract')
            value = int(name.split('.')[0][1:]) + 1
        else:
            require(name == 'hot.cn.test', 'hot query name differs from fixture contract')
            value = 42
        typ = sample['type']
        require(typ in (1, 28), 'unexpected response question type')
        address = ('198.18.%d.%d' % ((value >> 8) & 255, value & 255)) if typ == 1 else str(
            ipaddress.IPv6Address((0xfdaa << 112) | value))
        values['cn4' if typ == 1 else 'cn6'].add(address)
    return values


def nft_addresses(document, table):
    values = {}
    for item in document.get('nftables', []):
        value = item.get('set', {})
        if value.get('name') not in ('cn4', 'cn6'):
            continue
        name = value['name']
        require(value.get('table') == table and value.get('family') == 'inet' and name not in values,
                'nft set identity differs')
        addresses = []
        for elem in value.get('elem', []):
            addr = elem if isinstance(elem, str) else elem.get('elem', {}).get('val')
            parsed = ipaddress.ip_address(addr)
            require(parsed.version == (4 if name == 'cn4' else 6), 'nft address family differs')
            addresses.append(str(parsed))
        require(len(addresses) == len(set(addresses)), 'duplicate nft element')
        values[name] = set(addresses)
    require(set(values) == {'cn4', 'cn6'}, 'nft set missing')
    return values


def detached_command(script, log_path):
    """BusyBox-compatible detach, preserving ignored HUP across the payload exec."""
    return ('sh -c ' + shlex.quote('trap "" HUP; ' + script) + ' > '
            + shlex.quote(log_path) + ' 2>&1 < /dev/null &')


class SSH:
    def __init__(self, argv):
        self.argv = argv

    def run(self, command, data=None, timeout=30, check=True):
        proc = subprocess.run(self.argv + [command], input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
        if check and proc.returncode:
            raise RuntimeError('SSH command failed (%s): %s' %
                               (proc.returncode, proc.stderr.decode(errors='replace')[-2000:]))
        return proc.stdout.decode(errors='replace')


def paths(token):
    require(TOKEN.fullmatch(token), 'invalid ownership token')
    return '/tmp/ddns-suite-' + token, '/sys/fs/cgroup/ddns_suite_' + token, 'ddns_suite_' + token


def cleanup_script(token):
    root, group, table = paths(token)
    # Never remove another run's lock or delete a table without our ownership marker.
    # Keep the recovery script/owner if kernel resources cannot yet be removed.
    return f'''set -u
R={root}; G={group}; T={table}
if ! test -f "$R/owner"; then
  if test -f /tmp/ddns-suite.lock/owner && test "$(cat /tmp/ddns-suite.lock/owner)" = {token}; then rm /tmp/ddns-suite.lock/owner && rmdir /tmp/ddns-suite.lock; fi
  exit 0
fi
test "$(cat "$R/owner")" = {token} || exit 90
failed=0
if test -d "$G"; then
  if test -f "$G/cgroup.kill"; then echo 1 > "$G/cgroup.kill" || failed=1; fi
  n=0; while test -n "$(cat "$G/cgroup.procs" 2>/dev/null)" && test "$n" -lt 30; do sleep 1; n=$((n+1)); done
  rmdir "$G" || failed=1
fi
if test -f "$R/owns-table"; then
  if nft list table inet "$T" >/dev/null 2>&1; then nft delete table inet "$T" || failed=1; fi
fi
if test -f "$R/enabled-memory" && ! test -d "$G"; then
  other=0; for d in /sys/fs/cgroup/*/memory.max; do test -e "$d" && other=1; done
  if test "$other" -eq 0; then echo -memory > /sys/fs/cgroup/cgroup.subtree_control || failed=1; fi
fi
if test "$failed" -ne 0; then echo RECOVERY_REQUIRED >&2; exit 1; fi
if test -f /tmp/ddns-suite.lock/owner && test "$(cat /tmp/ddns-suite.lock/owner)" = {token}; then rm /tmp/ddns-suite.lock/owner && rmdir /tmp/ddns-suite.lock || exit 1; fi
rm -r "$R"
'''


def watch_script(token, host):
    root, group, _ = paths(token)
    return f'''#!/bin/sh
R={root}; G={group}
while test -f "$R/owner" && test "$(cat "$R/owner")" = {token}; do
  now=$(date +%s); deadline=$(cat "$R/lease")
  mem=$(awk '/MemAvailable:/ {{print $2}}' /proc/meminfo)
  ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
  oom=0
  if test -f "$G/memory.events"; then oom=$(awk '$1 == "oom_kill" {{print $2}}' "$G/memory.events"); fi
  echo "$now $mem $ct $oom"
  if test "$now" -ge "$deadline" || test "$mem" -lt {host['min_available_kib']} || test "$ct" -ge {host['max_conntrack']} || test "$oom" -ne 0; then
    echo SAFETY_STOP
    cp "$R/watch.log" /tmp/ddns-suite-failure-{token}.log 2>/dev/null || true
    echo "SAFETY_STOP now=$now deadline=$deadline mem=$mem conntrack=$ct oom=$oom" >> /tmp/ddns-suite-failure-{token}.log
    if sh "$R/cleanup.sh"; then exit 1; fi
    echo RECOVERY_REQUIRED
    sleep 5
  fi
  sleep 1
done
'''


class DeviceSuite:
    def __init__(self, cfg, output, profile, transport_factory=SSH, sleeper=time.sleep, token=None):
        self.cfg = cfg
        self.output = Path(output)
        self.profile = profile
        self.token = token or uuid.uuid4().hex[:16]
        self.root, self.group, self.table = paths(self.token)
        self.remote = {role: transport_factory(cfg[role]['ssh']) for role in ('target', 'client')}
        self.sleep = sleeper
        self.before = {}
        self.started = []
        self.cases = []
        self.cleanup_results = {}
        self.previous_version_round = None

    def rem(self, role, command, **kwargs):
        started = time.monotonic()
        data = kwargs.get('data')
        if isinstance(data, str):
            data = data.encode()
        record = dict(role=role, command=command,
                      started_utc=datetime.now(timezone.utc).isoformat(),
                      input_bytes=len(data) if data is not None else 0,
                      input_sha256=digest(data) if data is not None else None,
                      timeout_seconds=kwargs.get('timeout', 30), success=False)
        try:
            result = self.remote[role].run(command, **kwargs)
            encoded = result.encode('utf-8')
            record.update(success=True, stdout_utf8_bytes=len(encoded),
                          stdout_utf8_sha256=digest(encoded))
            return result
        except Exception as error:
            record.update(error=str(error), error_type=type(error).__name__)
            raise
        finally:
            record['duration_seconds'] = time.monotonic() - started
            # Only payload size/digest are retained, never binary stdin or stdout.
            with (self.output / 'commands.jsonl').open('a') as log:
                log.write(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')

    def snapshot(self, role, group=False):
        files = self.cfg[role]['production_files']
        cmd = 'set -e; printf "BOOT\\n"; cat /proc/sys/kernel/random/boot_id; printf "HASHES\\n"; '
        if files:
            cmd += 'sha256sum ' + ' '.join(shlex.quote(x) for x in files) + '; '
        cmd += ('printf "MEM\\n"; awk \'/MemAvailable:/ {print $2}\' /proc/meminfo; '
                'printf "CT\\n"; cat /proc/sys/net/netfilter/nf_conntrack_count; '
                'printf "CTMAX\\n"; cat /proc/sys/net/netfilter/nf_conntrack_max; '
                'printf "TABLES\\n"; nft list tables; '
                'printf "ADDRS\\n"; ip -o -4 addr show; printf "KERNEL\\n"; dmesg; '
                'printf "UNAME\\n"; uname -a; printf "CPU\\n"; cat /proc/stat; ')
        if group:
            cmd += ('printf "CGROUP\\n"; cat ' + self.group + '/memory.events ' + self.group + '/memory.current; '
                    + 'printf "PROCESS\\n"; if test -f ' + self.root + '/app.pid; then p=$(cat '
                    + self.root + '/app.pid); cat /proc/$p/status /proc/$p/stat; ls /proc/$p/fd; fi; ')
        raw = self.rem(role, cmd)
        markers = ('BOOT', 'HASHES', 'MEM', 'CT', 'CTMAX', 'TABLES', 'ADDRS', 'KERNEL', 'CGROUP', 'UNAME', 'CPU', 'PROCESS')
        sections = {}
        current = None
        for line in raw.splitlines():
            if line in markers:
                current = line
                sections[current] = []
            elif current:
                sections[current].append(line)
        require(len(sections.get('BOOT', [])) == 1, 'boot ID unavailable')
        for key in ('MEM', 'CT', 'CTMAX'):
            require(len(sections.get(key, [])) == 1 and sections[key][0].isdigit(), key + ' unavailable')
        result = dict(raw=raw, boot=sections['BOOT'][0], hashes=sections.get('HASHES', []),
                      memory_available_kib=int(sections['MEM'][0]), conntrack=int(sections['CT'][0]),
                      conntrack_max=int(sections['CTMAX'][0]), tables=sections.get('TABLES', []),
                      kernel=sections.get('KERNEL', []), cgroup=sections.get('CGROUP', []),
                      uname=sections.get('UNAME', []), cpu=sections.get('CPU', []), process=sections.get('PROCESS', []))
        address = self.cfg[role]['address']
        require(any('inet ' + address + '/' in x for x in sections.get('ADDRS', [])), 'SSH host lacks configured address')
        require(len(result['hashes']) == len(files), 'production hash count differs')
        require(result['memory_available_kib'] >= self.cfg[role]['min_available_kib'], 'low available memory')
        require(result['conntrack'] < self.cfg[role]['max_conntrack'] < result['conntrack_max'], 'conntrack safety limit invalid/exceeded')
        if group:
            require('oom_kill 0' in result['cgroup'], 'cgroup OOM detected')
        if role in self.before:
            require(result['boot'] == self.before[role]['boot'], 'device rebooted; abort')
            require(result['hashes'] == self.before[role]['hashes'], 'production file hash changed; abort')
            previous = self.before[role]['kernel']
            require(result['kernel'][:len(previous)] == previous, 'kernel log rotated/cleared; cannot compare safely')
            new_kernel = result['kernel'][len(previous):]
            require(not any(re.search(r'out of memory|oom-kill|segfault|kernel panic', x, re.I)
                            for x in new_kernel), 'new kernel fault; abort')
        return result

    def put(self, role, name, raw, executable=False):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', name), 'invalid staged filename')
        target = self.root + '/' + name
        self.rem(role, 'set -e; test "$(cat ' + self.root + '/owner)" = ' + self.token
                 + '; cat > ' + target, data=raw)
        value = self.rem(role, 'sha256sum ' + target).split()[0]
        require(value == digest(raw), 'remote staged hash differs: ' + name)
        if executable:
            self.rem(role, 'chmod 700 ' + target)

    def renew(self):
        for role in self.started:
            self.rem(role, 'set -e; test "$(cat ' + self.root + '/owner)" = ' + self.token
                     + '; echo $(( $(date +%s) + 120 )) > ' + self.root + '/lease')

    def prepare(self):
        # All read-only preflights happen before touching either device.
        for role in ('target', 'client'):
            state = self.snapshot(role)
            self.before[role] = state
            write_json(self.output / ('before-' + role + '.json'), state)
            port = self.cfg['listen_port'] if role == 'target' else self.cfg['fixture_port']
            self.rem(role, 'set -e; test ! -e ' + self.root + '; test ! -e ' + self.group
                     + '; test ! -e /tmp/ddns-suite.lock; test -e /sys/fs/cgroup/cgroup.controllers; '
                     + 'command -v nft >/dev/null; command -v sh >/dev/null; command -v netstat >/dev/null; '
                     + 'test -z "$(netstat -ln 2>/dev/null | awk \'$4 ~ /:' + str(port) + '$/ {print}\')"')
        require(self.before['target']['boot'] != self.before['client']['boot'], 'SSH aliases point to same machine')
        for role in ('target', 'client'):
            self.started.append(role)  # finally must clean partial staging too.
            host = self.cfg[role]
            recovery = shlex.quote(cleanup_script(self.token))
            watcher = shlex.quote(watch_script(self.token, host))
            detached_watch = detached_command('exec sh ' + self.root + '/watch.sh', self.root + '/watch.log')
            self.rem(role, f'''set -eu
mkdir -m700 /tmp/ddns-suite.lock
echo {self.token} > /tmp/ddns-suite.lock/owner
mkdir -m700 {self.root}
echo {self.token} > {self.root}/owner
printf '%s' {recovery} > {self.root}/cleanup.sh
printf '%s' {watcher} > {self.root}/watch.sh
trap 'sh {self.root}/cleanup.sh' EXIT HUP INT TERM
echo $(( $(date +%s) + 120 )) > {self.root}/lease
{detached_watch}
if ! grep -qw memory /sys/fs/cgroup/cgroup.subtree_control; then
  touch {self.root}/enabled-memory
  echo +memory > /sys/fs/cgroup/cgroup.subtree_control
fi
mkdir {self.group}
echo {host['memory_limit_mib'] * 1024 * 1024} > {self.group}/memory.max
echo 0 > {self.group}/memory.swap.max
echo 1 > {self.group}/memory.oom.group
test -f {self.group}/cgroup.kill
trap - EXIT HUP INT TERM
''')
        for version in self.cfg['versions']:
            raw = Path(version['_binary_path']).read_bytes()
            require(digest(raw) == version['binary']['sha256'], 'binary changed after verification')
            self.put('target', version['name'], raw, True)
            self.renew()
        for name in ('load', 'fixture'):
            raw = Path(self.cfg['helpers'][name]['_path']).read_bytes()
            require(digest(raw) == self.cfg['helpers'][name]['sha256'], 'helper changed after verification')
            self.put('client', name, raw, True)
        self.put('target', 'cn.txt', b'domain:cn.test\n')
        self.rem('target', 'set -e; if nft list table inet ' + self.table
                 + ' >/dev/null 2>&1; then exit 92; fi; touch ' + self.root
                 + '/owns-table; nft add table inet ' + self.table + '; nft add set inet ' + self.table
                 + ' cn4 "{ type ipv4_addr; flags timeout; size 16384; }"; nft add set inet '
                 + self.table + ' cn6 "{ type ipv6_addr; flags timeout; size 16384; }"')
        address = self.cfg['target']['address'] + ':' + str(self.cfg['listen_port'])
        upstream = self.cfg['client']['address'] + ':' + str(self.cfg['fixture_port'])
        conf = '\n'.join(('listen_udp=' + address, 'listen_tcp=' + address, 'cache_size=8192',
                          'nftset_ipv4=inet,' + self.table + ',cn4,ipv4_addr,32',
                          'nftset_ipv6=inet,' + self.table + ',cn6,ipv6_addr,128',
                          'nftset_fast=1', 'cn_domain_file=' + self.root + '/cn.txt',
                          'cn_upstream=' + upstream, 'foreign_upstream=' + upstream, ''))
        self.put('target', 'config.conf', conf.encode())
        self.start('client', 'fixture', [self.root + '/fixture'] + self.cfg['helpers']['fixture'].get('command_args', []))

    def launch_prefix(self):
        return ('set -eu; test "$(cat ' + self.root + '/owner)" = ' + self.token
                + '; test "$(date +%s)" -lt "$(cat ' + self.root + '/lease)"; echo $$ > '
                + self.group + '/cgroup.procs; grep -Fx ' + shlex.quote('0::/' + self.group.rsplit('/', 1)[1])
                + ' /proc/$$/cgroup >/dev/null; ')

    def start(self, role, name, argv):
        command = shlex.join(argv)
        script = self.launch_prefix() + 'echo $$ > ' + self.root + '/' + name + '.pid; exec ' + command
        self.rem(role, detached_command(script, self.root + '/' + name + '.log'))
        self.sleep(.3)
        self.rem(role, 'set -e; p=$(cat ' + self.root + '/' + name + '.pid); kill -0 "$p"; '
                 + 'test "$(readlink /proc/$p/exe)" = ' + shlex.quote(argv[0]) + '; grep -Fx '
                 + shlex.quote('0::/' + self.group.rsplit('/', 1)[1]) + ' /proc/$p/cgroup >/dev/null')

    def stop_app(self):
        self.rem('target', f'''set -eu
p=$(cat {self.root}/app.pid)
test "$(readlink /proc/$p/exe)" = "{self.root}/$(cat {self.root}/active-version)"
kill -TERM "$p"
n=0; while kill -0 "$p" 2>/dev/null; do
  test "$n" -lt 5 || exit 91
  sleep 1; n=$((n+1))
done
rm {self.root}/app.pid
''')

    def query(self, spec, path):
        self.renew()
        argv = [self.root + '/load', '-addr', self.cfg['target']['address'] + ':' + str(self.cfg['listen_port']),
                '-net', spec['net'], '-type', spec['type'], '-rate', str(spec['rate']),
                '-seconds', str(spec['seconds']), '-workers', str(self.cfg.get('workers', 32))]
        argv += ['-unique', '-offset', '20000'] if spec['unique'] else ['-name', 'hot.cn.test']
        command = self.launch_prefix() + 'exec ' + shlex.join(argv)
        raw = self.rem('client', command, timeout=spec['seconds'] + 20)
        Path(path).write_text(raw)
        result = json.loads(raw)
        return summarize_raw(result, spec)

    def settle(self, folder):
        deadline = time.monotonic() + self.cfg.get('conntrack_settle_timeout', 260)
        snapshots = []
        try:
            while True:
                self.renew()
                states = {role: self.snapshot(role, True) for role in ('target', 'client')}
                snapshots.append(states)
                if states['target']['conntrack'] < self.cfg.get('conntrack_settle_below', 2000):
                    return
                require(time.monotonic() < deadline, 'conntrack did not settle; abort without flushing')
                self.sleep(2)
        finally:
            write_json(folder / 'settling.json', snapshots)

    def run_case(self, spec, index):
        folder = self.output / ('%04d-%s-%s-%s' % (index, spec['direction'], spec['version'], spec['id']))
        folder.mkdir()
        row = dict(id=spec['id'], round=spec['round'], direction=spec['direction'], version=spec['version'],
                   status='incomplete', raw_path=str(folder / 'raw.json'), assertions={})
        self.cases.append(row)
        version_round = (spec['round'], spec['direction'], spec['version'])
        if version_round != self.previous_version_round:
            self.settle(folder)
            self.previous_version_round = version_round
        spec = dict(spec, max_p99_ms=self.cfg.get('latency_limits_ms', {}).get(spec['id']))
        self.renew()
        self.rem('target', 'set -e; nft flush set inet ' + self.table + ' cn4; nft flush set inet '
                 + self.table + ' cn6; echo ' + spec['version'] + ' > ' + self.root + '/active-version')
        self.start('target', 'app', [self.root + '/' + spec['version'], 'start', '-c',
                                    self.root + '/config.conf', '--cpu', str(self.cfg.get('cpu', 4))])
        try:
            if not spec['unique']:
                warm = dict(net='udp', type='mixed', rate=2, seconds=1, unique=False)
                require(self.query(warm, folder / 'warmup.json')['strict_rate_pass'], 'cache warmup failed')
            chunks = []
            started = time.monotonic()
            for chunk in range(spec.get('chunks', 1)):
                before = {role: self.snapshot(role, True) for role in ('target', 'client')}
                filename = 'raw.json' if spec.get('chunks', 1) == 1 else 'raw-%03d.json' % chunk
                metrics = self.query(spec, folder / filename)
                after = {role: self.snapshot(role, True) for role in ('target', 'client')}
                write_json(folder / ('state-%03d.json' % chunk), dict(before=before, after=after))
                metrics['conntrack_delta'] = after['target']['conntrack'] - before['target']['conntrack']
                metrics['raw_path'] = str(folder / filename)
                chunks.append(metrics)
                row['metrics'] = metrics if spec.get('chunks', 1) == 1 else {'chunks': chunks}
                require(metrics['functional_pass'], 'DNS response error (raw evidence retained)')
            row['metrics'] = chunks[0] if len(chunks) == 1 else dict(
                chunks=chunks, process_restarted_between_chunks=False,
                load_seconds=spec['seconds'] * len(chunks), wall_seconds=time.monotonic()-started,
                note='Same server process; client connections restart between chunks, with monitoring gaps.')
            if len(chunks) > 1:
                row['raw_path'] = [x['raw_path'] for x in chunks]
            sets = json.loads(self.rem('target', 'nft -j list table inet ' + self.table))
            write_json(folder / 'sets.json', sets)
            actual = nft_addresses(sets, self.table)
            samples = read_json(folder / ('raw.json' if len(chunks) == 1 else 'raw-000.json'))['samples']
            expected = expected_addresses(samples, spec['unique'])
            counts = {name: len(values) for name, values in actual.items()}
            set_pass = actual == expected
            write_json(folder / 'set-audit.json', dict(
                expected={k: sorted(v) for k,v in expected.items()},
                actual={k: sorted(v) for k,v in actual.items()}, exact_match=set_pass))
            row['assertions'] = dict(functional_pass=all(x['functional_pass'] for x in chunks),
                                     strict_rate_pass=all(x['strict_rate_pass'] for x in chunks),
                                     nftset_exact_addresses_pass=set_pass, nftset_counts=counts,
                                     latency_pass=(all(x['latency_pass'] for x in chunks) if spec.get('max_p99_ms') else None))
            row['status'] = 'pass' if all(row['assertions'][x] for x in (
                'functional_pass', 'strict_rate_pass', 'nftset_exact_addresses_pass')) and row['assertions']['latency_pass'] is not False else 'fail'
            write_json(folder / 'result.json', row)
        finally:
            try:
                (folder / 'app.log').write_text(self.rem('target', 'cat ' + self.root + '/app.log'))
            finally:
                self.stop_app()

    def cleanup(self):
        for role in reversed(self.started):
            try:
                # Preserve watcher output before the owned directory is removed.
                (self.output / ('watch-' + role + '.log')).write_text(
                    self.rem(role, 'cat ' + self.root + '/watch.log 2>/dev/null || true'))
                event = self.rem(role, 'cat /tmp/ddns-suite-failure-' + self.token + '.log 2>/dev/null || true')
                if event:
                    (self.output / ('safety-event-' + role + '.log')).write_text(event)
                self.rem(role, cleanup_script(self.token), timeout=45)
                if event:
                    self.rem(role, 'rm /tmp/ddns-suite-failure-' + self.token + '.log')
                after = self.snapshot(role)
                require(after['tables'] == self.before[role]['tables'], 'nft table inventory differs after cleanup')
                self.rem(role, 'test ! -e ' + self.root + '; test ! -e ' + self.group
                         + '; test ! -e /tmp/ddns-suite.lock')
                write_json(self.output / ('after-' + role + '.json'), after)
                self.cleanup_results[role] = dict(status='pass', boot_and_production_hashes_unchanged=True,
                                                  owned_resources_removed=True, safety_event=event or None)
                require(not event, 'remote watchdog stopped load; see safety-event-' + role + '.log')
            except Exception as error:
                self.cleanup_results[role] = dict(status='incomplete', error=str(error),
                                                  remote_lease_seconds=120,
                                                  manual_recovery_may_be_required=True,
                                                  recovery_script=cleanup_script(self.token))
        write_json(self.output / 'cleanup.json', self.cleanup_results)

    def execute(self):
        error = None
        try:
            self.prepare()
            for index, spec in enumerate(plan(self.cfg, self.profile)):
                self.run_case(spec, index)
                write_json(self.output / 'progress.json', self.cases)
        except Exception as exc:
            error = str(exc)
        finally:
            self.cleanup()
        complete = len(self.cases) == len(plan(self.cfg, self.profile)) and all(
            x['status'] != 'incomplete' for x in self.cases)
        clean = len(self.cleanup_results) == 2 and all(x['status'] == 'pass' for x in self.cleanup_results.values())
        status = 'incomplete' if error or not complete or not clean else (
            'pass' if all(x['status'] == 'pass' for x in self.cases) else 'fail')
        groups = {}
        aggregate_rows = []
        for row in self.cases:
            m = row.get('metrics', {})
            if m.get('p99_ms') is not None:
                groups.setdefault(row['version'] + '/' + row['id'], []).append(m['p99_ms'])
                spec = next(x for x in plan(self.cfg, self.profile) if x['id'] == row['id'])
                aggregate_rows.append(dict(version=row['version'], scenario=row['id'], rate=spec['rate'],
                                           seconds=spec['seconds'], workers=self.cfg.get('workers', 32),
                                           repeat=row['round'], direction=row['direction'], metrics=m,
                                           case_pass=(row['status'] == 'pass')))
        if not clean and self.started:
            self.cases.append(dict(id='device-cleanup-audit', status='incomplete', raw_path=str(self.output/'cleanup.json')))
        return dict(schema_version=SCHEMA, status=status, completed=complete and clean and not error,
                    identity=dict(commits=[v['commit'] for v in self.cfg['versions']],
                                  target_address=self.cfg['target']['address'], client_address=self.cfg['client']['address'],
                                  boot_ids={k:v['boot'] for k,v in self.before.items()}, token=self.token),
                    profile=self.profile, cases=self.cases,
                    error=error, cleanup=self.cleanup_results,
                    p99_medians={k: statistics.median(v) for k, v in groups.items()},
                    aggregate=aggregate(aggregate_rows, self.cfg.get('repeats', 3)),
                    verification=self.cfg['_verification'],
                    limitations=['LAN synthetic DNS fixture, not public website/WebSocket acceptance.',
                                 'A/AAAA records use IPv4 transport; IPv6 transport is not covered.',
                                 'Conntrack values are global net changes, not exact new-socket counts.',
                                 'Warm TCP includes client connection setup; cold TCP uses unique names.',
                                 'Strict-rate pass requires every offered slot to be sent and answered.'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=PROFILES, default='device-smoke')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--execute', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config, args.profile)
        require(not args.output.exists(), 'output directory already exists; preserve previous evidence')
        args.output.mkdir(parents=True)
        planned = dict(schema_version=SCHEMA, status='planned', profile=args.profile,
                       cases=[dict(**case, status='planned') for case in plan(cfg, args.profile)],
                       verification=cfg['_verification'])
        write_json(args.output / 'plan.json', planned)
        result = DeviceSuite(cfg, args.output, args.profile).execute() if args.execute else planned
        write_json(args.output / 'result.json', result)
        print(json.dumps(dict(status=result['status'], cases=len(result['cases']),
                              output=str(args.output / 'result.json'))))
        return 0 if result['status'] == 'pass' else (2 if result['status'] == 'planned' else 1)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    raise SystemExit(main())
