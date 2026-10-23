"""Pure Python safety/contract tests. No SSH or target executable is launched."""
import copy
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import suite_device as device


def load_result(spec, error=None):
    n = spec['rate'] * spec['seconds']
    samples = []
    for i in range(n):
        typ = 1 if spec['type'] == 'A' or (spec['type'] == 'mixed' and i % 2 == 0) else 28
        samples.append(dict(i=i, ms=1.0, late_ms=0.01, type=typ,
                            name='q%d.cn.test' % (i+20000) if spec.get('unique') else 'hot.cn.test'))
    errors = {}
    if error:
        samples[-1]['error'] = error
        errors[error] = 1
    missed = int(error in device.UNSENT)
    return dict(rate=spec['rate'], seconds=spec['seconds'], net=spec['net'], query_type=spec['type'],
                offered=n, sent=n-missed, success=n-int(bool(error)), unsent=missed,
                errors=errors, samples=samples)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'known_hosts').write_text('test host key fixture\n')
        binary = b'\x7fELFtest-target'
        (self.root / 'binary').write_bytes(binary)
        receipt = {'V0': dict(source_commit='a'*40, run_id=123, elf_sha256=device.digest(binary),
                              source_payload_verified=True, release_verifier_passed=True)}
        self.receipt = receipt
        (self.root / 'receipt.json').write_text(json.dumps(receipt))
        for n in ('load', 'fixture'):
            (self.root / n).write_bytes(b'\x7fELF' + n.encode())
        def file(n):
            return dict(path=n, sha256=device.digest((self.root / n).read_bytes()))
        def host(address, production):
            return dict(address=address, ssh=['ssh', '-T', '-F', '/dev/null',
                '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + str(self.root / 'known_hosts'),
                '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5',
                '-o', 'ServerAliveCountMax=2', 'root@' + address], production_files=production,
                memory_limit_mib=24, min_available_kib=8000, max_conntrack=12000)
        self.cfg = dict(schema_version=1, target=host('192.168.50.122', ['/usr/sbin/app', '/etc/app.conf']),
            client=host('192.168.50.131', []), listen_port=15491, fixture_port=15531,
            fixture_ttl=30, cpu=4, workers=32, repeats=3,
            versions=[dict(name='V0', commit='a'*40, run_id=123, binary=file('binary'),
                           receipt=dict(**file('receipt.json'), key='V0'))],
            helpers=dict(load=file('load'), fixture=dict(**file('fixture'),
                listen_address='192.168.50.131', listen_port=15531, ttl=30, command_args=[])))

    def read(self, profile='device-smoke'):
        path = self.root / 'config.json'
        path.write_text(json.dumps(self.cfg))
        return device.load_config(path, profile)

    def test_pinned_bytes_and_receipt_match(self):
        self.assertEqual(self.read()['_verification']['V0']['run_id'], 123)

    def test_modified_binary_rejected(self):
        (self.root / 'binary').write_bytes(b'\x7fELFtampered')
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            self.read()

    def test_modified_receipt_rejected(self):
        (self.root / 'receipt.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            self.read()

    def test_receipt_identity_not_just_hash(self):
        self.cfg['versions'][0]['commit'] = 'b'*40
        with self.assertRaisesRegex(ValueError, 'receipt identity'):
            self.read()

    def test_production_files_required(self):
        self.cfg['target']['production_files'] = []
        with self.assertRaisesRegex(ValueError, 'production binary/config'):
            self.read()

    def test_fixed_fixture_bind_required(self):
        self.cfg['helpers']['fixture']['listen_port'] = 16000
        with self.assertRaisesRegex(ValueError, 'compiled address'):
            self.read()

    def test_fixture_flag_matches_bind(self):
        self.cfg['helpers']['fixture']['command_args'] = ['-addr', '192.168.50.131:15531']
        self.read()
        self.cfg['helpers']['fixture']['command_args'] = ['-addr', '0.0.0.0:53']
        with self.assertRaisesRegex(ValueError, 'fixture args'):
            self.read()

    def test_strict_host_keys(self):
        argv = self.cfg['target']['ssh']
        argv[argv.index('StrictHostKeyChecking=yes')] = 'StrictHostKeyChecking=no'
        with self.assertRaisesRegex(ValueError, 'StrictHostKeyChecking'):
            self.read()

    def test_no_ambient_ssh_config(self):
        self.cfg['target']['ssh'][3] = '/etc/ssh/config'
        with self.assertRaisesRegex(ValueError, 'ambient config'):
            self.read()

    def test_ssh_proxy_command_rejected(self):
        self.cfg['target']['ssh'][1:1] = ['-o', 'ProxyCommand=arbitrary-shell']
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            self.read()

    def test_same_device_rejected(self):
        self.cfg['client'] = copy.deepcopy(self.cfg['target'])
        with self.assertRaisesRegex(ValueError, 'distinct'):
            self.read()

    def test_symlink_binary_rejected(self):
        (self.root / 'link').symlink_to(self.root / 'binary')
        self.cfg['versions'][0]['binary']['path'] = 'link'
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.read()

    def test_failed_ci_explicit_ablation_exception_only(self):
        self.receipt['V0'].update(release_verifier_passed=False, expected_ablation_ci_failure='known qemu failure')
        raw = json.dumps(self.receipt).encode()
        (self.root / 'receipt.json').write_bytes(raw)
        self.cfg['versions'][0]['receipt']['sha256'] = device.digest(raw)
        with self.assertRaisesRegex(ValueError, 'ablation-only'):
            self.read('ablation')
        self.cfg['versions'][0]['allow_expected_ci_failure'] = 'known qemu failure'
        self.read('ablation')
        with self.assertRaisesRegex(ValueError, 'ablation-only'):
            self.read('device-smoke')

    def test_dry_run_never_opens_ssh(self):
        self.read()
        with mock.patch.object(device.subprocess, 'run', side_effect=AssertionError('network called')):
            rc = device.main(['--config', str(self.root/'config.json'), '--output', str(self.root/'out')])
        self.assertEqual(rc, 2)
        result = device.read_json(self.root/'out/result.json')
        self.assertEqual(result['status'], 'planned')
        self.assertEqual(len(result['cases']), 5)

    def test_dry_run_preserves_existing_evidence(self):
        self.read()
        (self.root/'out').mkdir()
        (self.root/'out/kept').write_text('raw')
        with self.assertRaises(SystemExit):
            device.main(['--config', str(self.root/'config.json'), '--output', str(self.root/'out')])
        self.assertEqual((self.root/'out/kept').read_text(), 'raw')


class PlanAndMetricsTests(unittest.TestCase):
    def test_detached_shell_ignores_hup_without_nohup(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'survived'
            log = Path(folder) / 'detached.log'
            script = 'kill -HUP $$; printf survived > ' + shlex.quote(str(marker))
            command = device.detached_command(script, str(log))
            self.assertNotIn('nohup', command)
            self.assertIn('2>&1 < /dev/null &', command)
            subprocess.run(['sh', '-c', command], check=True, timeout=5, capture_output=True)
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(marker.read_text(), 'survived')

    def test_six_versions_three_forward_reverse_rounds(self):
        cfg = dict(versions=[dict(name=n) for n in ('V0','P7','A1','A2','A3','P8')], repeats=3)
        rows = device.plan(cfg, 'ablation')
        self.assertEqual(len(rows), 180)
        self.assertEqual(rows[0]['version'], 'V0')
        self.assertEqual(rows[30]['version'], 'P8')
        self.assertTrue(all(sum(r['version']==n and r['id']==scenario['id'] for r in rows)==6
                            for n in ('V0','P7','A1','A2','A3','P8') for scenario in device.SCENARIOS))

    def test_tcp_cold_and_hot_distinct(self):
        rows = device.plan(dict(versions=[dict(name='V0')]), 'device-performance')
        cold, hot = rows[2:4]
        self.assertEqual((cold['net'],cold['rate'],cold['seconds'],cold['unique']), ('tcp',100,5,True))
        self.assertFalse(hot['unique'])

    def test_stability_same_server_30_chunks(self):
        rows = device.plan(dict(versions=[dict(name='V0')]), 'stability')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['seconds'] * rows[0]['chunks'],1800)

    def test_missed_slot_is_not_strict_pass(self):
        spec = dict(device.SCENARIOS[0], rate=2,seconds=1)
        out = device.summarize_raw(load_result(spec,'inflight_limit'),spec)
        self.assertTrue(out['functional_pass'])
        self.assertFalse(out['strict_rate_pass'])
        self.assertEqual(out['unsent'],1)

    def test_reply_error_functional_failure(self):
        spec = dict(device.SCENARIOS[0], rate=2,seconds=1)
        out = device.summarize_raw(load_result(spec,'rcode_2'),spec)
        self.assertFalse(out['functional_pass'])

    def test_histogram_lie_rejected(self):
        spec = dict(device.SCENARIOS[0], rate=2,seconds=1)
        raw = load_result(spec,'inflight_limit');raw['errors']={}
        with self.assertRaisesRegex(ValueError,'histogram'):
            device.summarize_raw(raw,spec)

    def test_hot_post_refresh_windows_are_auxiliary(self):
        spec=dict(device.SCENARIOS[-1],rate=2)
        out=device.summarize_raw(load_result(spec),spec)
        self.assertEqual(out['last10']['start_seconds'],35)
        self.assertTrue(out['last10']['auxiliary'])
        self.assertFalse(out['last10']['replaces_full_run'])

    def test_cleanup_is_owned_and_bounded(self):
        command=device.cleanup_script('abcdef1234567890')
        self.assertIn('test "$(cat "$R/owner")" = abcdef1234567890',command)
        self.assertIn('nft delete table inet "$T"',command)
        self.assertNotIn('flush ruleset',command)
        self.assertNotIn('conntrack -F',command)
        self.assertNotIn('killall',command)
        self.assertNotIn('pkill',command)
        self.assertNotIn('/usr/sbin/',command)
        with self.assertRaisesRegex(ValueError,'ownership token'):
            device.cleanup_script('../bad')

    def test_shell_scripts_parse(self):
        token='abcdef1234567890'
        for script in (device.cleanup_script(token),device.watch_script(token,dict(min_available_kib=8000,max_conntrack=12000))):
            # Only the local shell parser is used: no shell statements execute.
            subprocess.run(['sh','-n'],input=script.encode(),check=True,capture_output=True)


class FakeSSH:
    """Models SSH responses, records mutations; executes no shell or target code."""
    def __init__(self, argv, cfg, state):
        self.role='target' if argv[-1].endswith('.122') else 'client'
        self.cfg=cfg
        self.state=state
        self.files={}

    def run(self, command, data=None, timeout=30, check=True):
        self.state['commands'].append((self.role,command))
        if 'printf "BOOT' in command:
            hashes=''.join('a'*64+'  '+p+'\n' for p in self.cfg[self.role]['production_files'])
            cg='CGROUP\noom_kill 0\n100000\n' if 'printf "CGROUP' in command else ''
            return ('BOOT\nboot-'+self.role+'\nHASHES\n'+hashes+'MEM\n65000\nCT\n100\nCTMAX\n15360\n'
                    'TABLES\ntable inet fw4\nADDRS\n2: eth0 inet '+self.cfg[self.role]['address']+'/24\nKERNEL\n'+self.state.get('kernel','boot ok')+'\n'+cg)
        if data is not None:
            self.files[command.split('cat > ')[-1]]=data
        if command.startswith('sha256sum '):
            return device.digest(self.files[command.split(' ',1)[1]])+'  file\n'
        if '/load -addr' in command:
            if self.state.get('fail_load'):
                raise RuntimeError('simulated disconnected SSH')
            args=shlex.split(command.split('exec ',1)[1])
            arg=lambda n:args[args.index(n)+1]
            spec=dict(net=arg('-net'),type=arg('-type'),rate=int(arg('-rate')),seconds=int(arg('-seconds')),
                      unique='-unique' in args)
            self.state['last_spec']=spec
            return json.dumps(load_result(spec))
        if command.startswith('nft -j list table'):
            spec=self.state['last_spec'];n=spec['rate']*spec['seconds']
            addresses=device.expected_addresses(load_result(spec)['samples'],spec['unique'])
            table=command.rsplit(' ',1)[1]
            return json.dumps({'nftables':[{'set':dict(name=name,table=table,family='inet',elem=sorted(addresses[name]))}
                                          for name in ('cn4','cn6')]})
        return ''


class FakeTransportTests(unittest.TestCase):
    setUp = ConfigTests.setUp
    read = ConfigTests.read

    def suite(self, fail_load=False):
        cfg=self.read();out=self.root/'run';out.mkdir()
        state=dict(commands=[],fail_load=fail_load)
        factory=lambda argv:FakeSSH(argv,cfg,state)
        suite=device.DeviceSuite(cfg,out,'device-smoke',factory,sleeper=lambda n:None,token='a'*16)
        return suite,state

    def test_full_fake_run_five_cases_and_cleanup(self):
        suite,state=self.suite()
        result=suite.execute()
        self.assertEqual(result['status'],'pass',result.get('error'))
        self.assertEqual(len(result['cases']),5)
        self.assertTrue(all(v['status']=='pass' for v in result['cleanup'].values()))
        commands='\n'.join(command for role,command in state['commands'])
        self.assertEqual(commands.count('nft flush set inet '+suite.table+' cn4'),5)
        self.assertNotIn('nohup',commands)
        self.assertIn('trap "" HUP',commands)
        self.assertIn('command -v netstat',commands)
        self.assertIn('/cleanup.sh',commands)
        self.assertNotIn('flush ruleset',commands)
        self.assertNotRegex(commands, r'\bsleep\s+[0-9]+\.[0-9]+')

    def test_stop_poll_uses_only_integer_seconds_with_five_second_bound(self):
        suite,state=self.suite()
        suite.stop_app()
        command=state['commands'][-1][1]
        self.assertIn('test "$n" -lt 5 || exit 91',command)
        self.assertIn('sleep 1; n=$((n+1))',command)
        self.assertNotRegex(command,r'\bsleep\s+[0-9]+\.[0-9]+')

    def test_failed_ssh_still_finally_cleans_both_devices(self):
        suite,state=self.suite(True)
        result=suite.execute()
        self.assertEqual(result['status'],'incomplete')
        self.assertIn('disconnected',result['error'])
        self.assertEqual(set(result['cleanup']),{'target','client'})
        for role in ('target','client'):
            self.assertTrue(any(r==role and 'rm -r "$R"' in command for r,command in state['commands']))

    def test_failed_preflight_has_no_remote_mutations(self):
        suite,state=self.suite()
        original=suite.snapshot
        def snapshot(role,group=False):
            if role=='client':raise ValueError('boot mismatch')
            return original(role,group)
        suite.snapshot=snapshot
        result=suite.execute()
        self.assertEqual(result['status'],'incomplete')
        self.assertFalse(any('mkdir -m700' in command for role,command in state['commands']))

    def test_remote_command_journal_records_success_failure_without_payload(self):
        suite,state=self.suite()
        payload=b'binary-input-must-not-be-logged'
        suite.rem('target','cat > '+suite.root+'/probe',data=payload)
        state['fail_load']=True
        with self.assertRaisesRegex(RuntimeError,'disconnected'):
            suite.rem('client',suite.root+'/load -addr ignored')
        raw=(suite.output/'commands.jsonl').read_text()
        rows=[json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(rows),2)
        self.assertTrue(rows[0]['success'])
        self.assertEqual(rows[0]['input_sha256'],device.digest(payload))
        self.assertEqual(rows[0]['input_bytes'],len(payload))
        self.assertNotIn(payload.decode(),raw)
        self.assertFalse(rows[1]['success'])
        self.assertEqual(rows[1]['error_type'],'RuntimeError')
        self.assertTrue(all(row['duration_seconds']>=0 for row in rows))

    def test_binary_drift_after_config_validation_is_rejected(self):
        suite,state=self.suite()
        Path(suite.cfg['versions'][0]['_binary_path']).write_bytes(b'\x7fELFchanged')
        result=suite.execute()
        self.assertEqual(result['status'],'incomplete')
        self.assertIn('changed after verification',result['error'])
        self.assertTrue(all(v['status']=='pass' for v in result['cleanup'].values()))

    def test_kernel_rotation_fails_closed(self):
        suite,state=self.suite()
        suite.before['target']=suite.snapshot('target')
        state['kernel']='new log after clear'
        with self.assertRaisesRegex(ValueError,'rotated/cleared'):
            suite.snapshot('target')

    def test_cgroup_write_failure_prevents_payload_execution(self):
        suite,state=self.suite()
        # Local disposable shell probe, never SSH: failing cgroup move must stop before touch.
        owned=self.root/'owned';owned.mkdir()
        (owned/'owner').write_text(suite.token)
        (owned/'lease').write_text('9999999999')
        suite.root=str(owned)
        suite.group=str(self.root/'absent-cgroup')
        marker=self.root/'must-not-run'
        proc=subprocess.run(['sh','-c',suite.launch_prefix()+'touch '+shlex.quote(str(marker))],
                            capture_output=True)
        self.assertNotEqual(proc.returncode,0)
        self.assertFalse(marker.exists())

    def test_nft_exact_addresses_reject_same_count_wrong_value(self):
        spec=dict(device.SCENARIOS[0],rate=2,seconds=1)
        expected=device.expected_addresses(load_result(spec)['samples'],True)
        wrong={'nftables':[{'set':dict(name='cn4',table='owned',family='inet',elem=['198.18.1.1','198.18.1.2'])},
                            {'set':dict(name='cn6',table='owned',family='inet')}]}
        actual=device.nft_addresses(wrong,'owned')
        self.assertEqual(len(actual['cn4']),len(expected['cn4']))
        self.assertNotEqual(actual,expected)

    def test_fixture_addresses_for_mixed_and_hot(self):
        spec=dict(device.SCENARIOS[2],rate=2,seconds=1)
        addresses=device.expected_addresses(load_result(spec)['samples'],True)
        self.assertEqual(addresses,{'cn4':{'198.18.78.33'},'cn6':{'fdaa::4e22'}})
        spec=dict(device.SCENARIOS[-1],rate=2,seconds=1)
        self.assertEqual(device.expected_addresses(load_result(spec)['samples'],False),
                         {'cn4':{'198.18.0.42'},'cn6':{'fdaa::2a'}})



if __name__=='__main__':
    unittest.main()
