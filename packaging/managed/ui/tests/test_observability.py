#!/usr/bin/env python3
"""Pure Lua fixture tests. No router, network, compiler or production configuration."""
import pathlib
import sys
import unittest

from lupa.lua51 import LuaRuntime

ROOT = pathlib.Path(__file__).parents[1]

class Tests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute("""
            package.preload['luci.jsonc']=function() return {parse=function() return nil end,stringify=function() return '{}' end} end
            package.preload['nixio.fs']=function() return {} end
        """)
        self.telemetry = self.lua.execute((ROOT / 'telemetry.lua').read_text())
        self.query = self.lua.execute((ROOT / 'query.lua').read_text())
        self.lua.globals().T = self.telemetry
        self.lua.globals().Q = self.query
        self.lua.execute("""
          function sample(sequence,elapsed,completed,success,hits,misses)
            local group={fresh=hits,stale=0,cold=misses,evicted=0,expired=0,bypass=0}
            local raw={version=1,pid=123,started_unix=1000,sequence=sequence,
              updated_unix_ms=1000000+elapsed,uptime_ms=elapsed,
              totals={requests=completed+2,completed=completed,success=success,failed=completed-success,
                latency_count=completed,latency_sum_us=completed*1000,latest_latency_us=1000,
                latest_completion_unix_ms=1000000+elapsed,latency_buckets={0,completed,0}},
              latency_bucket_upper_us={100,1000},cache={cn=group,foreign=group}}
            return raw
          end
        """)

    def run_lua(self, script):
        self.lua.execute(script)

    def test_real_counter_delta(self):
        self.run_lua("""
          local a=assert(T.validate(sample(1,10000,10,9,5,5),'boot'))
          local b=assert(T.validate(sample(2,30000,30,27,20,10),'boot'))
          local r=assert(T.delta(a,b))
          assert(r.dns.completed==20 and r.dns.successes==18 and r.dns.success_rate_pct==90)
          assert(r.dns.avg_ms==1 and r.dns.recent_ms==1 and r.dns.p95_ms==1)
          assert(r.dns.window_seconds==20 and r.dns.window_start==1010 and r.dns.window_end==1030)
          assert(r.cache.groups.all.queries==40 and r.cache.groups.all.cache_hit_rate_pct==75)
        """)

    def test_zero_denominators_are_missing_not_zero_percent(self):
        self.run_lua("""
          local a=T.validate(sample(1,10000,10,9,5,5),'b')
          local b=T.validate(sample(2,30000,10,9,5,5),'b')
          b.totals.latest_completion_unix_ms=1009000
          local r=assert(T.delta(a,b))
          assert(r.dns.success_rate_pct==nil and r.dns.avg_ms==nil and r.dns.recent_ms==nil)
          assert(r.cache.groups.all.cache_hit_rate_pct==nil)
        """)

    def test_missing_malformed_stale_and_clock_skew(self):
        self.run_lua("""
          assert(T.validate(nil)==nil)
          local raw=sample(1,10000,10,9,5,5);raw.totals.success=-1;assert(T.validate(raw)==nil)
          raw=sample(1,10000,10,9,5,5);raw.cache.cn.fresh=0/0;assert(T.validate(raw)==nil)
          raw=sample(1,10000,10,9,5,5);raw.totals.latency_buckets[2]=100;assert(T.validate(raw)==nil)
          local p=T.validate(sample(1,10000,10,9,5,5),'b')
          assert(not T.reduce({},1010).dns.available)
          assert(not T.reduce({p},1010).dns.available)
          assert(not T.reduce({p},1200).dns.available)
          assert(not T.reduce({p},1000).dns.available)
        """)

    def test_restart_reset_and_repeated_snapshot(self):
        self.run_lua("""
          local a=T.validate(sample(1,10000,10,9,5,5),'b')
          local b=T.validate(sample(2,30000,30,27,20,10),'other-boot')
          assert(T.delta(a,b)==nil)
          b=T.validate(sample(1,30000,30,27,20,10),'b');assert(T.delta(a,b)==nil)
          b=T.validate(sample(2,30000,8,7,5,5),'b');assert(T.delta(a,b)==nil)
          b=T.validate(sample(2,30000,30,27,4,10),'b');assert(T.delta(a,b)==nil)
          assert(T.delta(a,a)==nil)
        """)

    def test_final_snapshot_and_process_identity(self):
        self.run_lua("""
          local raw=sample(1,10000,10,9,5,5);raw.final=true
          local parsed,why=T.validate(raw,'b');assert(parsed==nil and why:find('stopped',1,true))
          raw.final=false;raw.totals.failed=0;assert(T.validate(raw,'b')==nil)
          raw=sample(1,10000,10,9,5,5)
          local function stat(state)
            local fields={state};for i=2,19 do fields[i]='0' end;fields[20]='12345'
            return '123 (diversion-dns-c) '..table.concat(fields,' ')
          end
          local goodlink=function() return '/usr/sbin/diversion-dns-c' end
          assert(T.process_identity(raw,function() return stat('S') end,goodlink)=='12345')
          assert(T.process_identity(raw,function() return nil end,goodlink)==nil)
          assert(T.process_identity(raw,function() return stat('Z') end,goodlink)==nil)
          assert(T.process_identity(raw,function() return stat('S') end,function()return '/usr/bin/other'end)==nil)
        """)

    def test_window_is_actual_span_and_current_process(self):
        self.run_lua("""
          local points={}
          for i=1,22 do points[i]=T.validate(sample(i,i*20000,i*10,i*10,i*5,i*5),'b') end
          local r=T.reduce(points,1440)
          assert(r.dns.available and r.dns.window_seconds==300 and r.dns.completed==150)
          points[22]=T.validate(sample(1,20000,5,5,2,3),'newboot')
          assert(not T.reduce(points,1020).dns.available)
        """)

    def test_histogram_overflow_not_fake_p95(self):
        self.run_lua("""
          local ra=sample(1,10000,10,10,5,5);ra.totals.latency_buckets={0,10,0}
          local rb=sample(2,30000,30,30,20,10);rb.totals.latency_buckets={0,10,20}
          local r=T.delta(T.validate(ra,'b'),T.validate(rb,'b'))
          assert(r.dns.p95_ms==nil and r.dns.p95_overflow and r.dns.p95_lower_bound_ms==1)
        """)

    def test_qname_and_ip_validation(self):
        self.run_lua(r"""
          for _,s in ipairs({'www.example.com','EXAMPLE.COM.','xn--fiqs8s.example','127.0.0.1','2001:db8::1','::1','::'}) do assert(Q.validate_input(s),s) end
          for _,s in ipairs({'', ' a.com','a.com\n','a;id','$(id)','a..com','-a.com','a-.com','a/b','a:80',
            '1.2.3.256','0192.0.2.4','1.2.3','2001:::1','1::2::3','2001:db8:1:2:3:4:5','example.com:443',string.rep('a',64)..'.com'}) do assert(Q.validate_input(s)==nil,s) end
        """)

    def test_exact_suffix_keyword_and_unsupported_regex(self):
        self.run_lua("""
          assert(Q.match_rule('a.example.com','domain:example.com'))
          assert(not Q.match_rule('badexample.com','domain:example.com'))
          assert(Q.match_rule('example.com','full:example.com'))
          assert(not Q.match_rule('a.example.com','full:example.com'))
          assert(Q.match_rule('a.example.com','domain:.example.com.'))
          assert(Q.match_rule('a.example.com','domain:.'))
          local hit,supported=Q.match_rule('x.ai.example','keyword:ai');assert(hit and supported)
          hit,supported=Q.match_rule('a.example.com','regexp:.*example');assert(not hit and not supported)
        """)

    def test_dns_packet_validation_and_answer_parse(self):
        self.run_lua("""
          local function u16(x)return string.char(math.floor(x/256),x%256)end
          local question='\3www\7example\3com\0'..u16(1)..u16(1)
          local packet=u16(123)..u16(33152)..u16(1)..u16(1)..u16(0)..u16(0)..question..
            string.char(192,12)..u16(1)..u16(1)..'\0\0\0\60'..u16(4)..string.char(192,0,2,4)
          local r=Q.parse_dns(packet,123,question);assert(r.ok and #r.answers==1 and r.answers[1].address=='192.0.2.4')
          assert(not pcall(Q.parse_dns,packet,124,question))
          assert(not pcall(Q.parse_dns,packet:sub(1,-2),123,question))
          local truncated=packet:sub(1,2)..u16(33664)..packet:sub(5);assert(not pcall(Q.parse_dns,truncated,123,question))
        """)

    def test_invalid_query_never_runs_shell(self):
        self.run_lua("""
          io.popen=function() error('must not run') end
          assert(not Q.lookup('$(id)',{}).ok)
          assert(not Q.lookup('example.com',{source=';id'}).ok)
        """)

    def test_runtime_rules_set_membership_and_error_boundaries(self):
        self.run_lua("""
          local mode='miss'
          io.popen=function(command)
            local body,rc='',0
            if command:find('nft list chain',1,true) then
              body='@cn4 @cn6 @cnsite4 @cnsite6 meta mark set 0x00000001'
            elseif command:find('nft get element',1,true) then
              if mode=='hit' and command:find(' cn4 ',1,true) then body='elements = { 192.0.2.4 }'
              elseif mode=='unsupported' then body='Operation not supported';rc=1
              else body='No such file or directory';rc=1 end
            elseif command:find('route get',1,true) then body='192.0.2.4 dev wg_vpn table 100'
            end
            return {read=function() return body..'\\nPNW_QUERY_RC='..rc..'\\n' end,close=function() end}
          end
          local r=Q.lookup('192.0.2.4',{selected='aws'});assert(r.answers[1].expected_path=='tunnel')
          mode='hit';r=Q.lookup('192.0.2.4',{selected='aws'});assert(r.answers[1].expected_path=='WAN' and #r.answers[1].sets==1)
          mode='unsupported';r=Q.lookup('192.0.2.4',{selected='aws'});assert(r.answers[1].expected_path=='unknown')
          mode='miss';r=Q.lookup('192.0.2.4',{selected='aws',emergency=true});assert(r.answers[1].expected_path=='blocked')
          r=Q.lookup('2001:db8::1',{selected='usss'});assert(r.answers[1].expected_path=='blocked')
          r=Q.lookup('192.168.50.1',{selected='aws'});assert(r.answers[1].expected_path=='local')
        """)

if __name__ == '__main__':
    unittest.main(verbosity=2)
