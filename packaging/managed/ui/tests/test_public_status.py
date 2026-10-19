#!/usr/bin/env python3
"""Domestic egress observation fixtures: no network, router or configuration changes."""
import pathlib
import unittest
from lupa.lua51 import LuaRuntime

ROOT = pathlib.Path(__file__).parents[1]


class PublicStatusTests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.lua.globals().P = self.lua.execute((ROOT / 'public-status.lua').read_text())
        self.lua.execute("""
          function fixture(overrides)
            local status={
              wan={up=true,l3_device='pppoe-wan',['ipv4-address']={{address='115.192.136.85'}}},
              wan_6={up=true,l3_device='pppoe-wan',['ipv6-address']={{address='240e:0390:1093:7576:cc99:2158:e55:a960',valid=100}}},
              lan={up=true,l3_device='br-lan'}}
            local opts={now=function()return 1234 end,interface_status=function(name)return status[name]end,
              fetch=function(af,url,limit,timeout)
                assert(url=='https://myip.ipip.net' and limit==4096 and timeout==6)
                if af==4 then return '当前 IP：115.192.136.85  来自于：中国 浙江 杭州 电信\\n',0 end
                return '当前 IP：240E:390:1093:7576:CC99:2158:E55:A960 来自于：中国 浙江 杭州 电信',0
              end}
            if overrides then overrides(status,opts) end
            return P.probe(opts),status
          end
        """)

    def run_lua(self, script):
        self.lua.execute(script)

    def test_actual_response_and_canonical_wan_match(self):
        self.run_lua("""
          local r=fixture()
          assert(r.time==1234 and r.ipv4.checked_at==1234)
          assert(r.ipv4.ip=='115.192.136.85' and r.ipv4.reachability and r.ipv4.available)
          assert(r.ipv4.identity_status=='wan_matched' and r.ipv4.route_device=='pppoe-wan')
          assert(r.ipv6.ip=='240e:390:1093:7576:cc99:2158:e55:a960')
          assert(r.ipv6.identity_status=='wan_matched' and r.ipv6.wan_interface=='wan_6')
          assert(r.ipv6.probe_scope=='router_domestic_https' and r.ipv6.source=='https://myip.ipip.net')
        """)

    def test_canonical_ipv6_compression_and_embedded_ipv4(self):
        self.run_lua("""
          local cases={['2001:0DB8:0:0:0:0:0:1']='2001:db8::1',['0:0:0:0:0:0:0:0']='::',
            ['2001:0:0:1:0:0:0:1']='2001:0:0:1::1',['2001:0:0:1:0:0:1:1']='2001::1:0:0:1:1',
            ['::ffff:192.0.2.128']='::ffff:c000:280',['::1']='::1',['2001:db8::']='2001:db8::'}
          for raw,want in pairs(cases)do assert(P.canonical_ip(raw,6)==want,raw)end
          for _,bad in ipairs({'2001:::1','1::2::3',':1:2:3:4:5:6:7','1:2:3:4:5:6:7:',
            '::1:2:3:4:5:6:7:8','1:2:3:4:5:6:7','10000::','fe80::1%eth0','[::1]',
            '::ffff:192.0.2.256','::ffff:192.0.2.01','2001:db8::g'})do assert(not P.canonical_ip(bad,6),bad)end
          for _,bad in ipairs({'1.2.3','01.2.3.4','256.2.3.4','1.2.3.4/32',' 1.2.3.4','1.2.3.4\\n'})do assert(not P.canonical_ip(bad,4),bad)end
        """)

    def test_invalid_wrong_family_or_oversize_response_never_displays_ip(self):
        self.run_lua("""
          for _,body in ipairs({'<html>115.192.136.85</html>','当前 IP：115.192.136.85 来自于：中国\\nspoof',
            'ip=115.192.136.85','115.192.136.85 1.2.3.4',string.rep('x',4097),'', '当前 IP：999.1.1.1 来自于：中国'})do
            local r=fixture(function(s,o)o.fetch=function()return body,0 end end)
            assert(not r.ipv4.ip and not r.ipv4.reachability and r.ipv4.identity_status=='unavailable',body)
          end
          assert(not P.parse_response('::1',4) and not P.parse_response('1.2.3.4',6))
        """)

    def test_nonzero_fetch_or_exception_cannot_rescue_plausible_ip(self):
        self.run_lua("""
          for _,rc in ipairs({1,124,127,255})do
            local r=fixture(function(s,o)o.fetch=function()return '115.192.136.85',rc end end)
            assert(not r.ipv4.ip and not r.ipv4.available and r.ipv4.error:find(tostring(rc),1,true))
          end
          local r=fixture(function(s,o)o.fetch=function()error('fetch error')end end)
          assert(not r.ipv4.ip and r.ipv4.error=='domestic HTTPS observation failed')
        """)

    def test_upstream_nat_mismatch_remains_observed_unverified(self):
        self.run_lua("""
          local r=fixture(function(s)s.wan['ipv4-address'][1].address='10.0.0.2'end)
          assert(r.ipv4.ip=='115.192.136.85' and r.ipv4.available)
          assert(r.ipv4.identity_status=='unverified' and r.ipv4.reason:find('upstream NAT',1,true))
        """)

    def test_down_unavailable_or_expired_wan_does_not_verify(self):
        self.run_lua("""
          local r=fixture(function(s)s.wan.up=false;s.wan_6.up=false end)
          assert(r.ipv4.identity_status=='unverified' and not r.ipv4.route_device)
          assert(r.ipv6.identity_status=='unverified' and not r.ipv6.route_device)
          r=fixture(function(s,o)o.interface_status=function()error('ubus disconnected')end end)
          assert(r.ipv4.ip and r.ipv4.identity_status=='unverified')
          r=fixture(function(s,o)o.interface_status=function()return nil,'API error'end end)
          assert(r.ipv6.ip and r.ipv6.identity_status=='unverified')
          r=fixture(function(s)s.wan_6['ipv6-address'][1].valid=0 end)
          assert(r.ipv6.identity_status=='unverified')
        """)

    def test_exact_local_delegated_ipv6_matches_active_wan_prefix(self):
        self.run_lua("""
          local r=fixture(function(s,o)
            s.wan_6['ipv6-prefix']={{address='240e:390:e9a:9000::',mask=60,valid=100}}
            s.lan['ipv6-prefix-assignment']={{address='240e:390:e9a:9000::',mask=64,
              ['local-address']={address='240e:390:e9a:9000:1204:c1ff:fe07:558e',mask=64}}}
            o.fetch=function(af)return af==4 and '115.192.136.85' or '240E:390:E9A:9000:1204:C1FF:FE07:558E',0 end
          end)
          assert(r.ipv6.identity_status=='wan_prefix_matched')
          assert(r.ipv6.identity_basis=='wan_delegated_local_address' and r.ipv6.wan_interface=='wan_6')
          assert(r.ipv6.route_device=='pppoe-wan')
        """)

    def test_prefix_membership_alone_and_inactive_delegation_do_not_verify(self):
        self.run_lua("""
          for _,mode in ipairs({'other-local','other-prefix','down-wan','down-lan','expired','missing-local'})do
            local r=fixture(function(s,o)
              s.wan_6['ipv6-prefix']={{address='240e:390:e9a:9000::',mask=60,valid=100}}
              s.lan['ipv6-prefix-assignment']={{['local-address']={address='240e:390:e9a:9000::1234'}}}
              o.fetch=function(af)return af==4 and '115.192.136.85' or '240e:390:e9a:9000::1234',0 end
              if mode=='other-local'then s.lan['ipv6-prefix-assignment'][1]['local-address'].address='240e:390:e9a:9000::4321'
              elseif mode=='other-prefix'then s.wan_6['ipv6-prefix'][1].address='240e:390:e9a:a000::'
              elseif mode=='down-wan'then s.wan_6.up=false
              elseif mode=='down-lan'then s.lan.up=false
              elseif mode=='expired'then s.wan_6['ipv6-prefix'][1].valid=0
              else s.lan['ipv6-prefix-assignment'][1]['local-address']=nil end
            end)
            assert(r.ipv6.identity_status=='unverified',mode)
          end
          assert(P.in_prefix('240e:390:e9a:900f::1','240e:390:e9a:9000::',60))
          assert(not P.in_prefix('240e:390:e9a:9010::1','240e:390:e9a:9000::',60))
          assert(not P.in_prefix('240e:390:e9a:9000::1','240e:390:e9a:9000::',129))
        """)

    def test_default_subprocesses_have_bounds_and_ubus_failures_are_safe(self):
        self.run_lua("""
          local calls={}
          io.popen=function(command)
            calls[#calls+1]=command
            local body=command:find('uclient-fetch -4',1,true) and '115.192.136.85' or '240e:390:e9a:9000::1'
            local rc=command:find('ubus -t 3 call',1,true) and 1 or 0
            return {read=function(self,n)assert(n<=65601);return body..'\\nPNW_PUBLIC_RC='..rc..'\\n'end,close=function()end}
          end
          local r=P.get({now=function()return 1234 end})
          assert(r.ipv4.ip=='115.192.136.85' and r.ipv4.identity_status=='unverified')
          assert(#calls==6)
          for _,command in ipairs(calls)do
            assert(command:find('head -c ',1,true))
            if command:find('uclient-fetch',1,true)then
              assert(command:find('uclient-fetch -',1,true))
              assert(command:find('--no-proxy -T 6 -q -O - https://myip.ipip.net',1,true))
              assert(not command:find('nft',1,true))
            else assert(command:find('ubus -t 3 call network.interface.',1,true))end
          end
        """)

    def test_malformed_interface_arrays_do_not_break_observation(self):
        self.run_lua("""
          local r=fixture(function(s)
            s.wan['ipv4-address']='invalid'
            s.wan_6['ipv6-address']={false,42,{address='invalid'}}
            s.wan_6['ipv6-prefix']='invalid'
            s.lan['ipv6-prefix-assignment']={42,{['local-address']=true}}
          end)
          assert(r.ipv4.ip and r.ipv4.identity_status=='unverified')
          assert(r.ipv6.ip and r.ipv6.identity_status=='unverified')
        """)

    def test_bounded_default_reader_rejects_truncated_or_excess_output(self):
        self.run_lua("""
          for _,body in ipairs({string.rep('x',4160),'115.192.136.85',
            string.rep(' ',4097)..'115.192.136.85\\nPNW_PUBLIC_RC=0\\n'})do
            io.popen=function()return {read=function()return body end,close=function()end}end
            local r=P.get({interface_status=function()return {}end,now=function()return 1234 end})
            assert(not r.ipv4.ip and r.ipv4.identity_status=='unavailable')
          end
        """)


if __name__ == '__main__':
    unittest.main(verbosity=2)
