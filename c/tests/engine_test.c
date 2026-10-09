/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "mosdns.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char directory[256];
static void write_config(const char *name,const char *text,char path[512]) {
    assert(snprintf(path,512,"%s/%s",directory,name)>0);
    FILE *f=fopen(path,"wb");assert(f);assert(fwrite(text,1,strlen(text),f)==strlen(text));assert(!fclose(f));
}
static md_engine *load_text(const char *text,bool check,char *err) {
    char path[512];write_config("config.yaml",text,path);return md_engine_load(path,check,err);
}
static void must_fail(const char *text,const char *reason) {
    char err[MD_ERROR_SIZE]={0};md_engine *e=load_text(text,true,err);
    if(e) { fprintf(stderr,"unexpected accepted config:\n%s",text);md_engine_free(e);abort(); }
    if(!strstr(err,reason)) { fprintf(stderr,"expected '%s', got '%s'\n",reason,err);abort(); }
}
static md_packet question(const char *name) {
    md_packet p={0};md_write16(p.data,1234);md_write16(p.data+2,0x0100);md_write16(p.data+4,1);size_t offset=12;
    const char *start=name;
    while(*start) { const char *end=strchr(start,'.');size_t n=end ? (size_t)(end-start) : strlen(start);assert(n<=63);
        p.data[offset++]=(uint8_t)n;memcpy(p.data+offset,start,n);offset+=n;if(!end) break;start=end+1; }
    p.data[offset++]=0;md_write16(p.data+offset,1);md_write16(p.data+offset+2,1);p.len=offset+4;return p;
}
static unsigned query(md_engine *e,const char *name) {
    md_packet q=question(name),r={0};char err[MD_ERROR_SIZE]={0};const md_listener *listener=md_engine_listener(e,0);assert(listener);
    if(md_engine_query(e,listener->entry,&q,&r,err)) { fprintf(stderr,"query: %s\n",err);abort(); }
    assert(md_read16(r.data)==1234);assert(md_read16(r.data+2)&0x8000);return md_read16(r.data+2)&15;
}
static void config_validation(void) {
    char err[MD_ERROR_SIZE]={0};
    const char *missing="plugins:\n"
        " - tag: domains\n   type: domain_set\n   args:\n     files: /definitely/missing/mosdns-c-domain-file\n"
        " - tag: main\n   type: sequence\n   args:\n    - matches: 'qname $domains'\n      exec: reject\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    md_engine *e=load_text(missing,true,err);assert(e);assert(md_engine_listener_count(e)==1);md_engine_free(e);
    e=load_text(missing,false,err);assert(!e);assert(strstr(err,"missing") || strstr(err,"No such"));
    must_fail("api: {http: '127.0.0.1:8080'}\n", "HTTP API");
    must_fail("plugins: [{type: ip_set}]\n", "plugin type");
    must_fail("plugins: [{type: cache, args: {dump_file: cache.db}}]\n", "disk dump");
    must_fail("plugins: [{type: cache, args: {size: -1}}]\n", "unsigned");
    must_fail("plugins: [{type: forward, args: {upstreams: [{addr: 'tls://1.1.1.1'}]}}]\n", "udp");
    must_fail("plugins: [{type: forward, args: {upstreams: [{addr: '127.0.0.1'}, {addr: 'tls://1.1.1.1'}]}}]\n", "udp");
    must_fail("plugins: [{type: forward, args: {upstreams: [{addr: '127.0.0.1', enable_pipeline: true}]}}]\n", "enable_pipeline");
    must_fail("plugins: [{tag: main, type: sequence, args: [{exec: '$unknown'}]}]\n", "cannot find executable");
    must_fail("plugins: [{type: sequence, args: [{matches: resp_ip, exec: accept}]}]\n", "matcher");
    must_fail("plugins: [{type: sequence, args: [{exec: 'reject 16'}]}]\n", "unsigned");
    must_fail("plugins: [{tag: d, type: domain_set}, {tag: d, type: cache}]\n", "duplicate plugin");
    must_fail("plugins: []\nplugins: []\n", "duplicate configuration");
    must_fail("plugins: [{type: cache, args: {mystery: 1}}]\n", "unsupported configuration");
    must_fail("plugins: [{type: sequence, args: [{exec: 'cache 1024'}, {exec: missing}]}]\n", "unsupported sequence executable");
    must_fail("plugins: [{type: sequence, args: [{matches: 'qname regexp:^ok$', exec: accept}, {matches: 'qname regexp:[', exec: accept}]}]\n", "regex");
    must_fail("plugins: [{type: sequence, args: [{exec: 'nftset inet,t,s,ipv4_addr,32'}, {exec: 'nftset invalid'}]}]\n", "nftset");
    must_fail("plugins: [{tag: a, type: domain_set, args: {sets: b}}, {tag: b, type: domain_set, args: {sets: a}}]\n", "cyclic");
    must_fail("plugins: [{tag: f, type: forward, args: {upstreams: [{addr: '127.0.0.1'}]}}, {tag: main, type: sequence, args: [{exec: 'jump f'}]}]\n", "not a sequence");
    must_fail("plugins: []\n---\nplugins: []\n", "multiple YAML");
    must_fail("plugins: [{type: \"cache\\0extra\"}]\n", "embedded NUL");
    must_fail("include: \"missing.yaml\\0extra\"\n", "embedded NUL");
    must_fail("\"plugins\\0extra\": []\n", "embedded NUL");
    e=md_engine_load("/tmp/config.toml",true,err);assert(!e);assert(strstr(err,"YAML/YML/JSON"));
}
static void regex_profile_validation(void) {
    const char *unsupported[]={"(*UTF)^example\\.test$", "(*UCP)^example\\.test$",
                               "^\\p{L}+\\.test$", "^\\P{L}+\\.test$", "^\\X\\.test$"};
    for(size_t i=0;i<sizeof(unsupported)/sizeof(unsupported[0]);i++) {
        char text[2048],path[512],rules[512],err[MD_ERROR_SIZE]={0};
        /* Both inline entry points compile in check mode as well as at startup. */
        snprintf(text,sizeof(text),"plugins: [{type: domain_set, args: {exps: ['regexp:%s']}}]\n",unsupported[i]);
        must_fail(text,"invalid PCRE2 regexp at ");
        md_engine *e=load_text(text,false,err);assert(!e);assert(strstr(err,"invalid PCRE2 regexp at "));
        snprintf(text,sizeof(text),"plugins: [{type: sequence, args: [{matches: 'qname regexp:%s', exec: reject}]}]\n",unsupported[i]);
        must_fail(text,"invalid PCRE2 regexp at ");
        e=load_text(text,false,err);assert(!e);assert(strstr(err,"invalid PCRE2 regexp at "));

        snprintf(rules,sizeof(rules),"# external regex profile\nfull:before.test\nregexp:%s\nfull:after.test\n",unsupported[i]);
        write_config("unicode-rules.txt",rules,path);
        for(unsigned direct=0;direct<2;direct++) {
            if(direct) snprintf(text,sizeof(text),"plugins:\n"
                " - {tag: main, type: sequence, args: [{matches: 'qname &%s', exec: reject}]}\n"
                " - {type: udp_server, args: {entry: main, listen: '127.0.0.1:0'}}\n",path);
            else snprintf(text,sizeof(text),"plugins:\n"
                " - {tag: domains, type: domain_set, args: {files: '%s'}}\n"
                " - {tag: main, type: sequence, args: [{matches: 'qname $domains', exec: reject}]}\n"
                " - {type: udp_server, args: {entry: main, listen: '127.0.0.1:0'}}\n",path);
            /* check deliberately skips external files; it is not a rules preflight. */
            e=load_text(text,true,err);assert(e);assert(md_engine_listener_count(e)==1);md_engine_free(e);
            e=load_text(text,false,err);assert(!e);
            assert(strstr(err,path) && strstr(err,"line 3:") && strstr(err,"invalid PCRE2 regexp at "));
        }
        assert(!unlink(path));
    }
}
static void matching_and_flow(void) {
    char err[MD_ERROR_SIZE]={0};
    const char *config="plugins:\n"
        " - tag: base\n   type: domain_set\n   args: {exps: ['domain:example.com', 'full:exact.test', 'regexp:^rx[0-9]+\\.test$', 'keyword:marker']}\n"
        " - tag: combined\n   type: domain_set\n   args: {sets: base}\n"
        " - tag: main\n   type: sequence\n   args:\n"
        "    - matches: ['qname $combined', '!_false', '_true']\n      exec: reject 3\n"
        "    - matches: [has_resp]\n      exec: reject 2\n"
        "    - exec: reject\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    md_engine *e=load_text(config,false,err);if(!e) { fprintf(stderr,"matching config: %s\n",err);abort(); }
    assert(query(e,"www.example.com")==3);assert(query(e,"exact.test")==3);assert(query(e,"rx12.test")==3);
    assert(query(e,"a-marker-b.test")==3);assert(query(e,"other.test")==5);assert(query(e,"badexample.com")==5);md_engine_free(e);
    config="plugins:\n"
        " - tag: child\n   type: sequence\n   args: [{exec: return}, {exec: 'reject 2'}]\n"
        " - tag: main\n   type: sequence\n   args: [{exec: 'jump child'}, {exec: 'reject 3'}]\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    e=load_text(config,false,err);assert(e);assert(query(e,"test")==3);md_engine_free(e);
    config="plugins:\n"
        " - tag: child\n   type: sequence\n   args: [{exec: 'reject 0'}]\n"
        " - tag: main\n   type: sequence\n   args: [{exec: '$child'}, {exec: 'reject 3'}]\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    e=load_text(config,false,err);assert(e);assert(query(e,"test")==3);md_engine_free(e);
    config="plugins:\n"
        " - tag: child\n   type: sequence\n   args: [{exec: 'reject 0'}]\n"
        " - tag: main\n   type: sequence\n   args: [{exec: 'jump child'}, {exec: 'reject 3'}]\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    e=load_text(config,false,err);assert(e);assert(query(e,"test")==0);md_engine_free(e);
    config="plugins:\n"
        " - tag: initial\n   type: sequence\n   args: [{exec: 'reject 0'}]\n"
        " - tag: child\n   type: sequence\n   args: [{exec: return}]\n"
        " - tag: main\n   type: sequence\n   args: [{exec: '$initial'}, {exec: 'goto child'}, {exec: 'reject 3'}]\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    e=load_text(config,false,err);assert(e);assert(query(e,"test")==0);md_engine_free(e);
    config="plugins:\n"
        " - tag: main\n   type: sequence\n   args: [{exec: '$main'}]\n"
        " - type: udp_server\n   args: {entry: main, listen: '127.0.0.1:0'}\n";
    e=load_text(config,false,err);assert(e);md_packet q=question("test"),r={0};
    assert(md_engine_query(e,md_engine_listener(e,0)->entry,&q,&r,err));assert(strstr(err,"recursion"));md_engine_free(e);
}
static void included_json(void) {
    char included[512],config[512],text[2048],err[MD_ERROR_SIZE]={0};
    write_config("included.json","{\"plugins\": [{\"tag\": \"main\", \"type\": \"sequence\", \"args\": [{\"exec\": \"reject 3\"}]}]}",included);
    snprintf(text,sizeof(text),"include: '%s'\nplugins:\n - type: tcp_server\n   args: {entry: main, listen: '127.0.0.1:0', idle_timeout: 2}\n",included);
    write_config("main.yml",text,config);md_engine *e=md_engine_load(config,false,err);assert(e);
    assert(md_engine_listener(e,0)->tcp);assert(md_engine_listener(e,0)->idle_timeout==2);assert(query(e,"test")==3);md_engine_free(e);
    snprintf(text,sizeof(text),"include: '%s'\n",config);write_config("main.yml",text,config);
    e=md_engine_load(config,true,err);assert(!e);assert(strstr(err,"include depth"));
    unlink(included);unlink(config);
}
static void cached_accept_guards(void) {
    const char *next[]={"{matches: has_resp, exec: accept}",
                        "{matches: has_resp, exec: 'reject 2'}",
                        "{matches: '!has_resp', exec: accept}",
                        "{matches: [has_resp, _false], exec: accept}"};
    for(size_t i=0;i<sizeof(next)/sizeof(next[0]);i++) {
        char config[2048],err[MD_ERROR_SIZE]={0};
        snprintf(config,sizeof(config),"plugins:\n"
            " - {tag: cache, type: cache, args: {size: 4}}\n"
            " - {tag: main, type: sequence, args: [{exec: '$cache'}, %s, {exec: 'reject 3'}]}\n"
            " - {tag: seed, type: sequence, args: [{exec: '$cache'}, {exec: 'reject 3'}]}\n"
            " - {type: udp_server, args: {entry: main, listen: '127.0.0.1:0'}}\n"
            " - {type: tcp_server, args: {entry: seed, listen: '127.0.0.1:0'}}\n",next[i]);
        md_engine *e=load_text(config,false,err);assert(e);
        md_packet q=question("cached.guard.test"),r={0};
        size_t main=md_engine_listener(e,0)->entry,seed=md_engine_listener(e,1)->entry;
        assert(!md_engine_cached_query(e,main,&q,&r) && !r.len);
        assert(!md_engine_query(e,seed,&q,&r,err));
        md_write16(q.data,9876);
        bool hit=md_engine_cached_query(e,main,&q,&r);
        assert(hit==(i==0));
        if(hit) { assert(md_dns_response_matches(&q,&r));assert((md_read16(r.data+2)&15)==3); }
        else assert(!r.len);
        assert(!md_engine_query(e,main,&q,&r,err));
        assert((md_read16(r.data+2)&15)==(i==1 ? 2 : 3));
        assert(!md_engine_cached_query(e,SIZE_MAX,&q,&r) && !r.len);
        md_engine_free(e);
    }
}
int main(void) {
    strcpy(directory,"/tmp/mosdns-c-engine-test-XXXXXX");assert(mkdtemp(directory));
    config_validation();regex_profile_validation();matching_and_flow();included_json();cached_accept_guards();char config[512];snprintf(config,sizeof(config),"%s/config.yaml",directory);unlink(config);assert(!rmdir(directory));
    puts("engine: configuration and sequence tests passed");return 0;
}
