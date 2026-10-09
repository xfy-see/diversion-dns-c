/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "mosdns.h"
#include "yaml.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Configuration construction is deliberately separate from serving.  The
 * checker decodes include files and compiles expressions, but never reads a
 * domain file, opens a socket, or applies an nftables operation. */
typedef struct { char **v; size_t n; } strings;
typedef struct plugin plugin;
typedef struct {
    md_domain *own; strings names; plugin **sets;
} domains;
typedef enum { MATCH_QNAME, MATCH_RESP, MATCH_TRUE, MATCH_FALSE } match_kind;
typedef struct { match_kind kind; bool reverse; domains domain; } matcher;
typedef enum { EXEC_REF, EXEC_ACCEPT, EXEC_REJECT, EXEC_RETURN, EXEC_JUMP,
               EXEC_GOTO, EXEC_NFT } exec_kind;
typedef struct {
    matcher *matches; size_t match_count;
    exec_kind kind; char *target, *arguments; plugin *to;
    md_upstream *selected; size_t selected_count; md_nft *nft;
    unsigned rcode;
} rule;
typedef enum { PL_DOMAIN, PL_CACHE, PL_FORWARD, PL_SEQUENCE, PL_SERVER } plugin_kind;
struct plugin {
    char *tag; plugin_kind kind;
    union {
        domains domain;
        md_cache *cache;
        struct { md_upstream *upstreams; size_t count; unsigned concurrent; } forward;
        struct { rule *rules; size_t count; } sequence;
        struct { md_listener listener; char *target; } server;
    } u;
};
typedef struct walker { plugin *sequence; size_t pos; const struct walker *back; } walker;
typedef struct refresh_job refresh_job;
struct md_engine {
    plugin **plugins; size_t count; md_listener *listeners; size_t listener_count;
    bool check, stopping; pthread_mutex_t lock; refresh_job *jobs;
};
typedef struct {
    md_engine *engine; const md_packet *query; md_packet *response, *scratch;
    md_question question; uint64_t revision, deadline; unsigned depth, steps;
} query_context;
struct refresh_job {
    pthread_t thread; md_engine *engine; md_cache *cache;
    md_packet query; md_packet *initial_response; walker *continuation; size_t walker_count;
    bool done; refresh_job *next;
};
typedef struct { yaml_document_t *doc; bool check; char *err; } decoder;

static int fail(char *err, const char *format, ...) {
    if (err) { va_list ap; va_start(ap, format); vsnprintf(err, MD_ERROR_SIZE, format, ap); va_end(ap); }
    return -1;
}
static void *grow(void *p, size_t count, size_t size, char *err) {
    if (count > SIZE_MAX / size) { fail(err, "configuration is too large"); return NULL; }
    void *v = realloc(p, count * size);
    if (!v) fail(err, "out of memory");
    return v;
}
static char *copy_string(const char *s, char *err) {
    char *v = strdup(s); if (!v) fail(err, "out of memory"); return v;
}
static int push_string(strings *s, const char *value, char *err) {
    char *v = copy_string(value, err); if (!v) return -1;
    char **a = grow(s->v, s->n + 1, sizeof(*a), err);
    if (!a) { free(v); return -1; } s->v = a; s->v[s->n++] = v; return 0;
}
static void strings_free(strings *s) {
    for (size_t i = 0; i < s->n; i++) free(s->v[i]); free(s->v);
}
static yaml_node_t *node(decoder *d, int index) { return yaml_document_get_node(d->doc, index); }
static bool scalar_has_nul(yaml_node_t *n) {
    return n && n->type==YAML_SCALAR_NODE && memchr(n->data.scalar.value,0,n->data.scalar.length)!=NULL;
}
static const char *scalar(yaml_node_t *n) {
    return n && n->type==YAML_SCALAR_NODE && !scalar_has_nul(n) ? (const char *)n->data.scalar.value : NULL;
}
static bool absent(yaml_node_t *n) {
    const char *s = scalar(n); return !n || (s && (!*s || !strcmp(s, "null") || !strcmp(s, "~")));
}
static yaml_node_t *field(decoder *d, yaml_node_t *map, const char *key) {
    if (!map || map->type != YAML_MAPPING_NODE) return NULL;
    for (yaml_node_pair_t *p = map->data.mapping.pairs.start; p < map->data.mapping.pairs.top; p++) {
        const char *name = scalar(node(d, p->key));
        if (name && !strcmp(name, key)) return node(d, p->value);
    }
    return NULL;
}
static int keys(decoder *d, yaml_node_t *map, const char *allowed) {
    if (absent(map)) return 0;
    if (map->type != YAML_MAPPING_NODE) return fail(d->err, "expected a mapping");
    for (yaml_node_pair_t *p = map->data.mapping.pairs.start; p < map->data.mapping.pairs.top; p++) {
        yaml_node_t *key=node(d,p->key);
        if(scalar_has_nul(key)) return fail(d->err,"configuration key contains an embedded NUL");
        const char *s = scalar(key);
        if (!s || !*s) return fail(d->err, "mapping keys must be nonempty strings");
        bool found = false; const char *a = allowed;
        while (*a) { const char *end = strchr(a, ' '); size_t len = end ? (size_t)(end-a) : strlen(a);
            if (strlen(s) == len && !strncmp(s, a, len)) found = true;
            if (!end) break; a = end + 1; }
        if (!found) return fail(d->err, "unsupported configuration option: %s", s);
        for (yaml_node_pair_t *q = map->data.mapping.pairs.start; q < p; q++) {
            const char *previous = scalar(node(d, q->key));
            if (previous && !strcmp(previous, s)) return fail(d->err, "duplicate configuration key: %s", s);
        }
    }
    return 0;
}
static int string_value(decoder *d, yaml_node_t *n, const char **out) {
    if (!n) { *out = ""; return 0; }
    if (scalar_has_nul(n)) return fail(d->err,"configuration string contains an embedded NUL");
    const char *s = scalar(n); if (!s) return fail(d->err, "expected a scalar string");
    *out = s; return 0;
}
static int string_field(decoder *d, yaml_node_t *m, const char *key, const char **out) {
    return string_value(d, field(d, m, key), out);
}
static int number_text(const char *s, uint64_t maximum, uint64_t *value, char *err) {
    if (!s || !*s || *s == '-' || isspace((unsigned char)*s)) return fail(err, "invalid unsigned number: %s", s ? s : "");
    errno = 0; char *end; unsigned long long n = strtoull(s, &end, !strncasecmp(s, "0x", 2) ? 16 : 10);
    if (errno || *end || n > maximum) return fail(err, "invalid unsigned number: %s", s);
    *value = n; return 0;
}
static int number_field(decoder *d, yaml_node_t *m, const char *key, uint64_t fallback, uint64_t maximum, uint64_t *out) {
    yaml_node_t *n = field(d, m, key); if (!n) { *out = fallback; return 0; }
    const char *s; if (string_value(d, n, &s)) return -1; return number_text(s, maximum, out, d->err);
}
static int bool_text(decoder *d, yaml_node_t *m, const char *key, bool *out) {
    const char *s; if (string_field(d, m, key, &s)) return -1;
    if (!*s || !strcasecmp(s, "false") || !strcmp(s, "0")) { *out = false; return 0; }
    if (!strcasecmp(s, "true") || !strcmp(s, "1")) { *out = true; return 0; }
    return fail(d->err, "invalid boolean for %s: %s", key, s);
}
static int string_list(decoder *d, yaml_node_t *n, strings *out) {
    if (absent(n)) return 0;
    if (n->type == YAML_SCALAR_NODE) { const char *s;if(string_value(d,n,&s)) return -1;return push_string(out,s,d->err); }
    if (n->type != YAML_SEQUENCE_NODE) return fail(d->err, "expected string or list of strings");
    for (yaml_node_item_t *p = n->data.sequence.items.start; p < n->data.sequence.items.top; p++) {
        const char *s; if (string_value(d, node(d, *p), &s) || push_string(out, s, d->err)) return -1;
    }
    return 0;
}
static int words(const char *text, strings *out, char *err) {
    const char *p = text;
    while (*p) { while (isspace((unsigned char)*p)) p++; if (!*p) break;
        const char *start = p; while (*p && !isspace((unsigned char)*p)) p++;
        size_t n = (size_t)(p-start); char *s = malloc(n+1);
        if (!s) return fail(err, "out of memory"); memcpy(s, start, n); s[n] = 0;
        int status = push_string(out, s, err); free(s); if (status) return -1;
    }
    return 0;
}
static int split_action(const char *text, char **name, char **args, char *err) {
    while (isspace((unsigned char)*text)) text++;
    const char *end = text; while (*end && !isspace((unsigned char)*end)) end++;
    size_t n = (size_t)(end-text); *name = malloc(n+1); if (!*name) return fail(err, "out of memory");
    memcpy(*name, text, n); (*name)[n] = 0;
    while (isspace((unsigned char)*end)) end++;
    *args = copy_string(end, err); return *args ? 0 : -1;
}
static int domain_add_file(domains *dom, const char *path, bool check, char *err) {
    if (!*path) return fail(err, "domain file path is empty");
    return check ? 0 : md_domain_load(dom->own, path, err);
}
static int domain_init(domains *dom, char *err) {
    dom->own = md_domain_new(); return dom->own ? 0 : fail(err, "out of memory");
}
static void domain_free(domains *dom) { md_domain_free(dom->own); strings_free(&dom->names); free(dom->sets); }
static int parse_domain(decoder *d, yaml_node_t *args, domains *dom) {
    if (keys(d, args, "exps files sets") || domain_init(dom, d->err)) return -1;
    strings exps = {0}, files = {0}; int status = -1;
    if (string_list(d, field(d, args, "exps"), &exps) || string_list(d, field(d, args, "files"), &files)
        || string_list(d, field(d, args, "sets"), &dom->names)) goto done;
    for (size_t i=0; i<exps.n; i++) if (md_domain_add(dom->own, exps.v[i], d->err)) goto done;
    for (size_t i=0; i<files.n; i++) if (domain_add_file(dom, files.v[i], d->check, d->err)) goto done;
    status = 0;
done: strings_free(&exps); strings_free(&files); return status;
}
static int parse_match(decoder *d, const char *text, matcher *m) {
    while (isspace((unsigned char)*text)) text++;
    if (*text == '!') { m->reverse = true; text++; }
    char *name = NULL, *args = NULL; int status = -1;
    if (split_action(text, &name, &args, d->err)) goto done;
    if (!strcmp(name, "qname")) {
        m->kind = MATCH_QNAME; if (domain_init(&m->domain, d->err)) goto done;
        strings tokens = {0}; if (words(args, &tokens, d->err)) { strings_free(&tokens); goto done; }
        for (size_t i=0; i<tokens.n; i++) {
            const char *s = tokens.v[i]; int rc;
            if (*s == '$') rc = *++s ? push_string(&m->domain.names, s, d->err) : fail(d->err, "empty domain_set reference");
            else if (*s == '&') rc = domain_add_file(&m->domain, s+1, d->check, d->err);
            else rc = md_domain_add(m->domain.own, s, d->err);
            if (rc) { strings_free(&tokens); goto done; }
        }
        strings_free(&tokens);
    } else if (!strcmp(name, "has_resp")) m->kind = MATCH_RESP;
    else if (!strcmp(name, "_true")) m->kind = MATCH_TRUE;
    else if (!strcmp(name, "_false")) m->kind = MATCH_FALSE;
    else { fail(d->err, "unsupported sequence matcher: %s", name); goto done; }
    if (m->kind != MATCH_QNAME && *args) { fail(d->err, "matcher %s takes no arguments", name); goto done; }
    status = 0;
done: free(name); free(args); return status;
}
static int parse_cache(decoder *d, yaml_node_t *args, plugin *p) {
    if (keys(d, args, "size lazy_cache_ttl dump_file dump_interval")) return -1;
    const char *dump; uint64_t size, lazy, interval;
    if (string_field(d,args,"dump_file",&dump) || number_field(d,args,"dump_interval",0,UINT32_MAX,&interval)) return -1;
    if (*dump || interval) return fail(d->err, "cache disk dump is unavailable in the C minimal build");
    if (number_field(d,args,"size",1024,10000000,&size) || number_field(d,args,"lazy_cache_ttl",0,UINT32_MAX,&lazy)) return -1;
    if (!size) size = 1024;
    p->u.cache = md_cache_new((size_t)size, (uint32_t)lazy);
    return p->u.cache ? 0 : fail(d->err, "cannot allocate cache");
}
static int reject_transport_options(decoder *d, yaml_node_t *args, bool upstream) {
    const char *s; uint64_t n; bool b;
    const char *names[] = {"socks5", "bootstrap"};
    for (size_t i=0;i<2;i++) { if (string_field(d,args,names[i],&s)) return -1;
        if (*s) return fail(d->err,"%s is unavailable in the C minimal build",names[i]); }
    if (number_field(d,args,"bootstrap_version",0,UINT32_MAX,&n)) return -1;
    if (n) return fail(d->err,"bootstrap_version is unavailable in the C minimal build");
    if (upstream) {
        const char *flags[] = {"enable_pipeline", "enable_http3", "insecure_skip_verify"};
        for (size_t i=0;i<3;i++) { if (bool_text(d,args,flags[i],&b)) return -1;
            if (b) return fail(d->err,"%s is unavailable in the C minimal build",flags[i]); }
        if (number_field(d,args,"idle_timeout",0,UINT32_MAX,&n)) return -1;
        if (n) return fail(d->err,"upstream idle_timeout requires connection reuse, unavailable in the C build");
        if (number_field(d,args,"max_conns",0,UINT32_MAX,&n)) return -1;
        if (n) return fail(d->err,"upstream max_conns is unavailable in the C build");
    }
    return 0;
}
static int parse_forward(decoder *d, yaml_node_t *args, plugin *p) {
    if (keys(d,args,"upstreams concurrent so_mark bind_to_device socks5 bootstrap bootstrap_version") || reject_transport_options(d,args,false)) return -1;
    uint64_t mark, concurrent; const char *device;
    if (number_field(d,args,"so_mark",0,UINT32_MAX,&mark) || number_field(d,args,"concurrent",1,UINT32_MAX,&concurrent)
        || string_field(d,args,"bind_to_device",&device)) return -1;
    if (!concurrent) concurrent=1; if (concurrent>3) concurrent=3;
    p->u.forward.concurrent=(unsigned)concurrent;
    yaml_node_t *list=field(d,args,"upstreams");
    if (!list || list->type != YAML_SEQUENCE_NODE || list->data.sequence.items.start == list->data.sequence.items.top)
        return fail(d->err,"forward requires a nonempty upstreams list");
    size_t count=(size_t)(list->data.sequence.items.top-list->data.sequence.items.start);
    p->u.forward.upstreams=calloc(count,sizeof(md_upstream));
    if (!p->u.forward.upstreams) return fail(d->err,"out of memory");
    p->u.forward.count=count;
    for (size_t i=0;i<count;i++) {
        yaml_node_t *a=node(d,list->data.sequence.items.start[i]);
        if (keys(d,a,"addr dial_addr tag so_mark bind_to_device socks5 bootstrap bootstrap_version idle_timeout max_conns enable_pipeline enable_http3 insecure_skip_verify")
            || reject_transport_options(d,a,true)) return -1;
        const char *addr,*dial,*dev,*tag; uint64_t local_mark;
        if (string_field(d,a,"addr",&addr) || string_field(d,a,"dial_addr",&dial) || string_field(d,a,"tag",&tag)
            || string_field(d,a,"bind_to_device",&dev) || number_field(d,a,"so_mark",mark,UINT32_MAX,&local_mark)) return -1;
        if (!*dev) dev=device; if (!local_mark) local_mark=mark;
        if (strlen(tag)>=sizeof(p->u.forward.upstreams[i].tag)) return fail(d->err,"upstream tag is too long");
        if (md_upstream_init(&p->u.forward.upstreams[i],addr,dial,(uint32_t)local_mark,dev,d->err)) return -1;
        strcpy(p->u.forward.upstreams[i].tag,tag);
        for(size_t j=0;j<i;j++) if(*tag && !strcmp(tag,p->u.forward.upstreams[j].tag)) return fail(d->err,"duplicate upstream tag: %s",tag);
    }
    return 0;
}
static plugin *new_plugin(md_engine *e, plugin_kind kind, const char *tag, char *err) {
    plugin *p=calloc(1,sizeof(*p)); if(!p) { fail(err,"out of memory"); return NULL; }
    p->kind=kind; p->tag=copy_string(tag,err); if(!p->tag) { free(p);return NULL; }
    plugin **all=grow(e->plugins,e->count+1,sizeof(*all),err);
    if(!all) { free(p->tag);free(p);return NULL; } e->plugins=all;e->plugins[e->count++]=p;return p;
}
static int parse_inline_forward(decoder *d, const char *text, plugin *p) {
    strings addresses={0}; if(words(text,&addresses,d->err)) { strings_free(&addresses);return -1; }
    if(!addresses.n) { strings_free(&addresses);return fail(d->err,"inline forward requires an upstream"); }
    p->u.forward.upstreams=calloc(addresses.n,sizeof(md_upstream));
    if(!p->u.forward.upstreams) { strings_free(&addresses);return fail(d->err,"out of memory"); }
    p->u.forward.count=addresses.n;p->u.forward.concurrent=3; int status=0;
    for(size_t i=0;i<addresses.n;i++) if(md_upstream_init(&p->u.forward.upstreams[i],addresses.v[i],"",0,"",d->err)) { status=-1;break; }
    strings_free(&addresses);return status;
}
static int parse_exec(md_engine *e, decoder *d, const char *text, rule *r) {
    char *name=NULL,*args=NULL;int status=-1;
    if(split_action(text,&name,&args,d->err)) goto done;
    if(*name=='$') {
        if(!name[1]) { fail(d->err,"empty executable reference");goto done; }
        r->kind=EXEC_REF;r->target=copy_string(name+1,d->err);r->arguments=copy_string(args,d->err);
        if(!r->target || !r->arguments) goto done;
    } else if(!strcmp(name,"accept") || !strcmp(name,"return")) {
        r->kind=!strcmp(name,"accept") ? EXEC_ACCEPT : EXEC_RETURN;
        if(*args) { fail(d->err,"%s takes no arguments",name);goto done; }
    } else if(!strcmp(name,"reject")) {
        r->kind=EXEC_REJECT;uint64_t n=5;
        if(*args && number_text(args,15,&n,d->err)) goto done;r->rcode=(unsigned)n;
    } else if(!strcmp(name,"jump") || !strcmp(name,"goto")) {
        r->kind=!strcmp(name,"jump") ? EXEC_JUMP : EXEC_GOTO;
        strings target={0}; if(words(args,&target,d->err)) { strings_free(&target);goto done; }
        if(target.n!=1) { strings_free(&target);fail(d->err,"%s requires one sequence tag",name);goto done; }
        r->target=copy_string(target.v[0][0]=='$' ? target.v[0]+1 : target.v[0],d->err);strings_free(&target);
        if(!r->target) goto done;
    } else if(!strcmp(name,"nftset")) {
        r->kind=EXEC_NFT;r->nft=md_nft_new(args,d->err);if(!r->nft) goto done;
    } else if(!strcmp(name,"cache") || !strcmp(name,"forward")) {
        plugin_kind kind=!strcmp(name,"cache") ? PL_CACHE : PL_FORWARD;
        r->kind=EXEC_REF;r->to=new_plugin(e,kind,"",d->err);if(!r->to) goto done;
        if(kind==PL_CACHE) {
            uint64_t size=1024;if(*args && number_text(args,10000000,&size,d->err)) goto done;
            if(size<1024) size=1024;r->to->u.cache=md_cache_new((size_t)size,0);
            if(!r->to->u.cache) { fail(d->err,"cannot allocate cache");goto done; }
        } else if(parse_inline_forward(d,args,r->to)) goto done;
    } else { fail(d->err,"unsupported sequence executable: %s",name);goto done; }
    status=0;
done:free(name);free(args);return status;
}
static int parse_sequence(md_engine *e, decoder *d, yaml_node_t *args, plugin *p) {
    if(absent(args)) return 0;
    if(args->type!=YAML_SEQUENCE_NODE) return fail(d->err,"sequence args must be a list");
    size_t count=(size_t)(args->data.sequence.items.top-args->data.sequence.items.start);
    p->u.sequence.rules=calloc(count ? count : 1,sizeof(rule));if(!p->u.sequence.rules) return fail(d->err,"out of memory");
    p->u.sequence.count=count;
    for(size_t i=0;i<count;i++) {
        yaml_node_t *a=node(d,args->data.sequence.items.start[i]); rule *r=&p->u.sequence.rules[i];
        if(keys(d,a,"matches exec")) return -1;
        strings match={0};int rc=string_list(d,field(d,a,"matches"),&match);
        if(rc) { strings_free(&match);return -1; }
        r->matches=calloc(match.n ? match.n : 1,sizeof(matcher));
        if(!r->matches) { strings_free(&match);return fail(d->err,"out of memory"); }
        r->match_count=match.n;
        for(size_t j=0;j<match.n;j++) if(parse_match(d,match.v[j],&r->matches[j])) { strings_free(&match);return -1; }
        strings_free(&match);const char *exec;
        if(string_field(d,a,"exec",&exec) || parse_exec(e,d,exec,r)) return -1;
    }
    return 0;
}
static int parse_server(decoder *d, yaml_node_t *args, plugin *p, bool tcp) {
    if(keys(d,args,tcp ? "listen entry idle_timeout cert key" : "listen entry")) return -1;
    const char *listen,*entry,*cert,*key;uint64_t idle=10;
    if(string_field(d,args,"listen",&listen) || string_field(d,args,"entry",&entry)) return -1;
    if(tcp && (string_field(d,args,"cert",&cert) || string_field(d,args,"key",&key) || number_field(d,args,"idle_timeout",10,UINT32_MAX,&idle))) return -1;
    if(tcp && (*cert || *key)) return fail(d->err,"TCP TLS certificates are unavailable in the C minimal build");
    if(!*listen) listen="127.0.0.1:53";
    if(strlen(listen)>=sizeof(p->u.server.listener.listen)) return fail(d->err,"listener address is too long");
    if(!*entry) return fail(d->err,"server entry is required");
    struct sockaddr_storage address;socklen_t length;
    if(md_parse_address(listen,53,&address,&length,d->err)) return -1;
    strcpy(p->u.server.listener.listen,listen);p->u.server.listener.tcp=tcp;p->u.server.listener.idle_timeout=idle ? (unsigned)idle : 10;
    p->u.server.target=copy_string(*entry=='$' ? entry+1 : entry,d->err);return p->u.server.target ? 0 : -1;
}
static plugin *find_plugin(md_engine *e,const char *tag) {
    for(size_t i=0;i<e->count;i++) if(*e->plugins[i]->tag && !strcmp(e->plugins[i]->tag,tag)) return e->plugins[i];return NULL;
}
static int parse_plugin(md_engine *e,decoder *d,yaml_node_t *a) {
    if(keys(d,a,"tag type args")) return -1;
    const char *tag,*type;if(string_field(d,a,"tag",&tag) || string_field(d,a,"type",&type)) return -1;
    if(*tag && find_plugin(e,tag)) return fail(d->err,"duplicate plugin tag: %s",tag);
    plugin_kind kind;
    if(!strcmp(type,"domain_set")) kind=PL_DOMAIN;
    else if(!strcmp(type,"cache")) kind=PL_CACHE;
    else if(!strcmp(type,"forward")) kind=PL_FORWARD;
    else if(!strcmp(type,"sequence")) kind=PL_SEQUENCE;
    else if(!strcmp(type,"udp_server") || !strcmp(type,"tcp_server")) kind=PL_SERVER;
    else return fail(d->err,"plugin type %s is unavailable in the C minimal build",type);
    plugin *p=new_plugin(e,kind,tag,d->err);if(!p) return -1;
    yaml_node_t *args=field(d,a,"args");
    switch(kind) {
        case PL_DOMAIN:return parse_domain(d,args,&p->u.domain);
        case PL_CACHE:return parse_cache(d,args,p);
        case PL_FORWARD:return parse_forward(d,args,p);
        case PL_SEQUENCE:return parse_sequence(e,d,args,p);
        case PL_SERVER:return parse_server(d,args,p,!strcmp(type,"tcp_server"));
    }
    return -1;
}
static int parse_log(decoder *d,yaml_node_t *a) {
    if(keys(d,a,"level file production")) return -1;
    const char *level,*file;bool production;
    if(string_field(d,a,"level",&level) || string_field(d,a,"file",&file) || bool_text(d,a,"production",&production)) return -1;
    if(*level && strcmp(level,"debug") && strcmp(level,"info") && strcmp(level,"warn") && strcmp(level,"warning") && strcmp(level,"error") && strcmp(level,"fatal") && strcmp(level,"panic")) return fail(d->err,"invalid log level: %s",level);
    if(*file) return fail(d->err,"log.file is unavailable in the C build (logs use stderr)");
    if(production) return fail(d->err,"log.production is unavailable in the C build");
    return 0;
}
static int load_config(md_engine *e,const char *path,unsigned depth,char *err) {
    if(depth>8) return fail(err,"maximum include depth reached");
    const char *ext=strrchr(path,'.');
    if(!ext || (strcasecmp(ext,".yaml") && strcasecmp(ext,".yml") && strcasecmp(ext,".json"))) return fail(err,"C minimal config supports YAML/YML/JSON: %s",path);
    FILE *f=fopen(path,"rb");if(!f) return fail(err,"read config %s: %s",path,strerror(errno));
    yaml_parser_t parser;yaml_document_t doc;
    if(!yaml_parser_initialize(&parser)) { fclose(f);return fail(err,"cannot allocate YAML parser"); }
    yaml_parser_set_input_file(&parser,f);int status=-1;
    if(!yaml_parser_load(&parser,&doc)) { fail(err,"parse config %s at line %zu: %s",path,parser.problem_mark.line+1,parser.problem ? parser.problem : "invalid YAML");goto done_parser; }
    decoder d={&doc,e->check,err};yaml_node_t *root=yaml_document_get_root_node(&doc);
    if(!root || root->type!=YAML_MAPPING_NODE) { fail(err,"config root must be a mapping: %s",path);goto done_doc; }
    if(keys(&d,root,"log include plugins api") || parse_log(&d,field(&d,root,"log"))) goto done_doc;
    yaml_node_t *api=field(&d,root,"api");const char *http;
    if(keys(&d,api,"http") || string_field(&d,api,"http",&http)) goto done_doc;
    if(*http) { fail(err,"HTTP API is unavailable in the C minimal build");goto done_doc; }
    strings includes={0};
    if(string_list(&d,field(&d,root,"include"),&includes)) { strings_free(&includes);goto done_doc; }
    for(size_t i=0;i<includes.n;i++) if(load_config(e,includes.v[i],depth+1,err)) { strings_free(&includes);goto done_doc; }
    strings_free(&includes);yaml_node_t *plugins=field(&d,root,"plugins");
    if(!absent(plugins)) {
        if(plugins->type!=YAML_SEQUENCE_NODE) { fail(err,"plugins must be a list");goto done_doc; }
        for(yaml_node_item_t *p=plugins->data.sequence.items.start;p<plugins->data.sequence.items.top;p++) if(parse_plugin(e,&d,node(&d,*p))) goto done_doc;
    }
    /* Multiple YAML documents have no defined merge semantics. */
    yaml_document_t extra;
    if(!yaml_parser_load(&parser,&extra)) { fail(err,"invalid trailing YAML document in %s",path);goto done_doc; }
    bool has_extra=yaml_document_get_root_node(&extra)!=NULL;yaml_document_delete(&extra);
    if(has_extra) { fail(err,"multiple YAML documents are unsupported: %s",path);goto done_doc; }
    status=0;
done_doc:yaml_document_delete(&doc);
done_parser:yaml_parser_delete(&parser);fclose(f);return status;
}
static int resolve_domains(md_engine *e,domains *d,char *err) {
    if(!d->names.n) return 0;d->sets=calloc(d->names.n,sizeof(plugin *));if(!d->sets) return fail(err,"out of memory");
    for(size_t i=0;i<d->names.n;i++) { const char *name=d->names.v[i];if(*name=='$') name++;
        plugin *p=find_plugin(e,name);if(!p || p->kind!=PL_DOMAIN) return fail(err,"cannot find domain_set: %s",name);d->sets[i]=p; }
    return 0;
}
static int domain_cycle(plugin *p,plugin **path,size_t depth,char *err) {
    if(depth>=128) return fail(err,"domain_set reference depth exceeds 128");
    for(size_t i=0;i<depth;i++) if(path[i]==p) return fail(err,"cyclic domain_set reference: %s",p->tag);
    path[depth]=p;for(size_t i=0;i<p->u.domain.names.n;i++) if(domain_cycle(p->u.domain.sets[i],path,depth+1,err)) return -1;return 0;
}
static int resolve_forward(rule *r,char *err) {
    if(!r->arguments || !*r->arguments) return 0;
    if(r->to->kind!=PL_FORWARD) return fail(err,"plugin %s does not accept executable arguments",r->to->tag);
    strings tags={0};if(words(r->arguments,&tags,err)) { strings_free(&tags);return -1; }
    r->selected=calloc(tags.n,sizeof(md_upstream));if(!r->selected) { strings_free(&tags);return fail(err,"out of memory"); }
    r->selected_count=tags.n;
    for(size_t i=0;i<tags.n;i++) {
        bool found=false;for(size_t j=0;j<r->to->u.forward.count;j++) if(*r->to->u.forward.upstreams[j].tag && !strcmp(tags.v[i],r->to->u.forward.upstreams[j].tag)) { r->selected[i]=r->to->u.forward.upstreams[j];found=true;break; }
        if(!found) { fail(err,"cannot find upstream tag: %s",tags.v[i]);strings_free(&tags);return -1; }
    }
    strings_free(&tags);return 0;
}
static int resolve(md_engine *e,char *err) {
    for(size_t i=0;i<e->count;i++) {
        plugin *p=e->plugins[i];
        if(p->kind==PL_DOMAIN && resolve_domains(e,&p->u.domain,err)) return -1;
        if(p->kind==PL_SEQUENCE) for(size_t j=0;j<p->u.sequence.count;j++) {
            rule *r=&p->u.sequence.rules[j];
            for(size_t k=0;k<r->match_count;k++) if(r->matches[k].kind==MATCH_QNAME && resolve_domains(e,&r->matches[k].domain,err)) return -1;
            if(r->kind==EXEC_REF || r->kind==EXEC_JUMP || r->kind==EXEC_GOTO) {
                if(!r->to) r->to=find_plugin(e,r->target);
                if(!r->to) return fail(err,"cannot find executable: %s",r->target);
                if((r->kind==EXEC_JUMP || r->kind==EXEC_GOTO) && r->to->kind!=PL_SEQUENCE) return fail(err,"jump/goto target is not a sequence: %s",r->target);
                if(r->kind==EXEC_REF && r->to->kind!=PL_FORWARD && r->to->kind!=PL_CACHE && r->to->kind!=PL_SEQUENCE) return fail(err,"plugin is not executable: %s",r->target);
                if(r->kind==EXEC_REF && resolve_forward(r,err)) return -1;
            }
        }
        if(p->kind==PL_SERVER) {
            plugin *entry=find_plugin(e,p->u.server.target);
            if(!entry || (entry->kind!=PL_SEQUENCE && entry->kind!=PL_FORWARD)) return fail(err,"server entry is not an executable sequence/forward: %s",p->u.server.target);
            size_t index=0;while(e->plugins[index]!=entry) index++;p->u.server.listener.entry=index;
            md_listener *all=grow(e->listeners,e->listener_count+1,sizeof(*all),err);if(!all) return -1;
            e->listeners=all;e->listeners[e->listener_count++]=p->u.server.listener;
        }
    }
    plugin *path[128];for(size_t i=0;i<e->count;i++) if(e->plugins[i]->kind==PL_DOMAIN && domain_cycle(e->plugins[i],path,0,err)) return -1;
    return 0;
}
static bool domain_matches(const domains *d,const char *name) {
    if(md_domain_match(d->own,name)) return true;
    for(size_t i=0;i<d->names.n;i++) if(domain_matches(&d->sets[i]->u.domain,name)) return true;
    return false;
}
static bool rule_matches(const rule *r,const query_context *q) {
    for(size_t i=0;i<r->match_count;i++) {
        const matcher *m=&r->matches[i];bool yes=false;
        switch(m->kind) { case MATCH_QNAME:yes=domain_matches(&m->domain,q->question.name);break;
            case MATCH_RESP:yes=q->response->len!=0;break;case MATCH_TRUE:yes=true;break;case MATCH_FALSE:break; }
        if(m->reverse) yes=!yes;if(!yes) return false;
    }
    return true;
}
static int walk(query_context *q,walker w,char *err);
static int forward_query(query_context *q,plugin *p,const rule *r,char *err) {
    const md_upstream *upstreams=r && r->selected_count ? r->selected : p->u.forward.upstreams;
    size_t count=r && r->selected_count ? r->selected_count : p->u.forward.count;
    int rc=md_forward(upstreams,count,p->u.forward.concurrent,q->query,q->response,err);
    if(!rc) q->revision++;return rc;
}
static void *refresh_thread(void *opaque) {
    refresh_job *job=opaque;md_packet *response=calloc(1,sizeof(*response));char err[MD_ERROR_SIZE]={0};
    if(response) {
        if(job->initial_response) *response=*job->initial_response;
        md_packet scratch;
        query_context q={.engine=job->engine,.query=&job->query,.response=response,.scratch=&scratch,.deadline=md_now()+5};
        if(!md_dns_question(q.query,&q.question,err)) {
            (void)walk(&q,*job->continuation,err);
            /* Match cache.Exec: a downstream side-effect error does not
             * discard an otherwise valid DNS answer from the cache. */
            if(response->len) md_cache_put(job->cache,q.query,response,md_now());
        }
        free(response);
    }
    md_cache_refresh_end(job->cache,&job->query);
    pthread_mutex_lock(&job->engine->lock);job->done=true;pthread_mutex_unlock(&job->engine->lock);return NULL;
}
static void refresh_start(query_context *q,md_cache *cache,const walker *continuation) {
    md_engine *e=q->engine;
    pthread_mutex_lock(&e->lock);
    refresh_job **link=&e->jobs;size_t active=0;
    while(*link) { refresh_job *job=*link;
        if(job->done) { *link=job->next;pthread_join(job->thread,NULL);free(job->initial_response);free(job->continuation);free(job); }
        else { active++;link=&job->next; } }
    if(e->stopping || active>=64 || !md_cache_refresh_begin(cache,q->query)) { pthread_mutex_unlock(&e->lock);return; }
    refresh_job *job=calloc(1,sizeof(*job));size_t count=0;
    for(const walker *w=continuation;w;w=w->back) count++;
    if(!job) { md_cache_refresh_end(cache,q->query);pthread_mutex_unlock(&e->lock);return; }
    job->continuation=calloc(count,sizeof(walker));
    if(!job->continuation) { free(job);md_cache_refresh_end(cache,q->query);pthread_mutex_unlock(&e->lock);return; }
    size_t i=0;for(const walker *w=continuation;w;w=w->back,i++) { job->continuation[i]=*w;job->continuation[i].back=i+1<count ? &job->continuation[i+1] : NULL; }
    if(q->response->len) {
        job->initial_response=malloc(sizeof(md_packet));
        if(!job->initial_response) { free(job->continuation);free(job);md_cache_refresh_end(cache,q->query);pthread_mutex_unlock(&e->lock);return; }
        *job->initial_response=*q->response;
    }
    job->walker_count=count;job->engine=e;job->cache=cache;job->query=*q->query;job->next=e->jobs;
    int rc=pthread_create(&job->thread,NULL,refresh_thread,job);
    if(rc) { free(job->initial_response);free(job->continuation);free(job);md_cache_refresh_end(cache,q->query); }
    else e->jobs=job;
    pthread_mutex_unlock(&e->lock);
}
static int execute_cache(query_context *q,md_cache *cache,walker next,char *err) {
    /* Shared within this query: copy a hit before walking the continuation,
     * so nested cache plugins may safely reuse the same bounded buffer. */
    md_packet *cached=q->scratch;
    int hit=md_cache_get(cache,q->query,cached,md_now());
    if(hit==2) refresh_start(q,cache,&next);
    if(hit) { memcpy(q->response->data,cached->data,cached->len);q->response->len=cached->len;q->revision++; }
    uint64_t revision=q->revision;int rc=walk(q,next,err);
    if(q->response->len && (!hit || q->revision!=revision)) md_cache_put(cache,q->query,q->response,md_now());
    return rc;
}
static int walk_inner(query_context *q,walker w,char *err) {
    while(w.pos<w.sequence->u.sequence.count) {
        if(md_now()>=q->deadline) return fail(err,"query execution deadline exceeded");
        if(++q->steps>4096) return fail(err,"sequence execution exceeds 4096 steps (possible cycle)");
        rule *r=&w.sequence->u.sequence.rules[w.pos++];if(!rule_matches(r,q)) continue;
        switch(r->kind) {
            case EXEC_ACCEPT:return 0;
            case EXEC_REJECT:if(md_dns_error(q->query,q->response,r->rcode)) return fail(err,"cannot construct reject response");q->revision++;return 0;
            case EXEC_RETURN:return w.back ? walk(q,*w.back,err) : 0;
            case EXEC_JUMP:{ walker child={r->to,0,&w};return walk(q,child,err); }
            case EXEC_GOTO:{ walker child={r->to,0,NULL};return walk(q,child,err); }
            case EXEC_NFT:if(q->response->len && md_nft_apply(r->nft,q->response,err)) return -1;break;
            case EXEC_REF:
                if(r->to->kind==PL_CACHE) return execute_cache(q,r->to->u.cache,w,err);
                if(r->to->kind==PL_FORWARD) { if(forward_query(q,r->to,r,err)) return -1; }
                else { walker child={r->to,0,NULL};if(walk(q,child,err)) return -1; }
                break;
        }
    }
    return w.back ? walk(q,*w.back,err) : 0;
}
static int walk(query_context *q,walker w,char *err) {
    if(++q->depth>128) { q->depth--;return fail(err,"sequence recursion exceeds 128 levels (possible cycle)"); }
    int status=walk_inner(q,w,err);q->depth--;return status;
}
md_engine *md_engine_load(const char *path,bool check,char *err) {
    md_engine *e=calloc(1,sizeof(*e));if(!e) { fail(err,"out of memory");return NULL; }
    e->check=check;if(pthread_mutex_init(&e->lock,NULL)) { free(e);fail(err,"cannot initialize engine mutex");return NULL; }
    if(load_config(e,path,0,err) || resolve(e,err)) { md_engine_free(e);return NULL; }return e;
}
size_t md_engine_listener_count(const md_engine *e) { return e->listener_count; }
const md_listener *md_engine_listener(const md_engine *e,size_t i) { return i<e->listener_count ? &e->listeners[i] : NULL; }
bool md_engine_cached_query(md_engine *e,size_t entry,const md_packet *query,md_packet *response) {
    if(!response) return false;response->len=0;
    if(!e || !query || e->check || entry>=e->count) return false;
    plugin *p=e->plugins[entry];
    if(p->kind!=PL_SEQUENCE || p->u.sequence.count<2) return false;
    rule *first=&p->u.sequence.rules[0],*accept=&p->u.sequence.rules[1];
    /* Anything before/after the cache that could change control flow or
     * require a side effect stays on the normal worker sequence path. */
    if(first->kind!=EXEC_REF || first->match_count || (first->arguments && *first->arguments) ||
       !first->to || first->to->kind!=PL_CACHE || accept->kind!=EXEC_ACCEPT ||
       accept->match_count!=1 || accept->matches[0].kind!=MATCH_RESP ||
       accept->matches[0].reverse) return false;
    if(md_cache_get(first->to->u.cache,query,response,md_now())==1) return true;
    response->len=0;return false;
}
int md_engine_query(md_engine *e,size_t entry,const md_packet *query,md_packet *response,char *err) {
    response->len=0;
    if(e->check) return fail(err,"checked configuration cannot execute queries");
    if(entry>=e->count) return fail(err,"invalid entry index");
    md_packet scratch;
    query_context q={.engine=e,.query=query,.response=response,.scratch=&scratch,.deadline=md_now()+5};if(md_dns_question(query,&q.question,err)) return -1;
    plugin *p=e->plugins[entry];int rc;
    if(p->kind==PL_SEQUENCE) { walker w={p,0,NULL};rc=walk(&q,w,err); }
    else if(p->kind==PL_FORWARD) rc=forward_query(&q,p,NULL,err);
    else return fail(err,"entry is not executable");
    if(!rc && !response->len) return fail(err,"sequence completed without a response");return rc;
}
static void plugin_free(plugin *p) {
    switch(p->kind) {
        case PL_DOMAIN:domain_free(&p->u.domain);break;
        case PL_CACHE:md_cache_free(p->u.cache);break;
        case PL_FORWARD:free(p->u.forward.upstreams);break;
        case PL_SEQUENCE:
            for(size_t i=0;i<p->u.sequence.count;i++) { rule *r=&p->u.sequence.rules[i];
                for(size_t j=0;j<r->match_count;j++) if(r->matches[j].kind==MATCH_QNAME) domain_free(&r->matches[j].domain);
                free(r->matches);free(r->target);free(r->arguments);free(r->selected);md_nft_free(r->nft); }
            free(p->u.sequence.rules);break;
        case PL_SERVER:free(p->u.server.target);break;
    }
    free(p->tag);free(p);
}
void md_engine_free(md_engine *e) {
    if(!e) return;pthread_mutex_lock(&e->lock);e->stopping=true;
    refresh_job *jobs=e->jobs;e->jobs=NULL;pthread_mutex_unlock(&e->lock);
    while(jobs) { refresh_job *next=jobs->next;pthread_join(jobs->thread,NULL);free(jobs->initial_response);free(jobs->continuation);free(jobs);jobs=next; }
    for(size_t i=0;i<e->count;i++) plugin_free(e->plugins[i]);free(e->plugins);free(e->listeners);pthread_mutex_destroy(&e->lock);free(e);
}
