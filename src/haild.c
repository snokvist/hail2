// haild.c
#define _GNU_SOURCE 1
#include "hail2.h"
#include "hail_app.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#define DEDUPE_N 128
static uint64_t g_seen_msg[DEDUPE_N];
static uint64_t g_seen_corr[DEDUPE_N];
static size_t   g_seen_msg_i = 0;
static size_t   g_seen_corr_i = 0;

static bool seen64(uint64_t *arr, size_t *idx, uint64_t v){
    for(size_t i=0;i<DEDUPE_N;i++) if(arr[i]==v) return true;
    arr[*idx] = v; *idx = (*idx + 1) % DEDUPE_N; return false;
}

static bool have64(const uint64_t *arr, size_t n, uint64_t v){
    for(size_t i=0;i<n;i++) if(arr[i]==v) return true;
    return false;
}

// Track our own recently-sent DATA message IDs so we don't execute them on echo/relay
#define SENT_N 256
static uint64_t g_sent_mid[SENT_N];
static size_t   g_sent_i = 0;

static inline void remember_sent(uint64_t mid){
    g_sent_mid[g_sent_i] = mid;
    g_sent_i = (g_sent_i + 1) % SENT_N;
}
static inline bool is_own_mid(uint64_t mid){
    for(size_t i=0;i<SENT_N;i++) if (g_sent_mid[i] == mid) return true;
    return false;
}



// ================== util ==================
static void hlogf(const char *fmt, ...){
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
static uint64_t now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000ull + ts.tv_nsec/1000000ull;
}
static void make_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if(fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}
static char* strcasestr_compat(const char *h, const char *n){
#ifdef __GLIBC__
    return strcasestr(h,n);
#else
    if(!h || !n) return NULL;
    size_t nl=strlen(n);
    for(const char *p=h; *p; ++p) if (strncasecmp(p, n, nl)==0) return (char*)p;
    return NULL;
#endif
}
static int hexval(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+c-'a'; if(c>='A'&&c<='F')return 10+c-'A'; return -1; }


// Avoid SIGPIPE on send() when peer disconnects
static ssize_t send_nosig(int fd, const void *buf, size_t n) {
#ifdef MSG_NOSIGNAL
    return send(fd, buf, n, MSG_NOSIGNAL);
#else
    // We already ignore SIGPIPE globally in main()
    return write(fd, buf, n);
#endif
}


// ================== global cfg/state ==================
static haild_config g_cfg;
static char g_alias[64] = {0};
static volatile int g_run = 1;
static void on_sigint(int sig){ (void)sig; g_run = 0; }

// single SSE client
static int g_sse_fd = -1;

// ================== tiny config loader: /etc/hail.conf ==================
static char* trim(char *s){
    while(*s && isspace((unsigned char)*s)) ++s;
    char *e=s+strlen(s); while(e>s && isspace((unsigned char)e[-1])) --e; *e=0;
    return s;
}
static char** split_csv(const char *in){
    if(!in || !*in) { char **z=calloc(1,sizeof(char*)); return z; }
    char *dup=strdup(in), *p=dup;
    size_t cnt=1; for(const char *q=in; *q; ++q) if(*q==',') cnt++;
    char **arr=calloc(cnt+1,sizeof(char*));
    size_t i=0;
    for(;;){
        char *c=strchr(p,','); if(c) *c=0;
        char *t=trim(p); if(*t) arr[i++]=strdup(t);
        if(!c) break; p=c+1;
    }
    free(dup);
    arr[i]=NULL;
    return arr;
}
static void free_csv(char **arr){
    if(!arr) return; for(size_t i=0; arr[i]; ++i) free(arr[i]); free(arr);
}
static int psk_from_hex(const char *hex, uint8_t *out, size_t cap){
    if(!hex) return 0; size_t L=strlen(hex); if(L%2) return -1;
    size_t n=L/2; if(n>cap) return -1;
    for(size_t i=0;i<n;i++){ int h=hexval(hex[2*i]); int l=hexval(hex[2*i+1]); if(h<0||l<0) return -1; out[i]=(uint8_t)((h<<4)|l); }
    return (int)n;
}

// applies conf to hail2_config_t (psk, siglen, keyid, alias, broadcast)
static void haild_apply_conf_to_hail2(hail2_config_t *hc, const char *path){
    // defaults
    hc->enable_broadcast = true;
    hc->sig_trunc = 16;
    hc->key_id = 1;

    FILE *f=fopen(path,"r"); if(!f) return;
    char line[512];
    static uint8_t psk[64]; size_t psk_len=0;
    while(fgets(line,sizeof(line),f)){
        char *s=trim(line);
        if(!*s || *s=='#') continue;
        char *eq=strchr(s,'='); if(!eq) continue;
        *eq=0; char *k=trim(s), *v=trim(eq+1);

        if(!strcmp(k,"alias")){ snprintf(hc->alias,sizeof(hc->alias),"%s",v); }
        else if(!strcmp(k,"roles")){ /* handled outside to g_cfg */ }
        else if(!strcmp(k,"caps")){ /* handled outside to g_cfg */ }
        else if(!strcmp(k,"psk_hex")){
            int n=psk_from_hex(v, psk, sizeof(psk));
            if(n>0){ hc->psk=psk; hc->psk_len=(size_t)n; }
        }else if(!strcmp(k,"sig_trunc")){
            hc->sig_trunc = (uint8_t)strtoul(v,NULL,10);
        }else if(!strcmp(k,"key_id")){
            hc->key_id = (uint32_t)strtoul(v,NULL,10);
        }else if(!strcmp(k,"broadcast")){
            hc->enable_broadcast = (!!strtoul(v,NULL,10));
        }
    }
    fclose(f);
}
static void haild_load_conf(const char *path, haild_config *dcfg){
    // defaults
    dcfg->alias       = NULL;
    dcfg->roles       = NULL;
    dcfg->caps        = NULL;
    dcfg->exec_prog   = "/usr/bin/hail-exec";
    dcfg->http_enable = true;
    dcfg->http_port   = 8080;

    FILE *f=fopen(path,"r"); if(!f) return;
    char line[512]; char *roles=NULL,*caps=NULL,*exec=NULL; int http_en=-1, http_port=-1;
    static char alias_buf[64]; alias_buf[0]=0;
    while(fgets(line,sizeof(line),f)){
        char *s=trim(line);
        if(!*s || *s=='#') continue;
        char *eq=strchr(s,'='); if(!eq) continue;
        *eq=0; char *k=trim(s), *v=trim(eq+1);
        if(!strcmp(k,"alias")){ snprintf(alias_buf,sizeof(alias_buf),"%s",v); dcfg->alias=alias_buf; }
        else if(!strcmp(k,"roles")){ roles=strdup(v); }
        else if(!strcmp(k,"caps")){ caps=strdup(v); }
        else if(!strcmp(k,"exec_prog")){ exec=strdup(v); }
        else if(!strcmp(k,"http_enable")){ http_en=(int)strtoul(v,NULL,10); }
        else if(!strcmp(k,"http_port")){ http_port=(int)strtoul(v,NULL,10); }
    }
    fclose(f);
    if(roles) dcfg->roles = (const char**)split_csv(roles);
    if(caps)  dcfg->caps  = (const char**)split_csv(caps);
    if(exec)  dcfg->exec_prog = exec;
    if(http_en>=0) dcfg->http_enable = !!http_en;
    if(http_port>0) dcfg->http_port = (uint16_t)http_port;
}



// --- varint encoder compatible with hail2_varint_decode() ---
static size_t put_varint(uint8_t *p, uint8_t *pe, uint64_t v){
    size_t n = 0;
    do {
        if (p >= pe) return 0;
        uint8_t b = (uint8_t)(v & 0x7f);
        v >>= 7;
        if (v) b |= 0x80;
        *p++ = b; n++;
    } while (v);
    return n;
}

// ================== HTTP (GET /health, GET /nodes, GET /events, POST /send, POST /exec local) ==================
static void http_write_cors(int fd) {
    dprintf(fd, "Access-Control-Allow-Origin: *\r\n");
    dprintf(fd, "Access-Control-Allow-Headers: Content-Type\r\n");
    dprintf(fd, "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
}

static void http_send(int cfd, const char *status,
                      const char *ctype, const char *body, size_t blen)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-cache\r\n",
        status, ctype, blen);
    (void)send_nosig(cfd, hdr, (size_t)n);
    // CORS
    http_write_cors(cfd);
    (void)send_nosig(cfd, "\r\n", 2);

    if (blen) (void)send_nosig(cfd, body, blen);
}
static void http_send_sse_headers(int cfd){
    dprintf(cfd, "HTTP/1.1 200 OK\r\n");
    http_write_cors(cfd);
    dprintf(cfd,
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n\r\n");
    // Prime the stream so proxies keep it open
    (void)send_nosig(cfd, ":\n\n", 3);
}
static void sse_push_line(const char *line){
    if (g_sse_fd < 0 || !line) return;

    // Try to write, treat EPIPE/ECONNRESET as a clean disconnect
    if (send_nosig(g_sse_fd, "data: ", 6) < 0) goto sse_dead_maybe;
    if (send_nosig(g_sse_fd, line, strlen(line)) < 0) goto sse_dead_maybe;
    if (send_nosig(g_sse_fd, "\n\n", 2) < 0) goto sse_dead_maybe;
    return;

sse_dead_maybe:
    if (errno == EPIPE || errno == ECONNRESET) {
        close(g_sse_fd);
        g_sse_fd = -1;
    }
    // For EAGAIN/EWOULDBLOCK just drop the event silently.
}

static int json_nodes(hail2_ctx *ctx, char *out, size_t cap){
    hail2_node_info_t arr[32];
    size_t count = hail2_nodes_copy(ctx, arr, 32, /*include_self*/true);
    size_t off = 0;
    int n = snprintf(out+off, cap-off, "{\"nodes\":[");
    if(n<0) return 0; off += (size_t)n;

    for(size_t i=0;i<count;i++){
        uint32_t ip = arr[i].ip4;
        unsigned a =  ip        & 255u;
        unsigned b = (ip >> 8)  & 255u;
        unsigned c = (ip >> 16) & 255u;
        unsigned d = (ip >> 24) & 255u;
        n = snprintf(out+off, cap-off,
            "%s{\"src\":\"%016llx\",\"ip\":\"%u.%u.%u.%u\",\"port\":%u,\"age_ms\":%u}",
            (i?",":""), (unsigned long long)arr[i].src_id, a,b,c,d, arr[i].port, (unsigned)arr[i].age_ms);
        if(n<0) return 0; off += (size_t)n;
        if(off>=cap) break;
    }
    n = snprintf(out+off, cap-off, "]}");
    if(n<0) return 0; off += (size_t)n;
    return (int)off;
}

// very small JSON getter: extracts the string value after first colon, strips quotes
static void jget_str(const char *body, const char *key, char *dst, size_t cap){
    dst[0]=0; if(!body || !key) return;
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    char *p = strcasestr_compat(body, pat); if(!p) return;
    p = strchr(p,':'); if(!p) return; p++;
    while(*p==' '||*p=='\t') ++p;
    if(*p=='\"'){ ++p; char *e=strchr(p,'\"'); if(!e) return; size_t L=(size_t)(e-p); if(L>=cap) L=cap-1; memcpy(dst,p,L); dst[L]=0; }
}
static bool jget_bool(const char *body, const char *key, bool dflt){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    char *p = strcasestr_compat(body, pat); if(!p) return dflt;
    p = strchr(p,':'); if(!p) return dflt; p++;
    while(*p==' '||*p=='\t') ++p;
    if(!strncasecmp(p,"true",4)) return true;
    if(!strncasecmp(p,"false",5)) return false;
    return dflt;
}
static uint32_t jget_uint(const char *body, const char *key, uint32_t dflt){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    char *p = strcasestr_compat(body, pat); if(!p) return dflt;
    p = strchr(p,':'); if(!p) return dflt; p++;
    while(*p==' '||*p=='\t') ++p;
    return (uint32_t)strtoul(p,NULL,10);
}



// NOTE: built-in UI (same file I sent earlier), trimmed only for length.
// You can replace with the full version; this one is complete.
static const char *k_index_html =
"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
"<title>haild console</title>"
"<style>"
":root{--bg:#0b0f14;--panel:#111722;--text:#e9eef5;--muted:#aab6c8;--ok:#3ad29f;--warn:#f7c948;--err:#ff6b6b;--tag:#4c6fff;--chip:#2b3242;--btn:#1f2a3c;--btnh:#27354b}"
"*{box-sizing:border-box;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica Neue,Arial}"
"body{margin:0;background:var(--bg);color:var(--text)}header{padding:14px 16px;background:linear-gradient(180deg,#101827,#0d131e);border-bottom:1px solid #1b2536;position:sticky;top:0;z-index:5}"
"h1{margin:0;font-size:18px}main{display:grid;grid-template-columns:380px 1fr;gap:14px;padding:14px}"
"section{background:var(--panel);border:1px solid #1b2536;border-radius:14px;padding:12px}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}"
"label{font-size:12px;color:var(--muted);margin-right:6px}"
"input[type=text],input[type=number],textarea,select{background:#0d1320;color:var(--text);border:1px solid #212b3d;border-radius:10px;padding:8px 10px;outline:none}"
"input[type=text]:focus,textarea:focus,select:focus{border-color:#345;box-shadow:0 0 0 2px #22324a inset}"
"button{background:var(--btn);color:var(--text);border:1px solid #2a3950;padding:8px 12px;border-radius:10px;cursor:pointer}"
"button:hover{background:var(--btnh)}.pill{background:var(--chip);border:1px solid #2a3950;padding:3px 8px;border-radius:999px;font-size:12px}"
".tag{background:#213166;color:#cfd9ff;border:1px solid #324889}.ok{color:var(--ok)}.warn{color:var(--warn)}.err{color:var(--err)}"
".stack{display:flex;flex-direction:column;gap:8px}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}"
".log{height:52vh;overflow:auto;background:#0b101b;border:1px solid #182238;border-radius:10px;padding:8px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.35}"
".log .line{white-space:pre-wrap;word-break:break-word;margin:0;padding:4px 6px;border-bottom:1px dashed #1a2436}"
".log .line:last-child{border-bottom:none}.kbd{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0e1625;border:1px solid #23314a;padding:2px 6px;border-radius:6px}"
".hl{color:#a5b8ff}.small{font-size:12px;color:var(--muted)}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}.hint{margin-top:6px;color:#93a5c6;font-size:12px}"
".flex1{flex:1 1 auto}.sep{height:1px;background:#1b2536;margin:8px 0}.nodes{display:flex;flex-wrap:wrap;gap:6px}.node{background:#0d1320;border:1px solid #212b3d;border-radius:10px;padding:6px 8px}"
"</style>"
"<header><h1>haild console <span class=small>– quick test UI for /health, /nodes, /events, /send</span></h1></header>"
"<main>"
"<section class=stack>"
" <div class=stack>"
"  <div class=row><label>Base URL</label><input id=baseUrl type=text value=\"\" class=flex1 placeholder=\"http://host:8080\"></div>"
"  <div class=row><button id=btnConnectSSE>Connect events</button><button id=btnDisconnectSSE>Disconnect</button><span id=sseStatus class=\"pill tag\">SSE: idle</span></div>"
"  <div class=row><button id=btnHealth>GET /health</button><button id=btnNodes>GET /nodes</button></div>"
" </div><div class=sep></div>"
" <div class=stack><strong>Quick send</strong>"
"  <div class=grid2>"
"    <button id=btnHBsigned>Broadcast HB (signed JSON)</button>"
"    <button id=btnHBunsigned>Broadcast HB (unsigned JSON)</button>"
"    <button id=btnExecOn>EXEC /sys/led {\"state\":\"on\"}</button>"
"    <button id=btnExecToggle>EXEC /sys/led {\"state\":\"toggle\"}</button>"
"  </div><div class=hint>EXEC uses TLV app payload and is accepted only if signed.</div>"
" </div><div class=sep></div>"
" <div class=stack><strong>Custom send</strong>"
"  <div class=row><label>dst</label><input id=dst type=text value=broadcast class=flex1>"
"  </div><div class=row><label>method</label><input id=method type=text value=EXEC>"
"  <label>path</label><input id=path type=text value=\"/sys/led\" class=flex1></div>"
"  <div class=row><label>args (JSON)</label><input id=args type=text value='{\"state\":\"on\"}' class=\"flex1 mono\"></div>"
"  <div class=row><label>ct</label><select id=ct><option value=tlv selected>tlv</option><option value=json>json</option></select>"
"  <label class=small>signed</label><input id=signed type=checkbox checked>"
"  <label class=small>ack</label><input id=ack type=checkbox checked>"
"  <label class=small>relay</label><input id=relay type=checkbox checked>"
"  <button id=btnSend>POST /send</button></div>"
"</section>"
"<section class=stack>"
" <div class=row><strong>Event log</strong><span class=small>(from <span class=kbd>GET /events</span>)</span><span id=logCount class=pill>0</span><span class=flex1></span><button id=btnClear>Clear</button></div>"
" <div id=log class=log aria-live=polite></div><div class=sep></div>"
" <div class=row><strong>Nodes</strong><span class=small>(from <span class=kbd>GET /nodes</span>)</span><span class=flex1></span><button id=btnNodes2>Refresh</button></div>"
" <div id=nodes class=nodes></div>"
"</section></main>"
"<script>"
"(()=>{const $=s=>document.querySelector(s);const baseUrlEl=$('#baseUrl');const sseStatus=$('#sseStatus');const logEl=$('#log');const logCount=$('#logCount');const nodesEl=$('#nodes');let es=null,lines=0;"
"function setSSE(s,c='tag'){sseStatus.textContent=`SSE: ${s}`;sseStatus.className=`pill ${c}`}"
"function toObj(x){if(typeof x!== 'string') return x;try{return JSON.parse(x)}catch{return x}}"
"function logJSON(o){const d=document.createElement('div');d.className='line';let t;if(typeof o==='string'){try{t=JSON.stringify(JSON.parse(o))}catch{t=JSON.stringify(o)}}else{t=JSON.stringify(o)};d.textContent=t;logEl.appendChild(d);lines++;logCount.textContent=lines;if(logEl.children.length>1000)logEl.removeChild(logEl.firstChild);logEl.scrollTop=logEl.scrollHeight}"
"async function apiGet(path){const u=new URL(path,baseUrlEl.value).toString();const r=await fetch(u);const t=await r.text();try{return JSON.parse(t)}catch{return t}}"
"async function apiPost(path,bodyObj){const u=new URL(path,baseUrlEl.value).toString();const b=JSON.stringify(bodyObj);const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:b});const t=await r.text();try{return JSON.parse(t)}catch{return t}}"
"$('#btnConnectSSE').addEventListener('click',()=>{if(es)try{es.close()}catch{};const u=new URL('/events',baseUrlEl.value).toString();es=new EventSource(u);setSSE('connecting…','tag');es.onopen=()=>setSSE('connected','ok');es.onerror=()=>setSSE('error','err');es.onmessage=(ev)=>{let o=ev.data;try{o=JSON.parse(ev.data)}catch{}logJSON(o)}});"
"$('#btnDisconnectSSE').addEventListener('click',()=>{if(es){es.close();es=null}setSSE('idle','tag')});"
"async function doHealth(){try{const j=await apiGet('/health');logJSON(j)}catch(e){logJSON({error:String(e)})}}"
"async function doNodes(){try{const j=await apiGet('/nodes');nodesEl.innerHTML='';if(j&&j.nodes&&Array.isArray(j.nodes)){j.nodes.forEach(n=>{const d=document.createElement('div');d.className='node';d.innerHTML=`<div class=mono>${n.src}</div><div class=small>${n.ip}:${n.port}</div><div class=small>${n.age_ms} ms</div>`;nodesEl.appendChild(d)})}logJSON(j)}catch(e){logJSON({error:String(e)})}}"
"$('#btnHealth').addEventListener('click',doHealth);$('#btnNodes').addEventListener('click',doNodes);$('#btnNodes2').addEventListener('click',doNodes);"
"async function sendHB(signed){const body={dst:'broadcast',method:'DATA',path:'/',args:{hb:1},ct:'json',signed:!!signed,ack:true,relay:false,req:Math.floor(Math.random()*1e7)};const res=await apiPost('/send',body);logJSON(res)}"
"async function sendExec(state){const body={dst:'broadcast',method:'EXEC',path:'/sys/led',args:{state:state},ct:'tlv',signed:true,ack:true,relay:false,req:Math.floor(Math.random()*1e7)};const res=await apiPost('/send',body);logJSON(res)}"
"$('#btnHBsigned').addEventListener('click',()=>sendHB(true));$('#btnHBunsigned').addEventListener('click',()=>sendHB(false));$('#btnExecOn').addEventListener('click',()=>sendExec('on'));$('#btnExecToggle').addEventListener('click',()=>sendExec('toggle'));"
"$('#btnSend').addEventListener('click',async()=>{const argsText=$('#args').value.trim();let args={};if(argsText){try{args=JSON.parse(argsText)}catch(e){logJSON({error:'Invalid args JSON',input:argsText});return}}const body={dst:$('#dst').value.trim()||'broadcast',method:$('#method').value.trim()||'EXEC',path:$('#path').value.trim()||'/',args:args,ct:$('#ct').value,signed:$('#signed').checked,ack:$('#ack').checked,relay:$('#relay').checked,req:Math.floor(Math.random()*1e7)};try{const res=await apiPost('/send',body);logJSON(res)}catch(e){logJSON({error:String(e)})}});"
"$('#btnClear').addEventListener('click',()=>{logEl.innerHTML='';lines=0;logCount.textContent='0'});"
"(function init(){const here=location.origin;$('#baseUrl').value=here;document.title+=' – '+here;$('#btnConnectSSE').click();doHealth();doNodes()})();"
"})();</script></html>";

// ---------- end static UI ----------

// === static UI + CORS helpers (once) =========================================


static void http_send_text(int fd, int code, const char *ct, const char *body, size_t n) {
    dprintf(fd, "HTTP/1.1 %d OK\r\n", code);
    http_write_cors(fd);
    dprintf(fd, "Content-Type: %s\r\n", ct);
    dprintf(fd, "Content-Length: %zu\r\n", n);
    dprintf(fd, "Cache-Control: no-cache\r\n");
    dprintf(fd, "Connection: close\r\n\r\n");
    if (n) (void)send_nosig(fd, body, n);
}

static int try_read_file(const char *path, char **out_buf, size_t *out_len) {
    struct stat st; *out_buf=NULL; *out_len=0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) { close(fd); return -1; }
    size_t n = (size_t)st.st_size;
    char *buf = (char*)malloc(n);
    if (!buf) { close(fd); return -1; }
    ssize_t r = read(fd, buf, n);
    close(fd);
    if (r != (ssize_t)n) { free(buf); return -1; }
    *out_buf = buf; *out_len = n;
    return 0;
}

// disk override paths for UI
static const char *k_ui_disk_paths[] = {
  "/usr/share/haild/index.html",
  "/etc/hail/index.html",
  NULL
};



static void http_handle_one(hail2_ctx *ctx, haild_config *cfg, int cfd){
    // --- read request into buffer ---
    char req[8192];
    int r = (int)read(cfd, req, sizeof(req)-1);
    if (r <= 0) return;
    req[r] = 0;

    // --- parse request line into method + path ---
    char method[8] = {0};
    char path[512] = {0};
    {
        // find first line
        char *eol = strstr(req, "\r\n");
        if (!eol) eol = strchr(req, '\n');
        if (eol) *eol = 0;                       // temporarily terminate first line
        // ex: "GET /something HTTP/1.1"
        (void)sscanf(req, "%7s %511s", method, path);
        if (eol) *eol = '\n';                    // restore
        if (method[0] == 0) strcpy(method, "GET");
        if (path[0] == 0)   strcpy(path, "/");
    }

    // ================= STATIC UI & CORS HANDLERS =================
    // CORS preflight
    if (!strcmp(method, "OPTIONS")) {
        dprintf(cfd, "HTTP/1.1 204 No Content\r\n");
        http_write_cors(cfd);
        dprintf(cfd, "Content-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    }

    // Serve index: prefer disk, fallback to built-in
    if (!strcmp(method, "GET") && (!strcmp(path, "/") || !strcmp(path, "/index.html"))) {
        for (int i=0; k_ui_disk_paths[i]; ++i) {
            char *buf=NULL; size_t n=0;
            if (try_read_file(k_ui_disk_paths[i], &buf, &n)==0) {
                http_send_text(cfd, 200, "text/html; charset=utf-8", buf, n);
                free(buf);
                return;
            }
        }
        http_send_text(cfd, 200, "text/html; charset=utf-8", k_index_html, strlen(k_index_html));
        return;
    }

    // /health
    if(!strncmp(req,"GET /health", 11)){
        char roles[512]="[]", caps[512]="[]";
        if(cfg->roles && cfg->roles[0]){
            size_t off=0; off+=snprintf(roles+off,sizeof(roles)-off,"[");
            for(size_t i=0; cfg->roles[i]; ++i){
                off+=snprintf(roles+off,sizeof(roles)-off,"%s\"%s\"", (i?",":""), cfg->roles[i]);
            }
            off+=snprintf(roles+off,sizeof(roles)-off,"]");
        }
        if(cfg->caps && cfg->caps[0]){
            size_t off=0; off+=snprintf(caps+off,sizeof(caps)-off,"[");
            for(size_t i=0; cfg->caps[i]; ++i){
                off+=snprintf(caps+off,sizeof(caps)-off,"%s\"%s\"", (i?",":""), cfg->caps[i]);
            }
            off+=snprintf(caps+off,sizeof(caps)-off,"]");
        }
        char body[512];
        int n = snprintf(body, sizeof(body),
            "{\"ok\":true,\"alias\":\"%s\",\"roles\":%s,\"caps\":%s}\n",
            g_alias, roles, caps);
        http_send(cfd, "200 OK", "application/json", body, (size_t)n);
        return;
    }

    // /nodes
    if(!strncmp(req,"GET /nodes", 10)){
        char buf[4096];
        int n = json_nodes(ctx, buf, sizeof(buf));
        http_send(cfd, "200 OK", "application/json", buf, (size_t)n);
        return;
    }

    // /events (Server-Sent Events, one client slot)
if(!strncmp(req,"GET /events", 11)){
    if (g_sse_fd >= 0) { close(g_sse_fd); g_sse_fd = -1; }

    // Keepalive helps detect dead clients sooner
    int one = 1;
    setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
    int idle = 30; setsockopt(cfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    int intvl = 10; setsockopt(cfd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    int cnt = 3; setsockopt(cfd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif

    make_nonblock(cfd);
    http_send_sse_headers(cfd);
    g_sse_fd = cfd;
    return; // keep open (do NOT close here)
}


    // POST /exec  (local execution only)
    if(!strncmp(req,"POST /exec", 10)){
        // naive body locate
        char *body = strstr(req, "\r\n\r\n"); if(!body){ http_send(cfd,"400 Bad Request","text/plain","Bad Request\n",11); return; }
        body += 4;

        char path[256]={0}, args[1024]={0};
        jget_str(body,"path",path,sizeof(path));
        jget_str(body,"args",args,sizeof(args));

        haild_exec_req ex = {
            .method="EXEC",
            .path = path[0]?path:"/",
            .args_json = args[0]?args:NULL,
            .req_id = (uint32_t)(now_ms() & 0x00FFFFFFu),
            .src_id = 0, .ip4_be = 0, .port = 0,
            .content_type = "json"
        };
        char out[2048];
        ssize_t on = haild_exec_run(&ex, out, sizeof(out));
        if(on<0){ http_send(cfd,"500 Internal Server Error","text/plain","exec failed\n",12); }
        else { http_send(cfd,"200 OK","text/plain", out, (size_t)on); }
        return;
    }

    // POST /send  (send into HAIL mesh)
// POST /send  (send into HAIL mesh)
if(!strncmp(req,"POST /send", 10)){
    char *body = strstr(req, "\r\n\r\n"); if(!body){ http_send(cfd,"400 Bad Request","text/plain","Bad Request\n",11); return; }
    body += 4;

    char dst[128]={0}, method[16]={0}, path[256]={0}, args[1024]={0}, ct[16]={0};
    jget_str(body,"dst",dst,sizeof(dst));             // "broadcast" or "ip:port"
    jget_str(body,"method",method,sizeof(method));     // "EXEC"
    jget_str(body,"path",path,sizeof(path));          // "/sys/led"
    jget_str(body,"args",args,sizeof(args));          // JSON string (optional)
    jget_str(body,"ct",ct,sizeof(ct));                // "tlv"|"json" (default tlv)
    bool signed_only = jget_bool(body,"signed",true);  (void)signed_only; // currently informational
    bool ack_req     = jget_bool(body,"ack",true);
    bool relay_ok    = jget_bool(body,"relay",true);
    uint32_t reqid   = jget_uint(body,"req", (uint32_t)(now_ms()&0xffffff));

    hail2_addr_t peer = (hail2_addr_t){0};
    hail2_addr_t *peerp = NULL;
    if(strcmp(dst,"broadcast")!=0 && dst[0]){
        // parse "A.B.C.D:PORT"
        unsigned A=0,B=0,C=0,D=0,P=HAIL2_DEFAULT_PORT;
        sscanf(dst,"%u.%u.%u.%u:%u",&A,&B,&C,&D,&P);
        peer.ip4 = (uint32_t)((D<<24)|(C<<16)|(B<<8)|A);
        peer.port= (uint16_t)P;
        peerp = &peer;
        relay_ok = false; // unicast doesn't relay
    }

    uint8_t payload[1024]; size_t pn=0;

    if(!ct[0] || !strcmp(ct,"tlv")){
        // TLV APP: 1=METHOD, 2=PATH, 3=ARGS, 4=REQID(be32), lengths are varint
        uint8_t *p = payload, *pe = payload + sizeof(payload);

        // METHOD
        if(method[0]){
            *p++ = 1; if(p>=pe) goto badreq;
            size_t L = strlen(method);
            size_t vn = put_varint(p, pe, L); if(!vn) goto badreq; p += vn;
            if(p+L>pe) goto badreq; memcpy(p, method, L); p += L;
        }
        // PATH
        if(path[0]){
            *p++ = 2; if(p>=pe) goto badreq;
            size_t L = strlen(path);
            size_t vn = put_varint(p, pe, L); if(!vn) goto badreq; p += vn;
            if(p+L>pe) goto badreq; memcpy(p, path, L); p += L;
        }
        // ARGS
        if(args[0]){
            size_t L = strlen(args);
            *p++ = 3; if(p>=pe) goto badreq;
            size_t vn = put_varint(p, pe, L); if(!vn) goto badreq; p += vn;
            if(p+L>pe) goto badreq; memcpy(p, args, L); p += L;
        }
        // REQID (always 4 bytes)
        {
            *p++ = 4; if(p>=pe) goto badreq;
            uint32_t be = htonl(reqid);
            size_t vn = put_varint(p, pe, 4); if(!vn) goto badreq; p += vn;
            if(p+4>pe) goto badreq; memcpy(p, &be, 4); p += 4;
        }
        pn = (size_t)(p - payload);
    }else{
        // JSON payload
        pn = (size_t)snprintf((char*)payload,sizeof(payload),
                              "{\"m\":\"%s\",\"p\":\"%s\"%s%s%s}",
                              method[0]?method:"EXEC",
                              path[0]?path:"/",
                              args[0]? ",\"a\":" :"",
                              args[0]? args :"",
                              args[0]? "" :"");
    }

    hail2_opts_t o; hail2_opts_reset(&o);
    if(!ct[0] || !strcmp(ct,"tlv")) hail2_opts_content_type(&o, HAIL2_CT_TLV);
    else                            hail2_opts_content_type(&o, HAIL2_CT_JSON);

    uint64_t mid=0;
    int rc = hail2_send_data(ctx, peerp, payload, pn, ack_req, relay_ok, &o, &mid);
    if(rc<0) http_send(cfd,"500 Internal Server Error","text/plain","send failed\n",12);
    else     http_send(cfd,"200 OK","application/json","{\"ok\":true}\n",13);
    return;

badreq:
    http_send(cfd,"400 Bad Request","text/plain","bad payload\n",12);
    return;
}

}

static int http_listen(uint16_t port){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s<0) return -1;
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(s,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
#endif
    struct sockaddr_in a={0};
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY);
    a.sin_port=htons(port);
    if(bind(s,(struct sockaddr*)&a,sizeof(a))<0){ close(s); return -1; }
    if(listen(s,8)<0){ close(s); return -1; }
    make_nonblock(s);
    return s;
}
static void http_accept(hail2_ctx *ctx, haild_config *cfg, int lfd){
    int c = accept(lfd, NULL, NULL);
    if(c<0) return;
    // If it's /events we keep it open in handler; else we serve and close
    // Peek minimal
    char peek[4]; int r = recv(c, peek, sizeof(peek), MSG_PEEK);
    (void)r;
    http_handle_one(ctx, cfg, c);
    if(c != g_sse_fd) close(c); // /events keeps the fd
}

// ================== EXEC runner ==================
ssize_t haild_exec_run(const haild_exec_req *req, char *out, size_t cap){
    if(!req || !out || !cap) return -1;

    // Only execute if node has capability "exec"
    if(!haild_has_cap(&g_cfg,"exec")) return -1;

    char e_method[32], e_path[256], e_args[1024], e_reqid[32], e_src[64], e_ct[32], e_peer[32], e_alias[96];
    snprintf(e_method,sizeof(e_method),"HAIL_METHOD=%s", req->method?req->method:"");
    snprintf(e_path,  sizeof(e_path),  "HAIL_PATH=%s",   req->path?req->path:"/");
    snprintf(e_args,  sizeof(e_args),  "HAIL_ARGS=%s",   req->args_json?req->args_json:"");
    snprintf(e_reqid, sizeof(e_reqid), "HAIL_REQID=%u",  req->req_id);
    snprintf(e_src,   sizeof(e_src),   "HAIL_SRC=%016llx",(unsigned long long)req->src_id);
    snprintf(e_ct,    sizeof(e_ct),    "HAIL_CT=%s",     req->content_type?req->content_type:"");
    uint32_t ip = req->ip4_be; unsigned A=ip&255u,B=(ip>>8)&255u,C=(ip>>16)&255u,D=(ip>>24)&255u;
    snprintf(e_peer,  sizeof(e_peer),  "HAIL_PEER=%u.%u.%u.%u:%u", A,B,C,D, req->port);
    snprintf(e_alias, sizeof(e_alias), "HAIL_ALIAS=%s", g_alias);

    putenv(e_method); putenv(e_path); putenv(e_args);
    putenv(e_reqid);  putenv(e_src);  putenv(e_ct); putenv(e_peer); putenv(e_alias);

    // Pluggable program if you want; for now simple echo as a safe default
    const char *cmd = g_cfg.exec_prog && *g_cfg.exec_prog
                      ? g_cfg.exec_prog
                      : "/bin/sh -c 'echo \"$HAIL_METHOD $HAIL_PATH $HAIL_ARGS\"'";

    FILE *P = popen(cmd, "r");
    if(!P) return -1;

    size_t off = 0;
    for(;;){
        if(off >= cap) break;
        size_t got = fread(out+off, 1, cap-off, P);
        if(got==0) break;
        off += got;
    }
    pclose(P);
    return (ssize_t)off;
}

// ================== HAIL callbacks ==================
static const char* tstr(uint16_t t){
    switch(t){
        case HAIL2_T_BEACON:   return "BEACON";
        case HAIL2_T_ANNOUNCE: return "ANNOUNCE";
        case HAIL2_T_PING:     return "PING";
        case HAIL2_T_PONG:     return "PONG";
        case HAIL2_T_ACK:      return "ACK";
        case HAIL2_T_DATA:     return "DATA";
        case HAIL2_T_TOPOQ:    return "TOPOQ";
        case HAIL2_T_TOPOA:    return "TOPOA";
        default:               return "UNK";
    }
}
static const char* ctstr(uint8_t ct){
    switch(ct){
        case 1: /* HAIL2_CT_JSON */ return "json";
        case 4: /* HAIL2_CT_TLV  */ return "tlv";
        default:                    return "bin";
    }
}

static void on_event(hail2_ctx *ctx, const hail2_event_info_t *ev, void *u){
    (void)ctx; (void)u;
    if(ev->kind == HAIL2_EVT_NODE_UP){
        hlogf("NODE_UP src=%016llx ip=%u.%u.%u.%u:%u",
            (unsigned long long)ev->src_id,
            ev->ip4&255u,(ev->ip4>>8)&255u,(ev->ip4>>16)&255u,(ev->ip4>>24)&255u,
            ev->port);
    }
}

static int henv_build(char *dst, size_t cap,
                      const hail2_meta_t *m,
                      const char *alias,
                      const char *type_str,
                      const char *ct_str,
                      uint64_t qid)
{
    uint32_t ip = m->rx_from_ip4;
    unsigned a =  ip        & 255u;
    unsigned b = (ip >> 8)  & 255u;
    unsigned c = (ip >> 16) & 255u;
    unsigned d = (ip >> 24) & 255u;

    if(qid){
        return snprintf(dst, cap,
          "{\"v\":1,\"src\":\"%016llx\",\"a\":\"%s\",\"ip\":\"%u.%u.%u.%u\",\"p\":%u,"
          "\"t\":\"%s\",\"ct\":\"%s\",\"msg\":\"%016llx\",\"hop\":%u,\"ttl\":%u,"
          "\"sig\":%u,\"correl\":\"%016llx\"}",
          (unsigned long long)m->src_id, alias?alias:"",
          a,b,c,d, m->rx_from_port, type_str?type_str:"", ct_str?ct_str:"",
          (unsigned long long)m->msg_id, m->hop, m->ttl,
          (unsigned)(m->signed_present && m->signed_ok),
          (unsigned long long)qid);
    }else{
        return snprintf(dst, cap,
          "{\"v\":1,\"src\":\"%016llx\",\"a\":\"%s\",\"ip\":\"%u.%u.%u.%u\",\"p\":%u,"
          "\"t\":\"%s\",\"ct\":\"%s\",\"msg\":\"%016llx\",\"hop\":%u,\"ttl\":%u,"
          "\"sig\":%u}",
          (unsigned long long)m->src_id, alias?alias:"",
          a,b,c,d, m->rx_from_port, type_str?type_str:"", ct_str?ct_str:"",
          (unsigned long long)m->msg_id, m->hop, m->ttl,
          (unsigned)(m->signed_present && m->signed_ok));
    }
}

static void henv_print_json_payload(FILE *f, const uint8_t *p, size_t n){
    if(!p || !n) return;
    fprintf(f, ",\"payload\":");
    fwrite(p, 1, n, f);
}

static void on_frame(hail2_ctx *ctx, const hail2_meta_t *m, const uint8_t *app, size_t n, void *u){
    (void)u;
    char head[512];
    const char *type = tstr(m->type);
    const char *ct   = m->has_ct ? ctstr(m->ct) : "bin";

// Robust de-dup for broadcast + relayed copies.
// Rule: execute a command only once per "command id":
//   - for originals: use msg_id
//   - for relayed copies: use correl_id (which equals the original msg_id)
if (m->type == HAIL2_T_DATA) {
    // 1) Drop exact dupes by message id
    if (have64(g_seen_msg, DEDUPE_N, m->msg_id)) return;

    if (m->has_correl) {
        // 2) This is a relayed copy — drop if we've seen the original msg_id before
        if (have64(g_seen_corr, DEDUPE_N, m->correl_id)) return;
        if (have64(g_seen_msg,  DEDUPE_N, m->correl_id)) return;

        // Not seen, remember correl_id in the correl-ring so any later relays get dropped
        g_seen_corr[g_seen_corr_i] = m->correl_id;
        g_seen_corr_i = (g_seen_corr_i + 1) % DEDUPE_N;
    } else {
        // 3) Original (no correl) — remember its msg_id as a "command id"
        g_seen_corr[g_seen_corr_i] = m->msg_id;
        g_seen_corr_i = (g_seen_corr_i + 1) % DEDUPE_N;
    }

    // Finally, remember this message id too (prevents same-packet repeats)
    g_seen_msg[g_seen_msg_i] = m->msg_id;
    g_seen_msg_i = (g_seen_msg_i + 1) % DEDUPE_N;
}


    uint64_t qid = m->has_correl ? m->correl_id : 0;
    int hn = henv_build(head, sizeof(head), m, g_alias, type, ct, qid);
    if(hn<0) hn=0;


    // default log + SSE line
    // DATA(JSON)
    if(m->type == HAIL2_T_DATA && m->has_ct && m->ct==1 /*JSON*/ && n>0){
        fwrite(head, 1, (size_t)hn, stdout);
        henv_print_json_payload(stdout, app, n);
        fputs("}\n", stdout);
        fflush(stdout);

        char line[1024];
        size_t ln = (size_t)snprintf(line,sizeof(line),"%s,\"payload\":%.*s}\n", head, (int)n, (const char*)app);
        if(ln < sizeof(line)) sse_push_line(line);
        // nothing else to do
        return;
    }

    // DATA(TLV): parse and potentially EXEC (signed-only)
    if(m->type == HAIL2_T_DATA && m->has_ct && m->ct==4 /*TLV*/ && n>0){
        const uint8_t *p=app, *pe=app+n;
        const uint8_t *path=NULL, *args=NULL, *method=NULL; size_t lp=0, la=0, lm=0; uint32_t rid=0;
        while(p<pe){
            uint8_t t = *p++; uint64_t L; size_t ln;
            if(hail2_varint_decode(p, (size_t)(pe-p), &L, &ln)) break;
            p+=ln; if(p+L>pe) break;
            const uint8_t *v = p;
            if(t==1){ method=v; lm=(size_t)L; }
            else if(t==2){ path=v; lp=(size_t)L; }
            else if(t==3){ args=v; la=(size_t)L; }
            else if(t==4 && L==4){ memcpy(&rid, v, 4); rid=ntohl(rid); }
            p+=L;
        }

        // log + SSE
        fwrite(head,1,(size_t)hn,stdout);
        fputs(",\"app\":{",stdout);
        if(method){ fputs("\"m\":\"",stdout); fwrite(method,1,lm,stdout); fputs("\"",stdout); }
        if(path){ fputs(method?",\"p\":\"":"\"p\":\"",stdout); fwrite(path,1,lp,stdout); fputs("\"",stdout); }
        if(args){ fputs(",\"a\":",stdout); fwrite(args,1,la,stdout); }
        fprintf(stdout, ",\"r\":%u}}\n", (unsigned)rid);
        fflush(stdout);

        {
            char sse[1024];
            int nn = snprintf(sse,sizeof(sse), "%s,\"app\":{", head);
            if(nn<0) nn=0;
            if(method){ nn+=snprintf(sse+nn,sizeof(sse)-nn,"\"m\":\"%.*s\"", (int)lm,(const char*)method); }
            if(path){   nn+=snprintf(sse+nn,sizeof(sse)-nn,"%s\"p\":\"%.*s\"", method?",":"", (int)lp,(const char*)path); }
            if(args){   nn+=snprintf(sse+nn,sizeof(sse)-nn,",\"a\":%.*s", (int)la,(const char*)args); }
            nn+=snprintf(sse+nn,sizeof(sse)-nn,",\"r\":%u}}\n",(unsigned)rid);
            if(nn>0 && nn<(int)sizeof(sse)) sse_push_line(sse);
        }

        // EXEC dispatch (signed only)
        if(method && lm==4 && !memcmp(method,"EXEC",4)){
            if(!(m->signed_present && m->signed_ok)) return; // commands must be signed
            if(!haild_has_cap(&g_cfg,"exec")) return;

            haild_exec_req ex = {
                .method="EXEC",
                .path = (path && lp) ? strndup((const char*)path, lp) : "/",
                .args_json = (args && la) ? strndup((const char*)args, la) : NULL,
                .req_id = rid,
                .src_id = m->src_id,
                .ip4_be = m->rx_from_ip4,
                .port   = m->rx_from_port,
                .content_type = "tlv",
            };
            char out[1024]={0};
            ssize_t on = haild_exec_run(&ex, out, sizeof(out));
            if(on>0){
                hail2_opts_t o; hail2_opts_reset(&o);
                hail2_opts_content_type(&o, HAIL2_CT_JSON);
                hail2_addr_t peer={.ip4=m->rx_from_ip4,.port=m->rx_from_port};
                (void)hail2_send_data(ctx, &peer, out, (size_t)on, /*ack*/false, /*relay*/false, &o, NULL);
            }
            if(ex.path && ex.path!="/") free((void*)ex.path);
            if(ex.args_json) free((void*)ex.args_json);
        }
        return;
    }

    // other frames: print + SSE header-only
    fwrite(head,1,(size_t)hn,stdout); fputs("}\n",stdout); fflush(stdout);
    sse_push_line(head);
}

// ================== main ==================
int main(void){
    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN);   // prevent process exit on broken pipe


    // Defaults
    static const char *roles_wayfinder[] = {"wayfinder", NULL};
    static const char *caps_default[]    = {"exec","topo","ping","relay", NULL};

    // Load daemon config and hail2 crypto/network bits from /etc/hail.conf (best-effort)
    haild_config dcfg = {
        .alias       = NULL,
        .roles       = roles_wayfinder,
        .caps        = caps_default,
        .exec_prog   = "/usr/bin/hail-exec",
        .http_enable = true,
        .http_port   = 8080,
    };
    haild_load_conf("/etc/hail.conf", &dcfg);
    g_cfg = dcfg;

    hail2_config_t cfg = {0};
    cfg.on_frame = on_frame;
    cfg.on_event = on_event;

    // apply network/crypto defaults and overlay from conf
    haild_apply_conf_to_hail2(&cfg, "/etc/hail.conf");

    // alias
    if(g_cfg.alias && *g_cfg.alias) snprintf(cfg.alias, sizeof(cfg.alias), "%s", g_cfg.alias);
    else snprintf(cfg.alias, sizeof(cfg.alias), "haild-%u", (unsigned)getpid() & 0xffff);

    snprintf(g_alias, sizeof(g_alias), "%s", cfg.alias);

    hail2_ctx *ctx=NULL;
    if(hail2_init(&cfg, &ctx) < 0 || !ctx){
        fprintf(stderr, "hail2_init failed\n"); return 1;
    }
    printf("haild up: UDP %u, alias=%s, HTTP %s:%u\n",
           cfg.port?cfg.port:(unsigned)HAIL2_DEFAULT_PORT,
           g_alias,
           g_cfg.http_enable?"on":"off", g_cfg.http_port);

    (void)hail2_send_beacon(ctx);
    (void)hail2_send_announce(ctx);

    int http_fd = -1;
    if(g_cfg.http_enable){
        http_fd = http_listen(g_cfg.http_port);
        if(http_fd<0) hlogf("HTTP listen failed on %u", g_cfg.http_port);
    }

    struct timespec nap={.tv_sec=0,.tv_nsec=10*1000*1000};
    while(g_run){
        (void)hail2_step(ctx);
        if(http_fd>=0){
            http_accept(ctx, &g_cfg, http_fd);
            // if SSE client died, clean up on write error next push; here no-op
        }
        nanosleep(&nap, NULL);
    }

    if(g_sse_fd>=0) close(g_sse_fd);
    if(http_fd>=0) close(http_fd);
    hail2_close(ctx);
    return 0;
}
