#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
/* hail2.c — HAIL v2: lean discovery + message exchange over UDP */
#include "hail2.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <net/if.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

/* ===== tiny SHA256/HMAC ===== */
typedef struct { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t blen; } sha256_ctx;
static uint32_t R(uint32_t x,int n){ return (x>>n)|(x<<(32-n)); }
static void sha256_init(sha256_ctx* c){
    c->s[0]=0x6a09e667; c->s[1]=0xbb67ae85; c->s[2]=0x3c6ef372; c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f; c->s[5]=0x9b05688c; c->s[6]=0x1f83d9ab; c->s[7]=0x5be0cd19;
    c->bits=0; c->blen=0;
}
static void sha256_compress(sha256_ctx* c,const uint8_t *p){
    static const uint32_t K[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x3910c0b3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for(int i=0;i<16;i++){ w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3]; }
    for(int i=16;i<64;i++){ uint32_t s0=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3);
                             uint32_t s1=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10);
                             w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=c->s[0],b=c->s[1],cc=c->s[2],d=c->s[3],e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7];
    for(int i=0;i<64;i++){
        uint32_t S1=R(e,6)^R(e,11)^R(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t temp1=h+S1+ch+K[i]+w[i];
        uint32_t S0=R(a,2)^R(a,13)^R(a,22);
        uint32_t maj=(a&b)^(a&cc)^(b&cc);
        uint32_t temp2=S0+maj;
        h=g; g=f; f=e; e=d+temp1; d=cc; cc=b; b=a; a=temp1+temp2;
    }
    c->s[0]+=a; c->s[1]+=b; c->s[2]+=cc; c->s[3]+=d; c->s[4]+=e; c->s[5]+=f; c->s[6]+=g; c->s[7]+=h;
}
static void sha256_update(sha256_ctx* c,const void*data,size_t len){
    const uint8_t *p=data;
    c->bits += (uint64_t)len*8;
    while(len){
        size_t n=64 - c->blen;
        if(n>len) n=len;
        memcpy(c->buf+c->blen,p,n);
        c->blen+=n; p+=n;
        len-=n;
        if(c->blen==64){ sha256_compress(c,c->buf); c->blen=0; }
    }
}
static void sha256_final(sha256_ctx* c,uint8_t out[32]){
    size_t i=c->blen; c->buf[i++]=0x80;
    if(i>56){ while(i<64) c->buf[i++]=0; sha256_compress(c,c->buf); i=0; }
    while(i<56) c->buf[i++]=0;
    uint64_t b=c->bits; for(int j=7;j>=0;j--) c->buf[i++]=(uint8_t)(b>>(8*j));
    sha256_compress(c,c->buf);
    for(int k=0;k<8;k++){ out[4*k]=(c->s[k]>>24)&0xff; out[4*k+1]=(c->s[k]>>16)&0xff;
                          out[4*k+2]=(c->s[k]>>8)&0xff; out[4*k+3]=c->s[k]&0xff; }
}
static void hmac_sha256_3(const uint8_t *key,size_t keylen,
                          const uint8_t *m1,size_t l1,
                          const uint8_t *m2,size_t l2,
                          const uint8_t *m3,size_t l3,
                          uint8_t out[32]){
    uint8_t k0[64]={0};
    if(keylen>64){ sha256_ctx t; sha256_init(&t); sha256_update(&t,key,keylen); sha256_final(&t,k0); }
    else memcpy(k0,key,keylen);
    uint8_t ipad[64],opad[64];
    for(int i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
    sha256_ctx ictx; sha256_init(&ictx);
    sha256_update(&ictx, ipad, 64);
    if(m1&&l1) sha256_update(&ictx,m1,l1);
    if(m2&&l2) sha256_update(&ictx,m2,l2);
    if(m3&&l3) sha256_update(&ictx,m3,l3);
    uint8_t ih[32]; sha256_final(&ictx, ih);
    sha256_ctx octx; sha256_init(&octx);
    sha256_update(&octx, opad, 64);
    sha256_update(&octx, ih, 32);
    sha256_final(&octx, out);
}

/* ===== utils ===== */
static uint64_t be64toh_u64(uint64_t v){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}
static uint64_t htobe64_u64(uint64_t v){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}
static uint32_t be32toh_u32(uint32_t v){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(v);
#else
    return v;
#endif
}
static uint32_t htobe32_u32(uint32_t v){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(v);
#else
    return v;
#endif
}

static uint64_t now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000ull + ts.tv_nsec/1000000ull;
}

static int sys_random(void *buf, size_t len){
#if defined(__NR_getrandom)
    ssize_t r = syscall(__NR_getrandom, buf, len, 0);
    if(r==(ssize_t)len) return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd<0) return -1;
    size_t got=0; while(got<len){ ssize_t n=read(fd,(uint8_t*)buf+got,len-got); if(n<=0){close(fd); return -1;} got+=n; }
    close(fd); return 0;
}

/* ===== varint ===== */
size_t hail2_varint_encode(uint64_t v, uint8_t *out, size_t cap){
    size_t n=0;
    do{
        if(n>=cap) return 0;
        uint8_t b = v & 0x7f; v >>= 7;
        if(v) b |= 0x80;
        out[n++]=b;
    } while(v);
    return n;
}
int hail2_varint_decode(const uint8_t *in, size_t in_len, uint64_t *v_out, size_t *consumed){
    uint64_t v=0; int shift=0; size_t i=0;
    while(i<in_len && i<10){
        uint8_t b=in[i++]; v |= ((uint64_t)(b&0x7f))<<shift; shift+=7;
        if(!(b&0x80)){ *v_out=v; if(consumed) *consumed=i; return 0; }
    }
    return -1;
}

/* ===== opts builder ===== */
int hail2_opts_reset(hail2_opts_t *o){ if(!o) return HAIL2_E_BADARGS; o->len=0; return 0; }

static int opts_put(hail2_opts_t *o, uint8_t t, const void *val, size_t vlen){
    if(!o) return HAIL2_E_BADARGS;
    uint8_t lbuf[10]; size_t ln = hail2_varint_encode(vlen, lbuf, sizeof(lbuf));
    if(!ln) return HAIL2_E_OVERFLOW;
    if(o->len + 1 + ln + vlen > sizeof(o->buf)) return HAIL2_E_OVERFLOW;
    o->buf[o->len++] = t;
    memcpy(o->buf + o->len, lbuf, ln); o->len += ln;
    if(vlen){ memcpy(o->buf + o->len, val, vlen); o->len += vlen; }
    return 0;
}
int hail2_opts_correl_id(hail2_opts_t *o, uint64_t cid){ uint64_t be=htobe64_u64(cid); return opts_put(o,HAIL2_TLV_CORREL_ID,&be,8); }
int hail2_opts_declared_ip4(hail2_opts_t *o, uint32_t ip4_be){ return opts_put(o,HAIL2_TLV_DECLARED_IP4,&ip4_be,4); }
int hail2_opts_expires_in(hail2_opts_t *o, uint8_t s){ return opts_put(o,HAIL2_TLV_EXPIRES_IN,&s,1); }
int hail2_opts_max_app(hail2_opts_t *o, uint16_t b){ uint16_t v=htons(b); return opts_put(o,HAIL2_TLV_MAX_APP,&v,2); }
int hail2_opts_alias(hail2_opts_t *o, const char *alias){
    if(!alias) return HAIL2_E_BADARGS;
    size_t n=0; while(alias[n] && n<HAIL2_MAX_ALIAS) n++;
    return opts_put(o,HAIL2_TLV_ALIAS,alias,n);
}
int hail2_opts_role(hail2_opts_t *o, const char *r){ if(!r) return HAIL2_E_BADARGS; size_t n=strlen(r); return opts_put(o,HAIL2_TLV_ROLE,r,n); }
int hail2_opts_cap(hail2_opts_t *o, const char *c){ if(!c) return HAIL2_E_BADARGS; size_t n=strlen(c); return opts_put(o,HAIL2_TLV_CAP,c,n); }
int hail2_opts_pref_unicast(hail2_opts_t *o, bool v){ uint8_t b=v?1:0; return opts_put(o,HAIL2_TLV_PREF_UNICAST,&b,1); }
int hail2_opts_relay_ok(hail2_opts_t *o, bool v){ uint8_t b=v?1:0; return opts_put(o,HAIL2_TLV_RELAY_OK,&b,1); }
int hail2_opts_content_type(hail2_opts_t *o, hail2_content_type_t ct){ uint8_t b=(uint8_t)ct; return opts_put(o,HAIL2_TLV_CONTENT_TYPE,&b,1); }
int hail2_opts_nonce(hail2_opts_t *o, const uint8_t nonce[HAIL2_NONCE_LEN]){ return opts_put(o,HAIL2_TLV_NONCE,nonce,HAIL2_NONCE_LEN); }
int hail2_opts_key_id(hail2_opts_t *o, uint32_t keyid){ uint32_t be=htobe32_u32(keyid); return opts_put(o,HAIL2_TLV_KEY_ID,&be,4); }

/* ===== ctx ===== */
typedef struct { uint64_t src_id; uint32_t ip4; uint16_t port; uint64_t last_seen_ms; bool up; } node_entry;
#define NODE_MAX 128
typedef struct { uint64_t src_id; uint8_t nonce[HAIL2_NONCE_LEN]; uint64_t ts_ms; uint32_t ip4; } replay_entry;
#define REPLAY_MAX 256

struct hail2_ctx_s {
    int      fd;
    hail2_config_t cfg;

    uint64_t t0_ms;
    uint64_t next_beacon_ms;
    uint64_t next_announce_ms;

    node_entry  nodes[NODE_MAX];
    replay_entry replay[REPLAY_MAX];
    size_t       replay_head;
    struct { uint64_t src_id, msg_id, ts_ms; } seen[512]; size_t seen_head;
    uint8_t  txbuf[2048];
    uint8_t  rxbuf[2048];
};

/* ===== nodes/replay ===== */
static node_entry* nodes_find(hail2_ctx *ctx, uint64_t src_id){
    for(size_t i=0;i<NODE_MAX;i++) if(ctx->nodes[i].up && ctx->nodes[i].src_id==src_id) return &ctx->nodes[i];
    return NULL;
}
static node_entry* nodes_touch(hail2_ctx *ctx, uint64_t src_id, uint32_t ip4, uint16_t port){
    uint64_t now = now_ms();
    node_entry *e = nodes_find(ctx, src_id);
    if(!e){
        for(size_t i=0;i<NODE_MAX;i++){
            if(!ctx->nodes[i].up){
                e=&ctx->nodes[i]; e->src_id=src_id; e->up=true;
                if(ctx->cfg.on_event){
                    hail2_event_info_t ev={.kind=HAIL2_EVT_NODE_UP,.src_id=src_id,.ip4=ip4,.port=port};
                    ctx->cfg.on_event(ctx,&ev,ctx->cfg.user);
                }
                break;
            }
        }
        if(!e) return NULL;
    }
    e->ip4=ip4; e->port=port; e->last_seen_ms=now; return e;
}
static void nodes_expire(hail2_ctx *ctx){
    uint64_t now = now_ms();
    for(size_t i=0;i<NODE_MAX;i++){
        if(ctx->nodes[i].up && now - ctx->nodes[i].last_seen_ms > ctx->cfg.node_expire_ms){
            if(ctx->cfg.on_event){
                hail2_event_info_t ev={.kind=HAIL2_EVT_NODE_DOWN,.src_id=ctx->nodes[i].src_id,.ip4=ctx->nodes[i].ip4,.port=ctx->nodes[i].port};
                ctx->cfg.on_event(ctx,&ev,ctx->cfg.user);
            }
            ctx->nodes[i].up=false;
        }
    }
}
static bool replay_seen(hail2_ctx *ctx, uint64_t src_id, const uint8_t nonce[HAIL2_NONCE_LEN], uint32_t ip4){
    for(size_t i=0;i<REPLAY_MAX;i++){
        replay_entry *r=&ctx->replay[i];
        if(r->src_id==src_id && memcmp(r->nonce,nonce,HAIL2_NONCE_LEN)==0) return true;
    }
    replay_entry *w = &ctx->replay[ctx->replay_head++ % REPLAY_MAX];
    w->src_id=src_id; memcpy(w->nonce,nonce,HAIL2_NONCE_LEN); w->ts_ms=now_ms(); w->ip4=ip4;
    return false;
}

/* ===== sockets ===== */
static int set_nonblock(int fd){ int fl=fcntl(fd,F_GETFL,0); if(fl<0) return -1; return fcntl(fd,F_SETFL,fl|O_NONBLOCK); }
static int sock_setup(hail2_ctx *ctx){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd<0) return -1;
    int one=1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    if(ctx->cfg.enable_broadcast) setsockopt(fd,SOL_SOCKET,SO_BROADCAST,&one,sizeof(one));
#ifdef IP_PKTINFO
    setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
#endif
    struct sockaddr_in sa={0}; sa.sin_family=AF_INET;
    sa.sin_port = htons(ctx->cfg.port?ctx->cfg.port:HAIL2_DEFAULT_PORT);
    sa.sin_addr.s_addr = ctx->cfg.bind_ip4? ctx->cfg.bind_ip4 : htonl(INADDR_ANY);
    if(bind(fd,(struct sockaddr*)&sa,sizeof(sa))<0){ close(fd); return -1; }
    if(set_nonblock(fd)<0){ close(fd); return -1; }
    ctx->fd=fd; return 0;
}
static int send_unicast(int fd, uint32_t ip4, uint16_t port, const uint8_t *buf, size_t len){
    struct sockaddr_in to={0}; to.sin_family=AF_INET; to.sin_port=htons(port); to.sin_addr.s_addr=ip4;
    ssize_t n = sendto(fd, buf, len, 0, (struct sockaddr*)&to, sizeof(to));
    return (n==(ssize_t)len)?0:-1;
}
static int send_broadcast_all(hail2_ctx *ctx, uint16_t port, const uint8_t *buf, size_t len){
    struct ifaddrs *ifa=0;
    if(getifaddrs(&ifa)<0) return -1;
    int rc=0;
    int sent=0;
    for(struct ifaddrs *i=ifa;i;i=i->ifa_next){
        if(!i->ifa_addr || i->ifa_addr->sa_family!=AF_INET) continue;
        if(!(i->ifa_flags & IFF_BROADCAST)) continue;
        if(!(i->ifa_flags & IFF_UP)) continue;
        struct sockaddr_in *mask=(struct sockaddr_in*)i->ifa_netmask;
        struct sockaddr_in *addr=(struct sockaddr_in*)i->ifa_addr;
        if(!mask) continue;
        uint32_t ip   = addr->sin_addr.s_addr;
        uint32_t msk  = mask->sin_addr.s_addr;
        uint32_t bcast= (ip & msk) | ~msk;
        if(send_unicast(ctx->fd, bcast, port, buf, len)<0) rc=-1;
        else sent++;
    }
    freeifaddrs(ifa);
    /* Fallback: if no broadcast-capable IFs were found/sent, try limited broadcast */
    if(sent==0){
        uint32_t lb = htonl(INADDR_BROADCAST); /* 255.255.255.255 */
        if(send_unicast(ctx->fd, lb, port, buf, len)<0) rc=-1;
    }
    return rc;
}

/* ===== pack/unpack ===== */
static int cfg_mtu(const hail2_ctx *ctx){ return ctx->cfg.mtu?ctx->cfg.mtu:HAIL2_DEFAULT_MTU; }

static void hdr_fill_common(hail2_ctx *ctx, hail2_hdr_t *h, hail2_type_t t, uint8_t flags, uint8_t hop, uint8_t ttl){
    memset(h,0,sizeof(*h));
    h->v_t_hi = (uint8_t)((HAIL2_WIRE_VERSION & 0x0f)<<4) | ((t>>8)&0x0f);
    h->t_lo   = (uint8_t)(t & 0xff);
    h->flags  = flags;
    h->hop    = hop;
    h->ttl    = ttl;
    uint64_t mid; sys_random(&mid,sizeof(mid)); h->msg_id_be = htobe64_u64(mid);
    uint64_t sid = ctx->cfg.src_id? ctx->cfg.src_id : 0; if(!sid){ sys_random(&sid,sizeof(sid)); sid|=1ull; ctx->cfg.src_id=sid; }
    h->src_id_be = htobe64_u64(sid);
    uint16_t port = ctx->cfg.port?ctx->cfg.port:HAIL2_DEFAULT_PORT;
    h->src_port_be = htons(port);
}

static size_t put_tlv(uint8_t *buf, size_t cap, uint8_t t, const void *val, size_t vlen){
    if(cap<1) return 0;
    buf[0]=t; size_t off=1;
    uint8_t lbuf[10]; size_t ln=hail2_varint_encode(vlen,lbuf,sizeof(lbuf));
    if(!ln || off+ln+vlen>cap) return 0;
    memcpy(buf+off,lbuf,ln); off+=ln;
    if(vlen){
        if(val) memcpy(buf+off,val,vlen);
        else    memset(buf+off, 0, vlen);
        off+=vlen;
    }
    return off;
}

size_t hail2_pack(uint8_t *buf, size_t buf_len,
                  hail2_hdr_t *hdr_inout,
                  const hail2_opts_t *opts,
                  const uint8_t *app, size_t app_len,
                  const hail2_config_t *cfg)
{
    if(!buf || buf_len<sizeof(hail2_hdr_t) || !hdr_inout) return 0;
    size_t off = 0;
    memcpy(buf+off, hdr_inout, sizeof(hail2_hdr_t)); off += sizeof(hail2_hdr_t);

    uint8_t tlv[1024]; size_t toff=0;
    if(opts && opts->len){
        if(opts->len>sizeof(tlv)) return 0;
        memcpy(tlv, opts->buf, opts->len); toff = opts->len;
    }

    bool need_sign = cfg && cfg->psk && cfg->psk_len>0;
    uint8_t nonce[HAIL2_NONCE_LEN]={0};
    size_t sig_tlv_val_off = 0;
    size_t sig_val_len = 0;

    if(need_sign){
        bool has_nonce=false, has_kid=false;
        size_t p=0;
        while(p<toff){
            uint8_t t=tlv[p++]; uint64_t L; size_t ln;
            if(hail2_varint_decode(&tlv[p], toff-p, &L, &ln)) return 0;
            p+=ln;
            if(t==HAIL2_TLV_NONCE && L==HAIL2_NONCE_LEN){ memcpy(nonce,&tlv[p],HAIL2_NONCE_LEN); has_nonce=true; }
            if(t==HAIL2_TLV_KEY_ID && L==4){ has_kid=true; }
            p+=(size_t)L;
        }
        if(!has_nonce){
            if(sys_random(nonce,sizeof(nonce))<0) return 0;
            size_t n = put_tlv(tlv+toff, sizeof(tlv)-toff, HAIL2_TLV_NONCE, nonce, HAIL2_NONCE_LEN);
            if(!n) return 0;
            toff+=n;
        }
        if(cfg->key_id && !has_kid){
            uint32_t be=htobe32_u32(cfg->key_id);
            size_t n=put_tlv(tlv+toff,sizeof(tlv)-toff,HAIL2_TLV_KEY_ID,&be,4);
            if(!n) return 0;
            toff+=n;
        }
        uint8_t trunc = cfg->sig_trunc?cfg->sig_trunc:16; if(trunc>HAIL2_SIG_MAX) trunc=HAIL2_SIG_MAX;
        size_t n=put_tlv(tlv+toff, sizeof(tlv)-toff, HAIL2_TLV_SIG, NULL, trunc);
        if(!n) return 0;
        uint8_t *varp = tlv+toff+1; uint64_t L; size_t ln;
        if(hail2_varint_decode(varp, n-1, &L, &ln)) return 0;
        sig_tlv_val_off = (size_t)((varp + ln) - tlv);
        sig_val_len = trunc;
        memset(tlv + sig_tlv_val_off, 0, sig_val_len);
        toff += n;
        buf[2] |= HAIL2_F_SIGNED;
    }
    {
        size_t n = put_tlv(tlv + toff, sizeof(tlv) - toff, HAIL2_TLV_END, NULL, 0);
        if(!n) return 0;
        toff += n;
    }

    off = sizeof(hail2_hdr_t);
    if(off + toff > buf_len) return 0;
    memcpy(buf + off, tlv, toff);
    off += toff;

    if(off + app_len > buf_len) return 0;
    if(app && app_len) memcpy(buf + off, app, app_len);
    off += app_len;

    if(need_sign && sig_val_len){
        uint8_t tag[32];
        hmac_sha256_3(cfg->psk, cfg->psk_len,
                      buf, sizeof(hail2_hdr_t),
                      buf + sizeof(hail2_hdr_t), toff,
                      app, app_len,
                      tag);
        uint8_t *sig_buf_ptr = buf + sizeof(hail2_hdr_t) + sig_tlv_val_off;
        memcpy(sig_buf_ptr, tag, sig_val_len);
    }

    return off;
}

int hail2_unpack(const uint8_t *buf, size_t len,
                 hail2_meta_t *meta,
                 const uint8_t **app_out, size_t *app_len_out,
                 const hail2_config_t *cfg)
{
    if(!buf || len<sizeof(hail2_hdr_t) || !meta) return HAIL2_E_BADARGS;
    memset(meta,0,sizeof(*meta));
    const hail2_hdr_t *h = (const hail2_hdr_t*)buf;
    uint8_t ver = (h->v_t_hi>>4)&0x0f;
    uint16_t type = ((uint16_t)(h->v_t_hi&0x0f)<<8) | h->t_lo;
    if(ver!=HAIL2_WIRE_VERSION) return HAIL2_E_BADARGS;
    meta->type  = (hail2_type_t)type;
    meta->flags = h->flags;
    meta->hop   = h->hop;
    meta->ttl   = h->ttl;
    meta->msg_id= be64toh_u64(h->msg_id_be);
    meta->src_id= be64toh_u64(h->src_id_be);

    size_t p = sizeof(hail2_hdr_t);
    size_t sig_val_off=0, sig_val_len=0;

    while(p<len){
        uint8_t t = buf[p++];
        uint64_t L; size_t ln;
        if(hail2_varint_decode(buf+p, len-p, &L, &ln)) return HAIL2_E_BADARGS;
        p += ln;
        if(p+L > len) return HAIL2_E_BADARGS;
        const uint8_t *val = buf+p;

        switch(t){
            case HAIL2_TLV_END:
                if(L!=0) return HAIL2_E_BADARGS;
                goto break_after_end;
            case HAIL2_TLV_CORREL_ID: if(L==8){ meta->has_correl=true; uint64_t be; memcpy(&be,val,8); meta->correl_id=be64toh_u64(be);} break;
            case HAIL2_TLV_DECLARED_IP4: if(L==4){ meta->has_declared_ip4=true; memcpy(&meta->declared_ip4,val,4);} break;
            case HAIL2_TLV_MAX_APP: if(L==2){ uint16_t v; memcpy(&v,val,2); meta->max_app_bytes=ntohs(v);} break;
            case HAIL2_TLV_PREF_UNICAST: if(L==1){ meta->pref_unicast=(val[0]!=0);} break;
            case HAIL2_TLV_RELAY_OK: if(L==1){ meta->relay_ok=(val[0]!=0);} break;
            case HAIL2_TLV_CONTENT_TYPE: if(L==1){ meta->has_ct=true; meta->ct=(hail2_content_type_t)val[0]; } break;
            case HAIL2_TLV_NONCE: if(L==HAIL2_NONCE_LEN){ memcpy(meta->nonce,val,HAIL2_NONCE_LEN); meta->has_nonce=true; } break;
            case HAIL2_TLV_KEY_ID: if(L==4){ uint32_t be; memcpy(&be,val,4); meta->key_id=be32toh_u32(be);} break;
            case HAIL2_TLV_SIG: sig_val_off = (size_t)(val - buf); sig_val_len=(size_t)L; break;
            default: break;
        }
        p += (size_t)L;
        if(p>=len) break;
    }
break_after_end:;

    size_t app_off = p;
    if(app_out) *app_out = (app_off<len)? (buf+app_off) : NULL;
    if(app_len_out) *app_len_out = (app_off<=len)? (len - app_off) : 0;

    if(sig_val_len){
        meta->signed_present=true;
        if(cfg && cfg->psk && cfg->psk_len>0){
            uint8_t tag[32];
            uint8_t zeros[HAIL2_SIG_MAX]={0};
            if(sig_val_len>HAIL2_SIG_MAX) return HAIL2_E_BADARGS;

            sha256_ctx ictx; uint8_t ipad[64],opad[64],k0[64]={0};
            const uint8_t *key=cfg->psk; size_t keylen=cfg->psk_len;
            if(keylen>64){ sha256_ctx t; sha256_init(&t); sha256_update(&t,key,keylen); sha256_final(&t,k0); }
            else memcpy(k0,key,keylen);
            for(int i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
            sha256_init(&ictx);
            sha256_update(&ictx, ipad, 64);

            sha256_update(&ictx, buf, sizeof(hail2_hdr_t));
            sha256_update(&ictx, buf+sizeof(hail2_hdr_t), sig_val_off - sizeof(hail2_hdr_t));
            sha256_update(&ictx, zeros, sig_val_len);
            size_t tlv_tail = app_off - (sig_val_off + sig_val_len);
            if(tlv_tail) sha256_update(&ictx, buf + sig_val_off + sig_val_len, tlv_tail);
            if(app_off < len) sha256_update(&ictx, buf + app_off, len - app_off);

            uint8_t ih[32]; sha256_final(&ictx, ih);
            sha256_ctx octx; sha256_init(&octx);
            sha256_update(&octx, opad, 64);
            sha256_update(&octx, ih, 32);
            sha256_final(&octx, tag);

            if(memcmp(tag, buf + sig_val_off, sig_val_len)==0) meta->signed_ok=true;
        }
    }
    return 0;
}

/* ===== max app ===== */
size_t hail2_max_app_bytes(const hail2_ctx *ctx, const hail2_opts_t *opts){
    size_t mtu = (size_t)cfg_mtu(ctx);
    size_t hdr = sizeof(hail2_hdr_t);
    size_t tlv = opts? opts->len : 0;
    if(ctx->cfg.psk && ctx->cfg.psk_len>0){
        uint8_t trunc = ctx->cfg.sig_trunc?ctx->cfg.sig_trunc:16;
        size_t nonce_over = 1 + 1 + 8;
        size_t sig_over   = 1 + 1 + trunc;
        size_t kid_over   = ctx->cfg.key_id? (1+1+4) : 0;
        tlv += nonce_over + sig_over + kid_over;
    }
    if(hdr + tlv >= mtu) return 0;
    return mtu - hdr - tlv;
}

/* ===== node snapshot ===== */
size_t hail2_nodes_copy(const hail2_ctx *ctx, hail2_node_info_t *out, size_t max, bool include_self){
    if(!ctx || !out || !max) return 0;
    size_t n=0;
    if(include_self && n<max){
        out[n].src_id = ctx->cfg.src_id;
        out[n].ip4 = 0;
        out[n].port = ctx->cfg.port?ctx->cfg.port:HAIL2_DEFAULT_PORT;
        out[n].age_ms = 0;
        out[n].up = 1;
        n++;
    }
    uint64_t now = now_ms();
    for(size_t i=0;i<NODE_MAX && n<max;i++){
        if(ctx->nodes[i].up){
            out[n].src_id = ctx->nodes[i].src_id;
            out[n].ip4 = ctx->nodes[i].ip4;
            out[n].port= ctx->nodes[i].port;
            out[n].age_ms = (uint32_t)(now - ctx->nodes[i].last_seen_ms);
            out[n].up = 1; n++;
        }
    }
    return n;
}

/* ===== send path ===== */
static int do_send(hail2_ctx *ctx, hail2_type_t type, uint8_t flags, const hail2_addr_t *to,
                   const uint8_t *payload, size_t plen, const hail2_opts_t *opts, uint64_t *out_mid)
{
    hail2_hdr_t h; hdr_fill_common(ctx, &h, type, flags, 0, ctx->cfg.default_ttl?ctx->cfg.default_ttl:2);
    size_t n = hail2_pack(ctx->txbuf, sizeof(ctx->txbuf), &h, opts, payload, plen, &ctx->cfg);
    if(!n) return HAIL2_E_OVERFLOW;
    if(out_mid) *out_mid = be64toh_u64(h.msg_id_be);
    uint16_t port = to && to->port? to->port : (ctx->cfg.port?ctx->cfg.port:HAIL2_DEFAULT_PORT);
    if(to && to->ip4){ return send_unicast(ctx->fd, to->ip4, port, ctx->txbuf, n); }
    if(!ctx->cfg.enable_broadcast) return HAIL2_E_BADARGS;
    return send_broadcast_all(ctx, port, ctx->txbuf, n);
}
int hail2_send(hail2_ctx *ctx, hail2_type_t type, uint8_t flags, const hail2_addr_t *to,
               const uint8_t *app, size_t app_len, const hail2_opts_t *opts, uint64_t *out_msg_id)
{ if(!ctx) return HAIL2_E_BADARGS; return do_send(ctx,type,flags,to,app,app_len,opts,out_msg_id); }

int hail2_send_ping(hail2_ctx *ctx, const hail2_addr_t *to, const hail2_opts_t *opts, uint64_t *out_msg_id){
    return hail2_send(ctx, HAIL2_T_PING, 0, to, NULL, 0, opts, out_msg_id);
}
int hail2_send_pong(hail2_ctx *ctx, const hail2_addr_t *to, uint64_t correl_id, const hail2_opts_t *opts){
    hail2_opts_t loc={0}; hail2_opts_t *o=(hail2_opts_t*)(opts?opts:&loc); if(!opts) hail2_opts_reset(o);
    hail2_opts_correl_id(o, correl_id);
    return hail2_send(ctx, HAIL2_T_PONG, 0, to, NULL, 0, o, NULL);
}
int hail2_send_data(hail2_ctx *ctx, const hail2_addr_t *to, const void *payload, size_t len,
                    bool ack_req, bool relay_ok, const hail2_opts_t *opts, uint64_t *out_msg_id)
{
    uint8_t flags = 0; if(ack_req) flags|=HAIL2_F_ACK_REQ; if(relay_ok) flags|=HAIL2_F_RELAY_OK;
    return hail2_send(ctx, HAIL2_T_DATA, flags, to, (const uint8_t*)payload, len, opts, out_msg_id);
}
int hail2_send_ack(hail2_ctx *ctx, const hail2_addr_t *to, uint64_t correl_id, const hail2_opts_t *opts){
    hail2_opts_t loc={0}; hail2_opts_t *o=(hail2_opts_t*)(opts?opts:&loc); if(!opts) hail2_opts_reset(o);
    hail2_opts_correl_id(o, correl_id);
    return hail2_send(ctx, HAIL2_T_ACK, 0, to, NULL, 0, o, NULL);
}
int hail2_send_topoq(hail2_ctx *ctx, uint8_t ttl, const hail2_opts_t *opts, uint64_t *out_msg_id){
    hail2_hdr_t h; hdr_fill_common(ctx, &h, HAIL2_T_TOPOQ, 0, 0, ttl?ttl:(ctx->cfg.default_ttl?ctx->cfg.default_ttl:2));
    size_t n = hail2_pack(ctx->txbuf, sizeof(ctx->txbuf), &h, opts, NULL, 0, &ctx->cfg);
    if(!n) return HAIL2_E_OVERFLOW;
    if(out_msg_id) *out_msg_id = be64toh_u64(h.msg_id_be);
    uint16_t port = ctx->cfg.port?ctx->cfg.port:HAIL2_DEFAULT_PORT;
    return send_broadcast_all(ctx, port, ctx->txbuf, n);
}
int hail2_send_topoa(hail2_ctx *ctx, const hail2_addr_t *to,
                     const uint32_t *nbr_ip4_be, const uint8_t *nbr_age_s, size_t cnt, const hail2_opts_t *opts)
{
    hail2_opts_t loc={0}; hail2_opts_t *o=(hail2_opts_t*)(opts?opts:&loc); if(!opts) hail2_opts_reset(o);
    for(size_t i=0;i<cnt;i++){
        size_t n = put_tlv(o->buf+o->len, sizeof(o->buf)-o->len, HAIL2_TLV_NEIGHBOR_IP4, &nbr_ip4_be[i], 4);
        if(!n) return HAIL2_E_OVERFLOW;
        o->len+=n;
        n = put_tlv(o->buf+o->len, sizeof(o->buf)-o->len, HAIL2_TLV_NEIGHBOR_AGE, &nbr_age_s[i], 1);
        if(!n) return HAIL2_E_OVERFLOW;
        o->len+=n;
    }
    return hail2_send(ctx, HAIL2_T_TOPOA, 0, to, NULL, 0, o, NULL);
}

/* ===== runtime controls / introspection ===== */
int hail2_set_signing(hail2_ctx *ctx, const uint8_t *psk, size_t psk_len, uint8_t sig_trunc, uint32_t key_id){
    if(!ctx) return HAIL2_E_BADARGS;
    ctx->cfg.psk = psk;
    ctx->cfg.psk_len = psk_len;
    if(sig_trunc) ctx->cfg.sig_trunc = sig_trunc;
    if(key_id)    ctx->cfg.key_id    = key_id;
    return 0;
}
uint64_t hail2_src_id(const hail2_ctx *ctx){ return ctx? ctx->cfg.src_id : 0; }

/* ===== discovery ===== */
static int send_discovery(hail2_ctx *ctx, hail2_type_t t){
    hail2_opts_t o; hail2_opts_reset(&o);
    if(ctx->cfg.alias[0]) (void)hail2_opts_alias(&o, ctx->cfg.alias);
    if(ctx->cfg.roles) for(const char *const* rr=ctx->cfg.roles; *rr; ++rr) (void)hail2_opts_role(&o, *rr);
    if(ctx->cfg.caps)  for(const char *const* cc=ctx->cfg.caps;  *cc; ++cc)  (void)hail2_opts_cap (&o, *cc);
    (void)hail2_opts_pref_unicast(&o, true);
    uint16_t maxapp = (uint16_t)hail2_max_app_bytes(ctx, &o);
    (void)hail2_opts_max_app(&o, maxapp);
    if(ctx->cfg.bind_ip4) (void)hail2_opts_declared_ip4(&o, ctx->cfg.bind_ip4);

    hail2_hdr_t h; hdr_fill_common(ctx, &h, t, 0, 0, ctx->cfg.default_ttl?ctx->cfg.default_ttl:2);
    size_t n = hail2_pack(ctx->txbuf, sizeof(ctx->txbuf), &h, &o, NULL, 0, &ctx->cfg);
    if(!n) return HAIL2_E_OVERFLOW;
    uint16_t port = ctx->cfg.port?ctx->cfg.port:HAIL2_DEFAULT_PORT;
    return send_broadcast_all(ctx, port, ctx->txbuf, n);
}
int hail2_send_beacon(hail2_ctx *ctx){ return send_discovery(ctx, HAIL2_T_BEACON); }
int hail2_send_announce(hail2_ctx *ctx){ return send_discovery(ctx, HAIL2_T_ANNOUNCE); }

/* tiny helper */
static bool seen_recent(hail2_ctx *ctx, uint64_t src_id, uint64_t msg_id, uint64_t window_ms){
    uint64_t now = now_ms();
    for(size_t i=0;i<ARRAY_SIZE(ctx->seen); i++){
        if(ctx->seen[i].src_id==src_id && ctx->seen[i].msg_id==msg_id){
            if(now - ctx->seen[i].ts_ms <= window_ms) return true;
        }
    }
    size_t idx = ctx->seen_head % ARRAY_SIZE(ctx->seen);
    ctx->seen[idx].src_id = src_id;
    ctx->seen[idx].msg_id = msg_id;
    ctx->seen[idx].ts_ms  = now;
    ctx->seen_head++;
    return false;
}

/* ===== init/close/fd ===== */
int hail2_init(const hail2_config_t *cfg_in, hail2_ctx **out){
    if(!cfg_in || !cfg_in->on_frame || !out) return HAIL2_E_BADARGS;
    hail2_ctx *ctx = calloc(1, sizeof(*ctx)); if(!ctx) return HAIL2_E_NOMEM;
    ctx->cfg = *cfg_in;
    if(!ctx->cfg.port) ctx->cfg.port = HAIL2_DEFAULT_PORT;
    if(!ctx->cfg.mtu)  ctx->cfg.mtu  = HAIL2_DEFAULT_MTU;
    if(!ctx->cfg.beacon_period_ms)   ctx->cfg.beacon_period_ms=2000;
    if(!ctx->cfg.announce_period_ms) ctx->cfg.announce_period_ms=9000;
    if(!ctx->cfg.node_expire_ms)     ctx->cfg.node_expire_ms=15000;
    if(!ctx->cfg.default_ttl)        ctx->cfg.default_ttl=2;
    if(!ctx->cfg.dedupe_ms)          ctx->cfg.dedupe_ms=3000;
    ctx->t0_ms = now_ms();
    ctx->next_beacon_ms = ctx->t0_ms + ctx->cfg.beacon_period_ms;
    ctx->next_announce_ms = ctx->t0_ms + ctx->cfg.announce_period_ms;

    if(sock_setup(ctx)<0){ free(ctx); return HAIL2_E_SOCKET; }

    if(!ctx->cfg.src_id){ uint64_t sid; sys_random(&sid,sizeof(sid)); sid|=1ull; ctx->cfg.src_id=sid; }

    *out = ctx; return 0;
}
void hail2_close(hail2_ctx *ctx){ if(!ctx) return; if(ctx->fd>=0) close(ctx->fd); free(ctx); }
int  hail2_fd(const hail2_ctx *ctx){ return ctx?ctx->fd:-1; }

/* ===== step (rx + timers) ===== */
int hail2_step(hail2_ctx *ctx){
    if(!ctx) return HAIL2_E_BADARGS;
    uint64_t now = now_ms();
    if(now >= ctx->next_beacon_ms){ (void)hail2_send_beacon(ctx); ctx->next_beacon_ms = now + ctx->cfg.beacon_period_ms; }
    if(now >= ctx->next_announce_ms){ (void)hail2_send_announce(ctx); ctx->next_announce_ms = now + ctx->cfg.announce_period_ms; }
    nodes_expire(ctx);

    for(;;){
        struct sockaddr_in from; memset(&from,0,sizeof(from));
        struct iovec iov; iov.iov_base=ctx->rxbuf; iov.iov_len=sizeof(ctx->rxbuf);
        char cbuf[128];
        struct msghdr msg={0};
        msg.msg_name=&from; msg.msg_namelen=sizeof(from);
        msg.msg_iov=&iov; msg.msg_iovlen=1;
        msg.msg_control=cbuf; msg.msg_controllen=sizeof(cbuf);

        ssize_t n = recvmsg(ctx->fd, &msg, MSG_DONTWAIT);
        if(n<0){ if(errno==EAGAIN||errno==EWOULDBLOCK) break; else return -1; }

        uint32_t ifindex=0;
#ifdef IP_PKTINFO
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg); c; c=CMSG_NXTHDR(&msg,c)){
            if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO){
                struct in_pktinfo *pi=(struct in_pktinfo*)CMSG_DATA(c); ifindex=pi->ipi_ifindex;
            }
        }
#endif
        hail2_meta_t m; const uint8_t *app=NULL; size_t app_len=0;
        int ur = hail2_unpack(ctx->rxbuf, (size_t)n, &m, &app, &app_len, &ctx->cfg);
        if(ur<0) continue;

        m.rx_ifindex = ifindex;
        m.rx_from_ip4 = from.sin_addr.s_addr;
        m.rx_from_port= ntohs(from.sin_port);
        m.tlv_start = ctx->rxbuf + sizeof(hail2_hdr_t);
        m.tlv_len   = (size_t)((app ? (const uint8_t*)app : ctx->rxbuf + (size_t)n) - m.tlv_start);

        if(m.signed_present && !m.signed_ok){
            if(ctx->cfg.on_event){ hail2_event_info_t ev={.kind=HAIL2_EVT_SIG_BAD,.src_id=m.src_id,.ip4=m.rx_from_ip4,.port=m.rx_from_port}; ctx->cfg.on_event(ctx,&ev,ctx->cfg.user); }
            continue;
        }
        if(m.src_id != ctx->cfg.src_id &&
           (m.flags & HAIL2_F_SIGNED) && m.has_nonce){
            if(replay_seen(ctx, m.src_id, m.nonce, m.rx_from_ip4)){
                if(ctx->cfg.on_event){ hail2_event_info_t ev={.kind=HAIL2_EVT_REPLAY_DROP,.src_id=m.src_id,.ip4=m.rx_from_ip4,.port=m.rx_from_port}; ctx->cfg.on_event(ctx,&ev,ctx->cfg.user); }
                continue;
            }
        }

        /* Suppress our own broadcasts */
        if (m.src_id == ctx->cfg.src_id) {
            continue;
        }

        /* Duplicate suppression by (src_id,msg_id) */
        if(seen_recent(ctx, m.src_id, m.msg_id, ctx->cfg.dedupe_ms)){
            continue;
        }

        (void)nodes_touch(ctx, m.src_id, m.rx_from_ip4, m.rx_from_port);
        hail2_addr_t raddr = {.ip4 = m.rx_from_ip4, .port = m.rx_from_port};

        if(m.type==HAIL2_T_PING){
            (void)hail2_send_pong(ctx, &raddr, m.msg_id, NULL);
        }else if(m.type==HAIL2_T_DATA){
            if(m.flags & HAIL2_F_ACK_REQ){ (void)hail2_send_ack(ctx, &raddr, m.msg_id, NULL); }
            if((m.flags & HAIL2_F_RELAY_OK) && m.ttl>0){
                hail2_opts_t o; hail2_opts_reset(&o);
                if(m.has_correl) (void)hail2_opts_correl_id(&o, m.correl_id); else (void)hail2_opts_correl_id(&o, m.msg_id);
                if(m.has_ct) (void)hail2_opts_content_type(&o, m.ct);
                hail2_hdr_t hh; hdr_fill_common(ctx,&hh,HAIL2_T_DATA,m.flags,(uint8_t)(m.hop+1),(uint8_t)(m.ttl-1));
                size_t nn = hail2_pack(ctx->txbuf, sizeof(ctx->txbuf), &hh, &o, app, app_len, &ctx->cfg);
                if(nn) (void)send_broadcast_all(ctx, ctx->cfg.port, ctx->txbuf, nn);
            }
        }else if(m.type==HAIL2_T_TOPOQ){
            uint32_t ip4s[32]; uint8_t ages[32]; size_t k=0;
            uint64_t nowms=now_ms();
            for(size_t i=0;i<NODE_MAX && k<ARRAY_SIZE(ip4s); i++){
                if(ctx->nodes[i].up){
                    ip4s[k] = ctx->nodes[i].ip4;
                    uint64_t age_ms = nowms - ctx->nodes[i].last_seen_ms; ages[k]=(age_ms>255000)?255:(uint8_t)(age_ms/1000);
                    k++;
                }
            }
            (void)hail2_send_topoa(ctx, &raddr, ip4s, ages, k, NULL);
        }

        ctx->cfg.on_frame(ctx, &m, app, app_len, ctx->cfg.user);
    }
    return 0;
}
