#define _POSIX_C_SOURCE 200809L
#include "hail2.h"
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static volatile int g_run = 1;
static void on_sigint(int sig){ (void)sig; g_run = 0; }

/* ===== tiny helpers ===== */
static uint64_t now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000ull + ts.tv_nsec/1000000ull;
}
static void ip4_to_str(uint32_t ip_be, char out[16]){
    unsigned a =  ip_be        & 255u;
    unsigned b = (ip_be >> 8)  & 255u;
    unsigned c = (ip_be >> 16) & 255u;
    unsigned d = (ip_be >> 24) & 255u;
    snprintf(out,16,"%u.%u.%u.%u",a,b,c,d);
}

/* ===== track outstanding msgs for RTT print ===== */
typedef struct { uint64_t id; uint64_t ts; const char *tag; } pend_t;
static pend_t pend[64];
static void pend_note(uint64_t id, const char *tag){
    for(size_t i=0;i<sizeof(pend)/sizeof(pend[0]); i++){
        if(pend[i].id==0){ pend[i].id=id; pend[i].ts=now_ms(); pend[i].tag=tag; return; }
    }
}
static void pend_rtt(uint64_t correl){
    uint64_t t=now_ms();
    for(size_t i=0;i<sizeof(pend)/sizeof(pend[0]); i++){
        if(pend[i].id==correl){
            printf("RTT DATA->ACK  %s: %llums\n", pend[i].tag?pend[i].tag:"", (unsigned long long)(t - pend[i].ts));
            pend[i].id=0; return;
        }
    }
}

/* ===== app-level TLV for EXEC ===== */
enum { APP_TLV_METHOD=1, APP_TLV_PATH=2, APP_TLV_ARGS=3, APP_TLV_REQID=4 };
enum { APP_METHOD_EXEC = 1 };

static size_t app_put_tlv(uint8_t *buf, size_t cap, uint8_t t, const void *val, size_t vlen){
    if(cap < 1) return 0;
    buf[0]=t; size_t off=1;
    /* varint length (very small, so 1 byte is fine) */
    if(vlen > 0x7f) return 0;
    buf[off++] = (uint8_t)vlen;
    if(off+vlen > cap) return 0;
    if(vlen) memcpy(buf+off,val,vlen);
    off+=vlen;
    return off;
}
static size_t build_exec_payload(uint8_t *out, size_t cap, const char *path, const char *args_json, uint32_t reqid){
    size_t off=0, n=0;
    uint8_t m = APP_METHOD_EXEC;
    if(!(n=app_put_tlv(out+off, cap-off, APP_TLV_METHOD, &m, 1))) return 0; off+=n;
    if(!(n=app_put_tlv(out+off, cap-off, APP_TLV_PATH, path, strlen(path)))) return 0; off+=n;
    if(args_json){
        if(!(n=app_put_tlv(out+off, cap-off, APP_TLV_ARGS, args_json, strlen(args_json)))) return 0; off+=n;
    }
    uint32_t reqid_be = htonl(reqid);
    if(!(n=app_put_tlv(out+off, cap-off, APP_TLV_REQID, &reqid_be, 4))) return 0; off+=n;
    return off;
}
static void parse_exec_payload(const uint8_t *p, size_t n){
    uint8_t  method=0; const char *path=""; const char *args=""; uint32_t reqid=0;
    const uint8_t *end=p+n;
    while(p<end){
        uint8_t t=*p++; if(p>=end) break;
        uint8_t L=*p++; if(p+L>end) break;
        const uint8_t *v=p; p+=L;
        switch(t){
            case APP_TLV_METHOD: if(L==1) method=v[0]; break;
            case APP_TLV_PATH: path=(const char*)v; break;
            case APP_TLV_ARGS: args=(const char*)v; break;
            case APP_TLV_REQID: if(L==4){ uint32_t be; memcpy(&be,v,4); reqid=ntohl(be); } break;
            default: break;
        }
    }
    if(method==APP_METHOD_EXEC){
        printf("    app: method=EXEC req=%u path=\"%s\" args=%s\n", reqid, path, args[0]?args:"{}");
    }
}

/* ===== print payload helpers ===== */
static void print_payload(const hail2_meta_t *m, const uint8_t *app, size_t app_len){
    if(m->has_ct && m->ct==HAIL2_CT_JSON){
        printf("    payload(JSON): %.*s\n", (int)app_len, (const char*)app);
    }else if(m->has_ct && m->ct==HAIL2_CT_TLV){
        parse_exec_payload(app, app_len);
    }
}

/* ===== callbacks ===== */
static void on_frame(hail2_ctx *ctx, const hail2_meta_t *m,
                     const uint8_t *app, size_t n, void *u){
    (void)ctx; (void)u;
    char ip[16]; ip4_to_str(m->rx_from_ip4, ip);
    const char *tn="?";
    switch(m->type){
        case HAIL2_T_BEACON:  tn="BEACON"; break;
        case HAIL2_T_ANNOUNCE:tn="ANNOUC"; break;
        case HAIL2_T_PING:    tn="PING";   break;
        case HAIL2_T_PONG:    tn="PONG";   break;
        case HAIL2_T_DATA:    tn="DATA";   break;
        case HAIL2_T_ACK:     tn="ACK";    break;
        case HAIL2_T_TOPOQ:   tn="TOPOQ";  break;
        case HAIL2_T_TOPOA:   tn="TOPOA";  break;
    }

    printf("RX %s   remote from=%s:%u msg=%016llx len=%zu sig=%d/%d ttl=%u hop=%u",
           tn, ip, m->rx_from_port, (unsigned long long)m->msg_id, n,
           m->signed_present?1:0, m->signed_ok?1:0, m->ttl, m->hop);

    if(m->has_ct && m->type==HAIL2_T_DATA) printf(" ct=%u", (unsigned)m->ct);
    if(m->has_correl) printf(" correl=%016llx", (unsigned long long)m->correl_id);
    puts("");

    /* RTT print for ACKs */
    if(m->type==HAIL2_T_ACK && m->has_correl){ pend_rtt(m->correl_id); }

    /* Show topology answer */
    if(m->type==HAIL2_T_TOPOA){
        const uint8_t *p = m->tlv_start;
        const uint8_t *end = p + m->tlv_len;
        uint32_t last_ip=0; int idx=0;
        while(p<end){
            uint8_t t=*p++; uint64_t L=0; size_t ln=0;
            if(hail2_varint_decode(p, (size_t)(end-p), &L, &ln)) break; p+=ln;
            if(p+L>end) break;
            if(t==HAIL2_TLV_NEIGHBOR_IP4 && L==4){
                memcpy(&last_ip,p,4);
            }else if(t==HAIL2_TLV_NEIGHBOR_AGE && L==1){
                char ipb[16]; ip4_to_str(last_ip, ipb);
                printf("    topo[%d]: %s age=%us\n", idx++, ipb, (unsigned)p[0]);
            }
            p += (size_t)L;
        }
    }

    if(m->type==HAIL2_T_DATA && n>0) print_payload(m, app, n);

    /* Print nodes snapshot every ~2s on first node */
    static uint64_t last_nodes=0;
    if(now_ms() - last_nodes > 2000){
        last_nodes = now_ms();
        hail2_node_info_t list[16]; size_t k = hail2_nodes_copy(ctx, list, 16, true);
        puts("NODES:");
        for(size_t i=0;i<k;i++){
            char nip[16]; ip4_to_str(list[i].ip4, nip);
            printf("  [%zu] %s src=%016llx ip=%s:%u age=%ums\n",
                   i, (i==0?"self ":"peer "),
                   (unsigned long long)list[i].src_id, nip, list[i].port, list[i].age_ms);
        }
    }
}

static void on_event(hail2_ctx *ctx, const hail2_event_info_t *ev, void *u){
    (void)ctx; (void)u;
    char ip[16]; ip4_to_str(ev->ip4, ip);
    const char *ek="?";
    switch(ev->kind){
        case HAIL2_EVT_NODE_UP: ek="NODE_UP"; break;
        case HAIL2_EVT_NODE_DOWN: ek="NODE_DOWN"; break;
        case HAIL2_EVT_SIG_BAD: ek="SIG_BAD"; break;
        case HAIL2_EVT_REPLAY_DROP: ek="REPLAY_DROP"; break;
    }
    printf("EVT %s     src=%016llx ip=%s:%u\n", ek, (unsigned long long)ev->src_id, ip, ev->port);
}

/* ===== demo send helpers ===== */
static void send_broadcast_hb(hail2_ctx *ctx, bool signed_mode, const char *tag){
    hail2_opts_t o; hail2_opts_reset(&o);
    hail2_opts_content_type(&o, HAIL2_CT_JSON);
    const char payload[] = "{\"hb\":1}";
    uint64_t mid=0;
    (void)hail2_send_data(ctx, NULL, payload, sizeof(payload)-1, true, true, &o, &mid);
    pend_note(mid, tag);
    printf("TX  DATA   broadcast %s ack=1 relay=1 msg=%016llx\n", signed_mode?"SIGNED":"UNSIGNED", (unsigned long long)mid);
}
static void send_unicast_data(hail2_ctx *ctx, uint32_t ip_be, uint16_t port, bool signed_mode, const char *tag){
    hail2_addr_t to={.ip4=ip_be,.port=port};
    hail2_opts_t o; hail2_opts_reset(&o);
    hail2_opts_content_type(&o, HAIL2_CT_JSON);
    const char payload[] = "{\"hi\":\"unicast\"}";
    uint64_t mid=0;
    (void)hail2_send_data(ctx, &to, payload, sizeof(payload)-1, true, false, &o, &mid);
    pend_note(mid, tag);
    printf("TX  DATA   -> %u.%u.%u.%u:%u %s ack=1 relay=0 msg=%016llx\n",
           ip_be&255u, (ip_be>>8)&255u, (ip_be>>16)&255u, (ip_be>>24)&255u,
           port, signed_mode?"SIGNED":"UNSIGNED", (unsigned long long)mid);
}
static void send_exec(hail2_ctx *ctx, const hail2_addr_t *to, const char *path, const char *args_json, const char *tag){
    uint8_t buf[256];
    uint32_t req = (uint32_t)(now_ms() & 0xffffff);
    size_t n = build_exec_payload(buf, sizeof(buf), path, args_json, req);
    hail2_opts_t o; hail2_opts_reset(&o);
    hail2_opts_content_type(&o, HAIL2_CT_TLV);
    uint64_t mid=0;
    (void)hail2_send_data(ctx, to, buf, n, true, to?false:true, &o, &mid);
    pend_note(mid, tag);
    if(to){
        printf("TX  EXEC  -> %u.%u.%u.%u:%u TLV ack=1 relay=0 msg=%016llx\n",
               to->ip4&255u, (to->ip4>>8)&255u, (to->ip4>>16)&255u, (to->ip4>>24)&255u,
               to->port?to->port:HAIL2_DEFAULT_PORT, (unsigned long long)mid);
    }else{
        printf("TX  EXEC  broadcast TLV ack=1 relay=1 msg=%016llx\n",(unsigned long long)mid);
    }
}

int main(void){
    signal(SIGINT, on_sigint);

    hail2_config_t cfg = {0};
    cfg.on_frame = on_frame;
    cfg.on_event = on_event;
    cfg.enable_broadcast = true;
    cfg.default_ttl = 2;

    /* PSK for signing */
    static const uint8_t psk[16] = {1,2,3};
    cfg.psk = psk;
    cfg.psk_len = sizeof(psk);
    cfg.sig_trunc = 16;
    cfg.key_id = 1;

    snprintf(cfg.alias, sizeof(cfg.alias), "demo-%u", (unsigned)(getpid() & 0xffff));

    hail2_ctx *ctx = NULL;
    int rc = hail2_init(&cfg, &ctx);
    if(rc < 0 || !ctx){
        fprintf(stderr, "hail2_init failed: %d\n", rc);
        return 1;
    }

    printf("HAIL2 running on UDP port %u (broadcast %s, MTU %u), alias=%s\n",
           cfg.port ? cfg.port : (unsigned)HAIL2_DEFAULT_PORT,
           cfg.enable_broadcast ? "on" : "off",
           cfg.mtu ? cfg.mtu : (unsigned)HAIL2_DEFAULT_MTU,
           cfg.alias);

    /* greet quickly */
    (void)hail2_send_beacon(ctx);
    (void)hail2_send_announce(ctx);

    /* demo cadence */
    uint64_t last_hb_s=0, last_uc_s=0, last_topo_s=0, last_exec_s=0;

    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10*1000*1000 }; /* 10 ms */
    while(g_run){
        int step = hail2_step(ctx);
        if(step < 0){ fprintf(stderr, "hail2_step error: %d\n", step); break; }

        uint64_t now = now_ms();

        if(now - last_hb_s > 1000){
            /* alternate signed/unsigned broadcast HB just to exercise both */
            static int flip=0; flip^=1;
            send_broadcast_hb(ctx, flip, flip?"HBs":"HBu");
            last_hb_s = now;
        }

        if(now - last_uc_s > 3000){
            /* try a unicast JSON to the newest peer (if any) */
            hail2_node_info_t ninfo[2];
            size_t k=hail2_nodes_copy(ctx,ninfo,2,false);
            if(k>0){
                hail2_addr_t to={.ip4=ninfo[0].ip4,.port=ninfo[0].port};
                send_unicast_data(ctx, to.ip4, to.port, true, "UcastS");
                send_unicast_data(ctx, to.ip4, to.port, false,"UcastU");
            }else{
                printf("TX  DATA   (no peer yet)\n");
            }
            last_uc_s = now;
        }

        if(now - last_topo_s > 7000){
            uint64_t mid=0;
            (void)hail2_send_topoq(ctx, 2, NULL, &mid);
            printf("TX  TOPOQ  ttl=2 msg=%016llx\n",(unsigned long long)mid);
            last_topo_s = now;
        }

        if(now - last_exec_s > 9000){
            /* broadcast and unicast EXEC TLV */
            send_exec(ctx, NULL, "/sys/led", "{\"state\":\"on\"}", "EXECb");
            hail2_node_info_t ninfo[1]; size_t k=hail2_nodes_copy(ctx,ninfo,1,false);
            if(k>0){
                hail2_addr_t to={.ip4=ninfo[0].ip4,.port=ninfo[0].port};
                send_exec(ctx, &to, "/sys/led", "{\"state\":\"toggle\"}", "EXECu");
            }
            last_exec_s = now;
        }

        nanosleep(&ts, NULL);
    }

    hail2_close(ctx);
    puts("Bye.");
    return 0;
}
