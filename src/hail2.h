/* hail2.h — HAIL v2: lean discovery + message exchange over UDP
 * Wire: [24B header][TLVs][payload]
 * MIT License (c) 2025
 */
#ifndef HAIL2_H
#define HAIL2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HAIL2_WIRE_VERSION        1u
#define HAIL2_DEFAULT_PORT        27182
#define HAIL2_DEFAULT_MTU         1200
#define HAIL2_MAX_ROLES           16
#define HAIL2_MAX_CAPS            32
#define HAIL2_MAX_ALIAS           63
#define HAIL2_NONCE_LEN           8
#define HAIL2_SIG_MAX             32

typedef enum {
    HAIL2_T_BEACON  = 1,
    HAIL2_T_ANNOUNCE= 2,
    HAIL2_T_PING    = 3,
    HAIL2_T_PONG    = 4,
    HAIL2_T_DATA    = 5,
    HAIL2_T_ACK     = 6,
    HAIL2_T_TOPOQ   = 7,
    HAIL2_T_TOPOA   = 8,
} hail2_type_t;

enum {
    HAIL2_F_ACK_REQ      = 1u << 0,
    HAIL2_F_SIGNED       = 1u << 1,
    HAIL2_F_PREF_UNICAST = 1u << 2,
    HAIL2_F_RELAY_OK     = 1u << 3,
    HAIL2_F_RESERVED_4   = 1u << 4,
    HAIL2_F_RESERVED_5   = 1u << 5,
    HAIL2_F_RESERVED_6   = 1u << 6,
    HAIL2_F_RESERVED_7   = 1u << 7,
};

typedef enum {
    HAIL2_CT_RAW   = 0,
    HAIL2_CT_JSON  = 1,
    HAIL2_CT_CBOR  = 2,
    HAIL2_CT_MSGPK = 3,
    HAIL2_CT_TLV   = 4,
    HAIL2_CT_ENV   = 5,   /* app envelope: varint length + JSON header + payload */
} hail2_content_type_t;

typedef enum {
    HAIL2_SIG_HMAC_SHA256 = 1,
} hail2_sig_alg_t;

/* 24-byte header layout (network order for multibyte):
 *  byte0: V(4b) | T_hi(4b)
 *  byte1: T_lo(8b)
 *  byte2: flags
 *  byte3: hop
 *  byte4: ttl
 *  byte5: rsvd
 *  bytes6..13 : msg_id (u64, BE)
 *  bytes14..21: src_id (u64, BE)
 *  bytes22..23: src_port (u16, BE)  // sender's UDP port hint
 */
typedef struct hail2_hdr_s {
    uint8_t  v_t_hi;
    uint8_t  t_lo;
    uint8_t  flags;
    uint8_t  hop;
    uint8_t  ttl;
    uint8_t  rsvd;
    uint64_t msg_id_be;
    uint64_t src_id_be;
    uint16_t src_port_be;
} __attribute__((packed)) hail2_hdr_t;

_Static_assert(sizeof(hail2_hdr_t) == 24, "hail2_hdr_t must be 24 bytes");

typedef enum {
    HAIL2_TLV_END           = 0x00,
    HAIL2_TLV_CORREL_ID    = 0x01,
    HAIL2_TLV_DECLARED_IP4 = 0x02,
    HAIL2_TLV_EXPIRES_IN   = 0x03,
    HAIL2_TLV_MAX_APP      = 0x04,
    HAIL2_TLV_ALIAS        = 0x05,
    HAIL2_TLV_ROLE         = 0x06,
    HAIL2_TLV_CAP          = 0x07,
    HAIL2_TLV_NONCE        = 0x08,
    HAIL2_TLV_SIG          = 0x09,
    HAIL2_TLV_PREF_UNICAST = 0x0A,
    HAIL2_TLV_RELAY_OK     = 0x0B,
    HAIL2_TLV_CONTENT_TYPE = 0x0C,
    HAIL2_TLV_KEY_ID       = 0x0D,
    HAIL2_TLV_SRC_PORT     = 0x0E,
    /* Topology */
    HAIL2_TLV_NEIGHBOR_IP4 = 0x20,
    HAIL2_TLV_NEIGHBOR_AGE = 0x21,
} hail2_tlv_type_t;

typedef struct hail2_meta_s {
    hail2_type_t type;
    uint8_t      flags;
    uint8_t      hop;
    uint8_t      ttl;

    uint64_t     msg_id;
    bool         has_correl;
    uint64_t     correl_id;
    uint64_t     src_id;

    bool         has_declared_ip4;
    uint32_t     declared_ip4;  /* BE */
    uint16_t     max_app_bytes;
    bool         pref_unicast;
    bool         relay_ok;

    bool                     has_ct;
    hail2_content_type_t     ct;

    bool         signed_present;
    bool         signed_ok;
    uint8_t      nonce[HAIL2_NONCE_LEN];
    bool         has_nonce;
    uint32_t     key_id;

    uint32_t     rx_ifindex;
    uint32_t     rx_from_ip4;   /* BE */
    uint16_t     rx_from_port;
    const uint8_t *tlv_start;
    size_t tlv_len;
} hail2_meta_t;

typedef struct hail2_opts_s {
    uint8_t  buf[512];
    size_t   len;
} hail2_opts_t;

int hail2_opts_reset(hail2_opts_t *o);
int hail2_opts_correl_id(hail2_opts_t *o, uint64_t correl_id);
int hail2_opts_declared_ip4(hail2_opts_t *o, uint32_t ip4_be);
int hail2_opts_expires_in(hail2_opts_t *o, uint8_t seconds);
int hail2_opts_max_app(hail2_opts_t *o, uint16_t bytes);
int hail2_opts_alias(hail2_opts_t *o, const char *alias_utf8);
int hail2_opts_role(hail2_opts_t *o, const char *role_token);
int hail2_opts_cap(hail2_opts_t *o, const char *cap_token);
int hail2_opts_pref_unicast(hail2_opts_t *o, bool v);
int hail2_opts_relay_ok(hail2_opts_t *o, bool v);
int hail2_opts_content_type(hail2_opts_t *o, hail2_content_type_t ct);
int hail2_opts_nonce(hail2_opts_t *o, const uint8_t nonce[HAIL2_NONCE_LEN]);
int hail2_opts_key_id(hail2_opts_t *o, uint32_t keyid);

typedef struct hail2_ctx_s hail2_ctx;

typedef void (*hail2_on_frame_fn)(hail2_ctx *ctx,
                                  const hail2_meta_t *meta,
                                  const uint8_t *app, size_t app_len,
                                  void *user);

typedef enum {
    HAIL2_EVT_NODE_UP = 1,
    HAIL2_EVT_NODE_DOWN,
    HAIL2_EVT_SIG_BAD,
    HAIL2_EVT_REPLAY_DROP,
} hail2_event_t;

typedef struct hail2_event_info_s {
    hail2_event_t kind;
    uint64_t      src_id;
    uint32_t      ip4;    /* BE if known */
    uint16_t      port;
} hail2_event_info_t;

typedef void (*hail2_on_event_fn)(hail2_ctx *ctx,
                                  const hail2_event_info_t *ev,
                                  void *user);

typedef struct hail2_config_s {
    uint16_t port;
    uint16_t mtu;
    uint32_t bind_ip4;
    bool     enable_broadcast;
    uint32_t   dedupe_ms;       /* 0 => default(3000) */
    uint32_t beacon_period_ms;
    uint32_t announce_period_ms;
    uint32_t node_expire_ms;

    uint8_t  default_ttl;
    bool     relay_enable;

    const uint8_t *psk;
    size_t         psk_len;
    hail2_sig_alg_t sig_alg;
    uint8_t        sig_trunc;
    uint32_t       key_id;

    uint64_t src_id;
    char     alias[HAIL2_MAX_ALIAS+1];
    const char *const *roles;
    const char *const *caps;

    hail2_on_frame_fn on_frame;
    hail2_on_event_fn on_event;
    void *user;
} hail2_config_t;

int  hail2_init(const hail2_config_t *cfg, hail2_ctx **out);
void hail2_close(hail2_ctx *ctx);
int  hail2_fd(const hail2_ctx *ctx);
int  hail2_step(hail2_ctx *ctx);

int  hail2_send_beacon(hail2_ctx *ctx);
int  hail2_send_announce(hail2_ctx *ctx);

typedef struct hail2_addr_s {
    uint32_t ip4;  /* BE */
    uint16_t port; /* host order; 0 => cfg.port */
} hail2_addr_t;

int hail2_send(hail2_ctx *ctx,
               hail2_type_t type,
               uint8_t flags,
               const hail2_addr_t *to,
               const uint8_t *app, size_t app_len,
               const hail2_opts_t *opts,
               uint64_t *out_msg_id);

int hail2_send_ping  (hail2_ctx *ctx, const hail2_addr_t *to, const hail2_opts_t *opts, uint64_t *out_msg_id);
int hail2_send_pong  (hail2_ctx *ctx, const hail2_addr_t *to, uint64_t correl_id, const hail2_opts_t *opts);
int hail2_send_data  (hail2_ctx *ctx, const hail2_addr_t *to, const void *payload, size_t len,
                      bool ack_req, bool relay_ok, const hail2_opts_t *opts, uint64_t *out_msg_id);
int hail2_send_ack   (hail2_ctx *ctx, const hail2_addr_t *to, uint64_t correl_id, const hail2_opts_t *opts);
int hail2_send_topoq (hail2_ctx *ctx, uint8_t ttl, const hail2_opts_t *opts, uint64_t *out_msg_id);
int hail2_send_topoa (hail2_ctx *ctx, const hail2_addr_t *to,
                      const uint32_t *neighbors_ip4_be, const uint8_t *neighbors_age_s,
                      size_t neighbors_count, const hail2_opts_t *opts);

int       hail2_set_signing(hail2_ctx *ctx, const uint8_t *psk, size_t psk_len, uint8_t sig_trunc, uint32_t key_id);
size_t hail2_max_app_bytes(const hail2_ctx *ctx, const hail2_opts_t *opts);
uint64_t  hail2_src_id(const hail2_ctx *ctx);
/* Node snapshot (for UIs / demos) */
typedef struct hail2_node_info_s {
    uint64_t src_id;
    uint32_t ip4;     /* BE (0 if unknown for self) */
    uint16_t port;
    uint32_t age_ms;  /* 0 for new/self */
    uint8_t  up;      /* boolean */
} hail2_node_info_t;

/* Copy up to max nodes into out. Returns count. If include_self=true, adds your node as entry 0. */
size_t hail2_nodes_copy(const hail2_ctx *ctx,
                        hail2_node_info_t *out, size_t max,
                        bool include_self);

typedef struct hail2_frame_s { hail2_hdr_t hdr; } hail2_frame_t;

size_t hail2_pack(uint8_t *buf, size_t buf_len,
                  hail2_hdr_t *hdr_inout,
                  const hail2_opts_t *opts,
                  const uint8_t *app, size_t app_len,
                  const hail2_config_t *cfg);

int hail2_unpack(const uint8_t *buf, size_t len,
                 hail2_meta_t *meta_out,
                 const uint8_t **app_out, size_t *app_len_out,
                 const hail2_config_t *cfg);

size_t hail2_varint_encode(uint64_t v, uint8_t *out, size_t out_cap);
int    hail2_varint_decode(const uint8_t *in, size_t in_len, uint64_t *v_out, size_t *consumed_out);

#define HAIL2_E_OVERFLOW   (-10)
#define HAIL2_E_BADARGS    (-11)
#define HAIL2_E_NOMEM      (-12)
#define HAIL2_E_SOCKET     (-13)
#define HAIL2_E_SIGFAIL    (-14)
#define HAIL2_E_REPLAY     (-15)

/* Example:
 *   hail2_opts_t opts; hail2_opts_reset(&opts);
 *   hail2_opts_content_type(&opts, HAIL2_CT_JSON);
 *   // Broadcast send: pass NULL for 'to'
 *   uint64_t mid; hail2_send_data(ctx, NULL, payload, len, true, true, &opts, &mid);
 */

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* HAIL2_H */
