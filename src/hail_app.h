// hail_app.h
#pragma once
#define _GNU_SOURCE 1

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>      // strcmp

// ========= runtime config =========
typedef struct {
    const char  *alias;          // node alias (optional)
    const char **roles;          // NULL-terminated list of role strings
    const char **caps;           // NULL-terminated list of capability strings
    const char  *exec_prog;      // e.g. "/usr/bin/hail-exec"
    bool         http_enable;    // HTTP/SSE control plane
    uint16_t     http_port;      // default 8080
} haild_config;

static inline bool haild_has_role(const haild_config *c, const char *role){
    if(!c || !c->roles || !role) return false;
    for(size_t i=0; c->roles[i]; ++i) if(!strcmp(c->roles[i], role)) return true;
    return false;
}
static inline bool haild_has_cap(const haild_config *c, const char *cap){
    if(!c || !c->caps || !cap) return false;
    for(size_t i=0; c->caps[i]; ++i) if(!strcmp(c->caps[i], cap)) return true;
    return false;
}

// ========= EXEC request (received or locally generated) =========
typedef struct {
    const char *method;     // "EXEC"
    const char *path;       // e.g. "/sys/led"
    const char *args_json;  // JSON string (may be NULL)
    uint32_t    req_id;     // request id

    uint64_t src_id;        // sender id (if inbound)
    uint32_t ip4_be;        // sender ip (BE)
    uint16_t port;          // sender port (host)

    const char *content_type; // "json" / "tlv"
} haild_exec_req;

// Runs the EXEC hook (injects env and runs shell/script). Returns bytes written to `out`, or <0.
ssize_t haild_exec_run(const haild_exec_req *req, char *out, size_t cap);
