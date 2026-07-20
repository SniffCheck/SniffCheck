#pragma once

#include <stdint.h>
#include <stddef.h>

#define CL_MAGIC      0x5C
#define CL_PROTO_VER  2

typedef enum {
    CL_CMD_PING        = 0x01,
    CL_CMD_SCAN        = 0x02,
    CL_CMD_GET_SCANSET = 0x03,
    CL_CMD_SET_MODE    = 0x04,
    CL_CMD_WALK        = 0x05,
    CL_CMD_GET_VERDICT = 0x06,
    CL_CMD_GET_EPUP    = 0x07,
    CL_CMD_SET_PLAN    = 0x08,
    CL_CMD_SET_PLACELABEL = 0x09,
    CL_CMD_GET_CKPT    = 0x0A,
    CL_CMD_GET_PLACES  = 0x0B,
    CL_CMD_RESET_BRAIN = 0x0C,

    CL_CMD_GET_SENT    = 0x0D,
    CL_CMD_GET_HITS    = 0x0E,
    CL_CMD_STATUS_SEL  = 0x0F,
    CL_CMD_SET_CLOCK   = 0x10,
} cl_cmd_t;

typedef enum { CL_SCAN_REGULAR = 0, CL_SCAN_ADV = 1 } cl_scan_mode_t;

typedef enum { CL_BAND_24_BLE = 1, CL_BAND_5_BLE = 2 } cl_band_t;

typedef enum { CL_STATE_IDLE = 0, CL_STATE_SCANNING = 1, CL_STATE_WALKING = 2 } cl_state_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  proto_ver;
    uint8_t  arm_index;
    uint8_t  band;
    uint8_t  state;
    uint8_t  scanset_ready;
    uint16_t wifi_seen;
    uint16_t ble_seen;
    uint32_t scan_seq;
    uint32_t scanset_len;
    uint16_t crc;
} cl_status_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  cmd;
    uint8_t  arg;
    uint8_t  crc;
} cl_cmd_frame_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  cmd;
    uint8_t  n_arms;
    uint8_t  arm_slot;
    uint16_t dwell_ms;
    uint16_t dwell_adv_ms;
    uint8_t  ble_every_n;
    uint8_t  flags;
    uint16_t crc;
} cl_plan_t;

#define CL_PLAN_FLAG_DFS  0x01

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  cmd;
    int8_t   idx;
    uint8_t  _pad;
    char     label[16];
    uint16_t crc;
} cl_placelabel_t;

#define CL_PLACE_MAX  6
typedef struct __attribute__((packed)) {
    char     label[16];
    uint32_t scans;
    uint16_t landmarks;
    uint8_t  flags;
    uint8_t  idx;
} cl_place_entry_t;
#define CL_PLACE_F_KNOWN    0x01u
#define CL_PLACE_F_CURRENT  0x02u
typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  cmd;
    uint8_t  count;
    int8_t   cur;
    cl_place_entry_t entries[CL_PLACE_MAX];
    uint16_t crc;
} cl_places_t;

#define CL_CHUNK_PAYLOAD  240

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  cmd;
    uint32_t offset;
    uint16_t crc;
} cl_getreq_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  type;
    uint32_t scan_seq;
    uint32_t total_len;
    uint32_t offset;
    uint16_t len;
    uint8_t  payload[CL_CHUNK_PAYLOAD];
    uint16_t crc;
} cl_chunk_t;

#define CL_RESP_CHUNK  1

#define CL_PUT_BASE       0x20
#define CL_PUT_TYPE(arm)  (uint8_t)(CL_PUT_BASE | ((arm) & 0x0F))
#define CL_PUT_IS(t)      (((t) & 0xF0) == CL_PUT_BASE)
#define CL_PUT_ARM(t)     ((t) & 0x0F)

#define CL_PUT_CKPT       0x30

#define CL_PUT_S3MERGE    0x32

#define CL_PUT_SENTCFG    0x34

uint16_t cl_crc16(const uint8_t *data, size_t len);

void cl_status_seal(cl_status_t *s);
int  cl_status_valid(const cl_status_t *s);

void cl_cmd_build(cl_cmd_frame_t *f, cl_cmd_t cmd, uint8_t arg);
int  cl_cmd_valid(const cl_cmd_frame_t *f);

void cl_plan_seal(cl_plan_t *p);
int  cl_plan_valid(const cl_plan_t *p);

void cl_placelabel_seal(cl_placelabel_t *p);
int  cl_placelabel_valid(const cl_placelabel_t *p);

void cl_places_seal(cl_places_t *p);
int  cl_places_valid(const cl_places_t *p);

void cl_getreq_build(cl_getreq_t *g, uint32_t offset);
int  cl_getreq_valid(const cl_getreq_t *g);
void cl_getreq_build_cmd(cl_getreq_t *g, uint8_t cmd, uint32_t offset);
int  cl_getreq_valid_cmd(const cl_getreq_t *g, uint8_t cmd);

void cl_chunk_seal(cl_chunk_t *c);
int  cl_chunk_valid(const cl_chunk_t *c);
