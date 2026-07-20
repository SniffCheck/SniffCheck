#include "cluster_proto.h"

uint16_t cl_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

void cl_status_seal(cl_status_t *s)
{
    s->magic     = CL_MAGIC;
    s->proto_ver = CL_PROTO_VER;
    s->crc = cl_crc16((const uint8_t *)s, offsetof(cl_status_t, crc));
}

int cl_status_valid(const cl_status_t *s)
{
    if (s->magic != CL_MAGIC || s->proto_ver != CL_PROTO_VER) return 0;
    return s->crc == cl_crc16((const uint8_t *)s, offsetof(cl_status_t, crc));
}

void cl_cmd_build(cl_cmd_frame_t *f, cl_cmd_t cmd, uint8_t arg)
{
    f->magic = CL_MAGIC;
    f->cmd   = (uint8_t)cmd;
    f->arg   = arg;
    f->crc   = (uint8_t)(f->magic ^ f->cmd ^ f->arg);
}

int cl_cmd_valid(const cl_cmd_frame_t *f)
{
    return f->magic == CL_MAGIC &&
           f->crc == (uint8_t)(f->magic ^ f->cmd ^ f->arg);
}

void cl_plan_seal(cl_plan_t *p)
{
    p->magic = CL_MAGIC;
    p->cmd   = (uint8_t)CL_CMD_SET_PLAN;
    p->crc   = cl_crc16((const uint8_t *)p, offsetof(cl_plan_t, crc));
}

int cl_plan_valid(const cl_plan_t *p)
{
    if (p->magic != CL_MAGIC || p->cmd != (uint8_t)CL_CMD_SET_PLAN) return 0;
    return p->crc == cl_crc16((const uint8_t *)p, offsetof(cl_plan_t, crc));
}

void cl_placelabel_seal(cl_placelabel_t *p)
{
    p->magic = CL_MAGIC;
    p->cmd   = (uint8_t)CL_CMD_SET_PLACELABEL;
    p->crc   = cl_crc16((const uint8_t *)p, offsetof(cl_placelabel_t, crc));
}

int cl_placelabel_valid(const cl_placelabel_t *p)
{
    if (p->magic != CL_MAGIC || p->cmd != (uint8_t)CL_CMD_SET_PLACELABEL) return 0;
    return p->crc == cl_crc16((const uint8_t *)p, offsetof(cl_placelabel_t, crc));
}

void cl_places_seal(cl_places_t *p)
{
    p->magic = CL_MAGIC;
    p->cmd   = (uint8_t)CL_CMD_GET_PLACES;
    p->crc   = cl_crc16((const uint8_t *)p, offsetof(cl_places_t, crc));
}

int cl_places_valid(const cl_places_t *p)
{
    if (p->magic != CL_MAGIC || p->cmd != (uint8_t)CL_CMD_GET_PLACES) return 0;
    if (p->count > CL_PLACE_MAX) return 0;
    return p->crc == cl_crc16((const uint8_t *)p, offsetof(cl_places_t, crc));
}

void cl_getreq_build_cmd(cl_getreq_t *g, uint8_t cmd, uint32_t offset)
{
    g->magic  = CL_MAGIC;
    g->cmd    = cmd;
    g->offset = offset;
    g->crc    = cl_crc16((const uint8_t *)g, offsetof(cl_getreq_t, crc));
}

int cl_getreq_valid_cmd(const cl_getreq_t *g, uint8_t cmd)
{
    if (g->magic != CL_MAGIC || g->cmd != cmd) return 0;
    return g->crc == cl_crc16((const uint8_t *)g, offsetof(cl_getreq_t, crc));
}

void cl_getreq_build(cl_getreq_t *g, uint32_t offset)
{
    cl_getreq_build_cmd(g, (uint8_t)CL_CMD_GET_SCANSET, offset);
}

int cl_getreq_valid(const cl_getreq_t *g)
{
    return cl_getreq_valid_cmd(g, (uint8_t)CL_CMD_GET_SCANSET);
}

void cl_chunk_seal(cl_chunk_t *c)
{
    c->magic = CL_MAGIC;
    if (c->len < CL_CHUNK_PAYLOAD)
        for (uint16_t i = c->len; i < CL_CHUNK_PAYLOAD; i++) c->payload[i] = 0;
    c->crc = cl_crc16((const uint8_t *)c, offsetof(cl_chunk_t, crc));
}

int cl_chunk_valid(const cl_chunk_t *c)
{
    if (c->magic != CL_MAGIC) return 0;
    if (c->len > CL_CHUNK_PAYLOAD) return 0;
    return c->crc == cl_crc16((const uint8_t *)c, offsetof(cl_chunk_t, crc));
}
