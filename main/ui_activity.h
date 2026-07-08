#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ui_activity {
    const char *name;
    void (*on_enter)(void *ctx);
    void (*loop)(void *ctx);
    void (*render)(void *ctx);
    void (*on_exit)(void *ctx);
} ui_activity_t;

void ui_activity_switch(const ui_activity_t *next, void *ctx);

void ui_activity_tick(void *ctx);

const ui_activity_t *ui_activity_current(void);

#ifdef __cplusplus
}
#endif
