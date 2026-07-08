

#include "ui_activity.h"

#include "esp_log.h"

static const char *TAG = "sniffcheck_ui";

static const ui_activity_t *s_current = NULL;

void ui_activity_switch(const ui_activity_t *next, void *ctx)
{
    if (next == s_current) {
        return;
    }

    if (s_current && s_current->on_exit) {
        s_current->on_exit(ctx);
    }

    const ui_activity_t *prev = s_current;
    s_current = next;

    ESP_LOGD(TAG, "activity %s -> %s",
             prev ? prev->name : "(none)",
             next ? next->name : "(none)");

    if (s_current && s_current->on_enter) {
        s_current->on_enter(ctx);
    }
}

void ui_activity_tick(void *ctx)
{
    if (!s_current) {
        return;
    }
    if (s_current->loop) {
        s_current->loop(ctx);
    }
    if (s_current->render) {
        s_current->render(ctx);
    }
}

const ui_activity_t *ui_activity_current(void)
{
    return s_current;
}
