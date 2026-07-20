#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include "esp_http_server.h"

esp_err_t cluster_web_start(httpd_handle_t server);

bool cluster_web_gps(double *lat, double *lon, float *acc, int64_t *wall_ms);
