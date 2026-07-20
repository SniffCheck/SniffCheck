#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_http_server.h"

#include "cluster_web.h"
#include "master_shim.h"

static const char *TAG = "cluster-web";

extern const char _binary_dogpark_dashboard_html_start[];

static esp_err_t dogpark_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, _binary_dogpark_dashboard_html_start, HTTPD_RESP_USE_STRLEN);
}

static double   s_lat = NAN, s_lon = NAN;
static float    s_acc = 0;
static int64_t  s_wall_base_ms = 0;
static int64_t  s_wall_base_us = 0;
static bool     s_have_time = false;

bool cluster_web_gps(double *lat, double *lon, float *acc, int64_t *wall_ms)
{
    if (!s_have_time) return false;
    if (wall_ms) *wall_ms = s_wall_base_ms + (esp_timer_get_time() - s_wall_base_us) / 1000;
    if (lat) *lat = s_lat;
    if (lon) *lon = s_lon;
    if (acc) *acc = s_acc;
    return true;
}

static bool json_num(const char *body, const char *key, double *out)
{
    char pat[24];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "null", 4) == 0) return false;
    char *end = NULL;
    double v = strtod(p, &end);
    if (end == p) return false;
    *out = v;
    return true;
}

static esp_err_t gps_post(httpd_req_t *req)
{
    char buf[256];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';

    double ts, lat, lon, acc;
    if (!json_num(buf, "ts", &ts)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ts required\"}");
        return ESP_OK;
    }
    s_wall_base_ms = (int64_t)ts;
    s_wall_base_us = esp_timer_get_time();
    s_have_time    = true;
    if (json_num(buf, "lat", &lat) && json_num(buf, "lon", &lon)) {
        s_lat = lat; s_lon = lon;
        s_acc = json_num(buf, "acc", &acc) ? (float)acc : 0.0f;
    } else {
        s_lat = s_lon = NAN;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t status_get(httpd_req_t *req)
{

    char body[1536], fix[160];
    master_cluster_status_json(body, sizeof(body));

    size_t len = strlen(body);
    if (len && body[len - 1] == '}') body[len - 1] = '\0';
    double lat, lon; float acc; int64_t wall;
    if (cluster_web_gps(&lat, &lon, &acc, &wall)) {
        if (isnan(lat))
            snprintf(fix, sizeof(fix), ",\"gps\":{\"fix\":false,\"time\":true,\"wall_ms\":%lld}}",
                     (long long)wall);
        else
            snprintf(fix, sizeof(fix),
                ",\"gps\":{\"fix\":true,\"lat\":%.6f,\"lon\":%.6f,\"acc\":%.1f,\"wall_ms\":%lld}}",
                lat, lon, acc, (long long)wall);
    } else {
        snprintf(fix, sizeof(fix), ",\"gps\":{\"fix\":false,\"time\":false}}");
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, fix, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t log_get(httpd_req_t *req)
{
    static char body[3072];
    master_cluster_log_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t sentinel_get(httpd_req_t *req)
{
    static char body[2048];
    master_cluster_sentinel_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t sentinel_post(httpd_req_t *req)
{
    char buf[320];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_sentinel_cfg(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t scan_post(httpd_req_t *req)
{
    master_on_rescan_request();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true,\"disconnecting\":false}");
    return ESP_OK;
}

static esp_err_t walk_post(httpd_req_t *req)
{
    char q[32]; bool start = true;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char v[8];
        if (httpd_query_key_value(q, "start", v, sizeof(v)) == ESP_OK)
            start = (v[0] == '1');
    }
    master_on_walk_request(start);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, start ? "{\"ok\":true,\"walking\":true,\"disconnecting\":false}"
                                  : "{\"ok\":true,\"walking\":false,\"disconnecting\":false}");
    return ESP_OK;
}

static esp_err_t epup_label_post(httpd_req_t *req)
{
    char buf[48];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_epup_label(buf);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t places_get(httpd_req_t *req)
{
    static char body[2048];
    master_cluster_places_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t place_label_post(httpd_req_t *req)
{
    char buf[96];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_place_label(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t hits_get(httpd_req_t *req)
{
    static char body[4096];
    master_cluster_hits_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t time_post(httpd_req_t *req)
{
    char buf[24];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_settime((uint32_t)strtoul(buf, NULL, 10));
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t brain_reset_post(httpd_req_t *req)
{
    master_on_brain_reset();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

esp_err_t cluster_web_start(httpd_handle_t server)
{
    if (!server) return ESP_ERR_INVALID_STATE;
    static const httpd_uri_t routes[] = {
        { .uri = "/dogpark",            .method = HTTP_GET,  .handler = dogpark_get },
        { .uri = "/api/gps",            .method = HTTP_POST, .handler = gps_post },
        { .uri = "/api/cluster/status", .method = HTTP_GET,  .handler = status_get },
        { .uri = "/api/cluster/log",    .method = HTTP_GET,  .handler = log_get },
        { .uri = "/api/cluster/sentinel", .method = HTTP_GET,  .handler = sentinel_get },
        { .uri = "/api/cluster/sentinel", .method = HTTP_POST, .handler = sentinel_post },
        { .uri = "/api/cluster/scan",   .method = HTTP_POST, .handler = scan_post },
        { .uri = "/api/cluster/walk",   .method = HTTP_POST, .handler = walk_post },
        { .uri = "/api/cluster/epup/label", .method = HTTP_POST, .handler = epup_label_post },
        { .uri = "/api/cluster/places", .method = HTTP_GET,  .handler = places_get },
        { .uri = "/api/cluster/place/label", .method = HTTP_POST, .handler = place_label_post },
        { .uri = "/api/cluster/sentinel/hits", .method = HTTP_GET, .handler = hits_get },
        { .uri = "/api/cluster/time",   .method = HTTP_POST, .handler = time_post },
        { .uri = "/api/cluster/brain/reset", .method = HTTP_POST, .handler = brain_reset_post },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        esp_err_t e = httpd_register_uri_handler(server, &routes[i]);
        if (e != ESP_OK) ESP_LOGE(TAG, "register %s: %s", routes[i].uri, esp_err_to_name(e));
    }
    ESP_LOGI(TAG, "cluster routes registered (/api/gps, /api/cluster/*)");
    return ESP_OK;
}
