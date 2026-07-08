#include "download_http.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "capture_ring.h"
#include "capture_writer.h"
#include "download_mode.h"
#include "app_settings.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#include "sta_tracker.h"
#include "wifi_csi_probe.h"
#include "pcap_capture.h"

static const char *TAG = "sc_dlhttp";

static httpd_handle_t s_server = NULL;

#define STREAM_LINE_MAX 4200

extern const char _binary_capture_viewer_html_start[];
extern const unsigned char _binary_webap_logo_png_start[];
extern const unsigned char _binary_webap_logo_png_end[];
extern const unsigned char _binary_webap_favicon_png_start[];
extern const unsigned char _binary_webap_favicon_png_end[];
extern const unsigned char _binary_webap_pup_png_start[];
extern const unsigned char _binary_webap_pup_png_end[];

#define ISLAND_MARKER "<!--SC_DATA_ISLAND-->"

static const char *s_view_head;
static size_t      s_view_head_len;
static const char *s_view_tail;
static size_t      s_view_tail_len;

static void viewer_locate_marker(void)
{
    if (s_view_head) return;
    const char *blob = _binary_capture_viewer_html_start;
    const char *mark = strstr(blob, ISLAND_MARKER);
    if (!mark) {
        ESP_LOGE(TAG, "viewer asset has no data-island marker — report route off");
        return;
    }
    s_view_head     = blob;
    s_view_head_len = (size_t)(mark - blob);
    s_view_tail     = mark + strlen(ISLAND_MARKER);
    s_view_tail_len = strlen(s_view_tail);
    ESP_LOGI(TAG, "viewer asset: %u + %u bytes around data island",
             (unsigned)s_view_head_len, (unsigned)s_view_tail_len);
}

static esp_err_t send_json(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t send_chunk_escaped(httpd_req_t *req, const char *p, size_t len)
{
    size_t i = 0, seg = 0;
    while (i + 1 < len) {
        if (p[i] == '<' && p[i + 1] == '/') {
            if (httpd_resp_send_chunk(req, p + seg, i + 1 - seg) != ESP_OK)
                return ESP_FAIL;
            if (httpd_resp_send_chunk(req, "\\", 1) != ESP_OK)
                return ESP_FAIL;
            seg = i + 1;
            i += 2;
        } else {
            i++;
        }
    }
    if (len > seg && httpd_resp_send_chunk(req, p + seg, len - seg) != ESP_OK)
        return ESP_FAIL;
    return ESP_OK;
}

static esp_err_t stream_ring(httpd_req_t *req, bool escaped, size_t *count_out)
{
    char *buf = heap_caps_malloc(STREAM_LINE_MAX + 1, MALLOC_CAP_SPIRAM);
    if (!buf) return ESP_ERR_NO_MEM;

    capture_ring_reader_t r;
    capture_ring_reader_open(&r);

    size_t emitted = 0;
    esp_err_t err = ESP_OK;
    for (;;) {
        size_t len = capture_ring_reader_next(&r, buf, STREAM_LINE_MAX);
        if (len == 0) break;
        buf[len++] = '\n';
        err = escaped ? send_chunk_escaped(req, buf, len)
                      : httpd_resp_send_chunk(req, buf, len);
        if (err != ESP_OK) { err = ESP_FAIL; break; }
        if (++emitted % 32 == 0) vTaskDelay(1);
    }
    heap_caps_free(buf);
    if (count_out) *count_out = emitted;
    return err;
}

static const char DASH_HTML[] =
"<!DOCTYPE html><html><head><meta charset=utf-8>"
"<meta name=viewport content=\"width=device-width,initial-scale=1\">"
"<title>SniffCheck</title><link rel=icon type=\"image/png\" href=\"/favicon.ico\"><style>"

":root{--bg:#ffd93b;--panel:#fff7d6;--ink:#3f2a14;--line:#3f2a14;--muted:#7a5a34;"
"--sh:#3f2a14;--accent:#ff8a1e;--pname:#e0701a;--safe:#2fa85a;--trk:#fff;"
"--onacc:#3f2a14}"
"body.dark{--bg:#241a0e;--panel:#3a2a18;--ink:#f3e4bf;--line:#c8a25a;--muted:#c9ac7e;"
"--sh:#100a04;--accent:#ffcf4a;--pname:#ffb14a;--safe:#5ec98a;--trk:#0f0a04}"
"body{font:15px/1.35 system-ui,sans-serif;background:var(--bg);color:var(--ink);"
"margin:0 auto;padding:12px;max-width:480px}"
"h1{margin:2px 0}h1 img{display:block;height:44px;width:auto;max-width:100%;"
"border:3px solid var(--line);border-radius:11px;background:var(--panel);padding:3px 6px;"
"box-shadow:3px 3px 0 var(--sh)}"
".m{color:var(--muted);font-size:13px;font-weight:700;margin:6px 0 8px}"
"#card{background:var(--panel);border:3px solid var(--line);border-radius:12px;"
"padding:10px 12px;margin:8px 0;font-size:14px;box-shadow:4px 4px 0 var(--sh)}"
"#card div{display:flex;justify-content:space-between;gap:10px;padding:2px 0}"
"#card b{color:var(--muted);font-weight:700}"
"#rem{font-size:20px;font-weight:900;color:var(--safe)}"
"a.b,button{display:block;width:100%;box-sizing:border-box;margin:6px 0;"
"padding:9px;border:2px solid var(--line);border-radius:9px;font-size:15px;font-weight:800;"
"text-align:center;text-decoration:none;color:#181206;cursor:pointer;"
"box-shadow:3px 3px 0 var(--sh)}"
"a.b:active,button:active{transform:translate(2px,2px);box-shadow:0 0 0 var(--sh)}"
".rep{background:#ffcf4a}.dl{background:#45c07a}.ext{background:#ffdd8a}"
".cl{background:#ef8a22}.off{background:#d63838;color:#fff}"
"button[data-armed]{outline:3px solid var(--line);outline-offset:2px}"
"h2{font-size:13px;margin:12px 0 4px;color:var(--ink);font-weight:900;"
"text-transform:uppercase;letter-spacing:.6px}"
".set label{display:flex;justify-content:space-between;align-items:center;"
"gap:10px;margin:8px 0;font-size:14px}"
".set select{font:15px system-ui;padding:8px;border-radius:8px;font-weight:700;"
"border:2px solid var(--line);background:var(--panel);color:var(--ink);min-width:108px}"
".ex{color:var(--muted);font-size:12px;margin:-1px 0 8px}"
".hot{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}"
".hotlbl{width:100%;font-size:14px;font-weight:700}"
".set label.hotck{display:inline-flex;justify-content:flex-start;gap:6px;margin:0;"
"font-size:13px;font-weight:700;padding:6px 10px;border:2px solid var(--line);"
"border-radius:8px;background:var(--panel);cursor:pointer}"
".hotck input{width:16px;height:16px;accent-color:var(--accent)}"
".dz{margin-top:14px;border-top:2px solid var(--line);padding-top:4px}"
"#pcard{background:var(--panel);border:3px solid var(--line);border-radius:12px;"
"padding:10px 12px;margin:8px 0;font-size:14px;box-shadow:4px 4px 0 var(--sh)}"
"#pcard>div{display:flex;justify-content:space-between;gap:10px;"
"align-items:center;margin:4px 0}"
"#pname{color:var(--pname);font-size:16px;font-weight:900}"
".pm{color:var(--muted);font-size:12px;text-transform:capitalize}"
".dimx{color:var(--muted);font-size:12px}"
"#pcard .pbar{display:block;height:9px;background:var(--trk);"
"border:2px solid var(--line);border-radius:5px;overflow:hidden;margin:6px 0}"
"#pcard .pbar i{display:block;height:100%;background:var(--safe)}"
".pstat{color:var(--muted);font-size:12px}"
"#nav{display:flex;gap:8px;margin:6px 0 4px}"
"#nav button{margin:0;padding:8px;font-size:14px;background:var(--panel);color:var(--ink)}"
"#nav button.act{background:var(--accent);color:var(--onacc)}"
".view{display:none}.view.act{display:block}"
".bytypes{margin:8px 0 10px;padding-left:20px;color:var(--muted);font-size:13px}"
"#byname,#bystat{color:var(--muted);font-size:13px;margin:6px 0}"
"#dig{position:fixed;inset:0;background:rgba(20,14,6,.93);display:none;z-index:9;"
"align-items:center;justify-content:center;text-align:center;padding:20px;color:#ffd93b;font-weight:800}"
"#dig span{display:block;color:#fff7d6;font-size:14px;font-weight:600;margin-top:8px}"
".wc{background:var(--panel);border:3px solid var(--safe);border-radius:12px;"
"padding:10px 12px;margin:8px 0;font-size:14px;display:none;box-shadow:4px 4px 0 var(--sh)}"
".wc h3{margin:0 0 6px;color:var(--safe);font-size:15px}"
".wc .wr{display:flex;justify-content:space-between;gap:10px;padding:1px 0;color:var(--muted)}"
".wc .wr b{color:var(--ink);font-weight:700}"
".wc.alert{border-color:#e5701a}.wc.alert h3{color:#e5701a}"

"#themebtn{position:fixed;top:10px;right:10px;z-index:15;width:42px;height:42px;"
"display:flex;align-items:center;justify-content:center;padding:0;margin:0;cursor:pointer;"
"color:var(--ink);background:var(--panel);border:3px solid var(--line);border-radius:11px;"
"box-shadow:3px 3px 0 var(--sh)}"
"#themebtn svg{width:22px;height:22px}"
"#themebtn .moon{display:none}body.dark #themebtn .sun{display:none}"
"body.dark #themebtn .moon{display:inline}"

"#pupimg{display:block;height:120px;width:auto;margin:2px auto 6px}"
"#splash{position:fixed;inset:0;background:var(--bg);display:flex;z-index:20;"
"align-items:center;justify-content:center;transition:opacity .45s}"
"#splash img{width:68%;max-width:300px;height:auto;"
"filter:drop-shadow(4px 4px 0 var(--sh))}"
"#splash.hide{opacity:0;pointer-events:none}"
"@media(prefers-reduced-motion:reduce){#splash{transition:none}}"
"</style></head><body>"

"<script>var TH={'sniffcheck':[0],'sniffcheck-dark':[1],"
"'dracula':[1,'#282a36','#343746','#f8f8f2','#bd93f9','#9ba3cf','#191a21','#ff79c6','#bd93f9','#50fa7b','#191a21','#282a36'],"
"'nord':[1,'#2e3440','#3b4252','#eceff4','#88c0d0','#a9b6c9','#232831','#88c0d0','#81a1c1','#a3be8c','#232831','#2e3440'],"
"'gruvbox-dark':[1,'#282828','#32302f','#ebdbb2','#d79921','#a89984','#1d2021','#fabd2f','#fe8019','#b8bb26','#1d2021','#282828'],"
"'solarized-light':[0,'#fdf6e3','#eee8d5','#073642','#586e75','#657b83','#93a1a1','#b58900','#cb4b16','#859900','#ffffff','#fdf6e3'],"
"'tokyo-night':[1,'#1a1b26','#24283b','#c0caf5','#7aa2f7','#9aa5ce','#0f101a','#7aa2f7','#bb9af7','#9ece6a','#0f101a','#1a1b26'],"
"'monokai':[1,'#272822','#34352d','#f8f8f2','#e6db74','#a59f85','#1b1c17','#fd971f','#e6db74','#a6e22e','#1b1c17','#272822']};"
"var THV=['bg','panel','ink','line','muted','sh','accent','pname','safe','trk','onacc'],"
"curth='sniffcheck';"
"function applyth(id){if(!TH[id])id='sniffcheck';var t=TH[id],"
"s=document.body.style,i;"
"for(i=0;i<THV.length;i++){if(t[i+1])s.setProperty('--'+THV[i],t[i+1]);"
"else s.removeProperty('--'+THV[i])}"
"document.body.classList.toggle('dark',!!t[0]);curth=id;"
"var e=document.getElementById('thm');if(e)e.value=id}"
"function setthm(id){applyth(id);"
"try{localStorage.setItem('sc-theme',curth)}catch(e){}}"
"try{var t0=localStorage.getItem('sc-theme');"
"applyth(t0==='dark'?'sniffcheck-dark':t0==='light'?'sniffcheck':t0||'sniffcheck')}"
"catch(e){}</script>"
"<div id=splash><img alt=\"SniffCheck\" src=\"/logo.png\"></div>"
"<script>setTimeout(function(){var s=document.getElementById('splash');"
"if(s){s.classList.add('hide');setTimeout(function(){s.style.display='none'},450)}},1200);</script>"
"<button id=themebtn type=button title=\"Quick light/dark flip (full theme list in Settings)\" aria-label=\"Toggle dark mode\">"
"<svg class=sun viewBox=\"0 0 24 24\" aria-hidden=true><circle cx=12 cy=12 r=5 fill=currentColor/>"
"<g stroke=currentColor stroke-width=2 stroke-linecap=round><path d=\"M12 1.5v3\"/><path d=\"M12 19.5v3\"/>"
"<path d=\"M1.5 12h3\"/><path d=\"M19.5 12h3\"/><path d=\"M4.2 4.2l2.1 2.1\"/><path d=\"M17.7 17.7l2.1 2.1\"/>"
"<path d=\"M19.8 4.2l-2.1 2.1\"/><path d=\"M6.3 17.7l-2.1 2.1\"/></g></svg>"
"<svg class=moon viewBox=\"0 0 24 24\" aria-hidden=true><path fill=currentColor d=\"M21 14.3A8.5 8.5 0 0 1 9.7 3 7.5 7.5 0 1 0 21 14.3z\"/></svg>"
"</button>"

"<script>document.getElementById('themebtn').onclick=function(){"
"setthm(document.body.classList.contains('dark')?'sniffcheck':'sniffcheck-dark')};</script>"
"<h1><img alt=\"SniffCheck\" src=\"/logo.png\"></h1>"
"<div class=m id=ssid>SniffCheck AP</div>"
"<div id=nav>"
"<button id=nv-home class=act onclick=\"nav('home')\">Home</button>"
"<button id=nv-pup onclick=\"nav('pup')\">Pup</button>"
"<button id=nv-byos onclick=\"nav('byos')\">BYOS</button>"
"<button id=nv-settings onclick=\"nav('settings')\">Settings</button>"
"</div>"

"<div class=\"view act\" id=v-home>"
"<div id=card>"
"<div><b>time remaining</b><span id=rem>–:––</span></div>"
"<div><b>capture</b><span id=recs>…</span></div>"
"<div><b>scans</b><span id=scans>…</span></div>"
"<div><b>clients</b><span id=cli>…</span></div>"
"<div><b>session</b><span id=sid>…</span></div>"
"<div><b>firmware</b><span id=fw>…</span></div>"
"</div>"
"<h2>Results</h2>"
"<a class=\"b rep\" href=\"/report.html\">View report</a>"
"<a class=\"b rep\" href=\"/report.html?dl=1\">Save report (.html)</a>"
"<a class=\"b dl\" href=\"/api/captures/live.jsonl\">Download data (.jsonl)</a>"
"<h2>Session</h2>"
"<button class=ext onclick=\"post('/api/download/extend')\">Keep awake +15 min</button>"
"<button class=rep onclick=\"armscan(this)\">Start new scan</button>"
"<div class=ex>A new scan uses the Wi-Fi radio, so this page disconnects. Re-open the SniffCheck AP on the device after the scan to see the new results.</div>"
"<button class=off onclick=\"arm(this,'/api/download/disable')\">Close AP</button>"
"<div class=dz><h2>Danger zone</h2>"
"<button class=cl onclick=\"arm(this,'/api/captures/clear-volatile')\">Clear capture</button>"
"</div>"
"</div>"

"<div class=view id=v-pup>"
"<h2>Virtual Pup</h2>"
"<img id=pupimg alt=\"Suz the pup\" src=\"/pup.png\">"
"<div id=pcard>"
"<div><span id=pname>Suz</span><span class=pm id=pmood>curious</span></div>"
"<div><span id=plvl>Level &ndash;</span><span class=dimx id=pxp></span></div>"
"<div class=pbar><i id=pbarf style=width:0></i></div>"
"<div class=pstat><span id=pscan>&ndash; scans</span><span id=ppt></span></div>"
"</div>"
"<button class=ext onclick=\"ppost('/api/pup/pet')\">Pet</button>"
"<button class=ext onclick=\"ppost('/api/pup/treat')\">Give treat</button>"
"<button class=ext onclick=\"prename()\">Rename</button>"
"<div class=ex>XP comes from real scans and walks. Petting and treats are just for fun.</div>"
"<h2>Sniff Walk</h2>"
"<div class=wc id=wcard2></div>"
"<button class=dl onclick=\"armwalk(this)\">Start Sniff Walk</button>"
"<div class=ex>The walk scans Wi-Fi &amp; BLE while you carry SniffCheck, so this AP closes. End the walk on the device button &mdash; the AP re-opens with the walk summary.</div>"
"<button class=off onclick=\"armpup(this)\">Reset Pup</button>"
"</div>"

"<div class=view id=v-byos>"
"<h2>Bring Your Own Scan</h2>"
"<div class=ex>Accepted file types:</div>"
"<ul class=bytypes>"
"<li>Biscuit JSON / JSONL</li><li>Wigle CSV / JSON</li>"
"<li>Kismet JSON / JSONL</li><li>Wardriver CSV / TXT / LOG with MAC addresses</li>"
"</ul>"
"<input id=byfile type=file multiple style=display:none accept=\".json,.jsonl,.csv,.txt,.log\">"
"<button class=ext onclick=\"bypick()\">Upload external scan(s)</button>"
"<div id=byname>No file selected.</div>"
"<button class=dl onclick=\"byparse()\">Carve</button>"

"<div id=bystat></div>"
"<a class=\"b dl\" id=bydl style=display:none download=sniffcheck-byos-devices.txt>Download carved device list</a>"
"<button class=rep id=bysc onclick=\"bysniff()\" disabled>SniffCheck</button>"
"<div class=ex>SniffCheck sends only the deduped device list to this device, then re-decodes each record against on-device eui.db so the upload lands in the report split into Wi-Fi and BLE. Active RF-only checks are unavailable for imported data.</div>"
"</div>"

"<div class=view id=v-settings>"
"<div class=set>"
"<h2>Settings</h2>"
"<label>Mode<select id=mode onchange=\"sset('/api/settings/mode',{mode:this.value})\">"
"<option value=lite>Lite</option><option value=adv>Adv</option></select></label>"
"<div class=ex>Lite is a quick glance verdict. Adv is the full audit with drill-down. Applies on the next scan.</div>"
"<label>Brightness<select id=bri onchange=\"sset('/api/settings/brightness',{pct:+this.value})\">"
"<option value=25>25%</option><option value=50>50%</option>"
"<option value=75>75%</option><option value=100>100%</option></select></label>"
"<div class=ex>Screen backlight level.</div>"
"<label>LED<select id=led onchange=\"sset('/api/settings/led',{enabled:this.value=='1'})\">"
"<option value=1>On</option><option value=0>Off</option></select></label>"
"<div class=ex>Status light on the dongle.</div>"
"<label>AP timeout<select id=tmo onchange=\"sset('/api/settings/download-timeout',{minutes:+this.value})\">"
"<option value=15>15 min</option><option value=30>30 min</option>"
"<option value=60>60 min</option></select></label>"
"<div class=ex>How long the SniffCheck AP stays open.</div>"

"<label>Theme<select id=thm onchange=\"setthm(this.value)\">"
"<option value=sniffcheck>SniffCheck Yellow</option>"
"<option value=sniffcheck-dark>SniffCheck Dark</option>"
"<option value=dracula>Dracula</option>"
"<option value=nord>Nord</option>"
"<option value=gruvbox-dark>Gruvbox Dark</option>"
"<option value=solarized-light>Solarized Light</option>"
"<option value=tokyo-night>Tokyo Night</option>"
"<option value=monokai>Monokai</option></select></label>"
"<div class=ex>WebUI colors, saved in this browser and shared with the report page.</div>"

"<div class=hot><span class=hotlbl>Quick tabs</span>"
"<label class=hotck><input type=checkbox value=s-wifi onchange=\"savehot()\">Wi-Fi</label>"
"<label class=hotck><input type=checkbox value=s-ble onchange=\"savehot()\">BLE</label>"
"<label class=hotck><input type=checkbox value=s-clusters onchange=\"savehot()\">Clusters</label>"
"<label class=hotck><input type=checkbox value=s-channel onchange=\"savehot()\">Channels</label>"
"<label class=hotck><input type=checkbox value=s-trackers onchange=\"savehot()\">Trackers</label>"
"<label class=hotck><input type=checkbox value=s-alerts onchange=\"savehot()\">Alerts</label>"
"<label class=hotck><input type=checkbox value=s-privacy onchange=\"savehot()\">Privacy</label>"
"<label class=hotck><input type=checkbox value=s-banner onchange=\"savehot()\">Summary</label>"
"<label class=hotck><input type=checkbox value=s-raw onchange=\"savehot()\">Raw</label>"
"<label class=hotck><input type=checkbox value=s-drones onchange=\"savehot()\">Drones</label>"
"</div>"
"<div class=ex>The report page's apps-grid button jumps to these tabs. Saved in this browser and shared with the report page.</div>"
"</div>"
"</div>"
"<script>"
"var rem=0;function el(i){return document.getElementById(i)}"
"function fmt(s){var m=Math.floor(s/60),x=s%60;return m+':'+(x<10?'0':'')+x}"
"function refresh(){fetch('/api/status').then(function(r){return r.json()})"
".then(function(j){el('ssid').textContent=j.ssid||'SniffCheck AP';"
"el('recs').textContent=j.records+' records / '+Math.round(j.bytes/1024)+' KB'"
"+(j.dropped?' / '+j.dropped+' dropped':'');"
"el('scans').textContent=j.scans;el('cli').textContent=j.clients;"
"el('sid').textContent=j.session_id;"
"el('fw').textContent=j.fw_version+' / schema '+j.schema_version;"
"rem=j.seconds_remaining;el('rem').textContent=fmt(rem)})"
".catch(function(){})}"
"refresh();setInterval(refresh,5000);"
"setInterval(function(){if(rem>0){rem--;el('rem').textContent=fmt(rem)}},1000);"
"function post(u){fetch(u,{method:'POST'}).then(refresh)}"
"function applyset(j){if(!j)return;el('mode').value=j.advisor_mode;"
"el('bri').value=j.brightness_pct;el('led').value=j.led_enabled?'1':'0';"
"el('tmo').value=j.download_timeout_min}"
"function loadset(){fetch('/api/settings').then(function(r){return r.json()})"
".then(applyset).catch(function(){})}"
"function sset(u,b){fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify(b)}).then(function(r){return r.json()}).then(applyset)"
".catch(function(){})}"
"loadset();"
"el('thm').value=curth;"

"function loadhot(){var a=['s-wifi','s-ble','s-clusters','s-channel'];"
"try{var v=JSON.parse(localStorage.getItem('sc-hotlist'));"
"if(v&&v.length)a=v}catch(e){}"
"var c=document.querySelectorAll('.hotck input'),i;"
"for(i=0;i<c.length;i++)c[i].checked=a.indexOf(c[i].value)>=0}"
"function savehot(){var c=document.querySelectorAll('.hotck input'),o=[],i;"
"for(i=0;i<c.length;i++)if(c[i].checked)o.push(c[i].value);"
"try{localStorage.setItem('sc-hotlist',JSON.stringify(o))}catch(e){}}"
"loadhot();"
"function applypup(j){if(!j)return;el('pname').textContent=j.name;"
"el('pmood').textContent=j.mood;el('plvl').textContent='Level '+j.level;"
"el('pxp').textContent=j.xp+' / '+j.xp_next+' xp';"
"el('pbarf').style.width=(j.xp_next?Math.min(100,Math.round(j.xp/j.xp_next*100)):0)+'%';"
"el('pscan').textContent=j.lifetime_scans+' scans \\u00b7 +'+j.last_scan_xp+' last';"
"el('ppt').textContent=j.pets+' pets \\u00b7 '+j.treats+' treats'}"
"function loadpup(){fetch('/api/pup/status').then(function(r){return r.json()})"
".then(applypup).catch(function(){})}"
"function ppost(u){fetch(u,{method:'POST'}).then(function(r){return r.json()})"
".then(applypup).catch(function(){})}"
"function prename(){var n=prompt('Name your pup:',el('pname').textContent);"
"if(n===null)return;fetch('/api/pup/name',{method:'POST',"
"headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})})"
".then(function(r){return r.json()}).then(applypup).catch(function(){})}"
"function armpup(b){if(b.getAttribute('data-armed')){clearTimeout(tm['pr']);"
"disarm(b);ppost('/api/pup/reset');return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again to reset';tm['pr']=setTimeout(function(){disarm(b)},3000)}"
"loadpup();"
"var tm={};"
"function disarm(b){b.removeAttribute('data-armed');"
"var l=b.getAttribute('data-l');if(l)b.textContent=l}"
"function arm(b,u){if(b.getAttribute('data-armed')){clearTimeout(tm[u]);"
"disarm(b);post(u);return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again to confirm';"
"tm[u]=setTimeout(function(){disarm(b)},3000)}"
"function armscan(b){if(b.getAttribute('data-armed')){disarm(b);"
"b.textContent='Scan starting. Check SniffCheck.';b.disabled=true;"
"fetch('/api/scan/start',{method:'POST'}).catch(function(){});return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again \\u2014 page will disconnect';"
"setTimeout(function(){disarm(b)},3000)}"
"function nav(v){['home','pup','byos','settings'].forEach(function(n){"
"el('v-'+n).classList.toggle('act',n===v);"
"el('nv-'+n).classList.toggle('act',n===v)})}"

"function walkhtml(w){var r=function(k,v){return '<div class=wr><span>'+k+"
"'</span><b>'+v+'</b></div>'};var mm=Math.floor(w.duration_sec/60),"
"ss=w.duration_sec%60;return '<h3>'+w.pup_name+'\\u2019s walk</h3>'+"
"r('time',mm+'m '+(ss<10?'0':'')+ss+'s')+"
"r('Wi-Fi',w.wifi_unique_bssid+' APs / '+w.wifi_unique_ssid+' networks')+"
"r('BLE',w.ble_unique_devices+' devices')+"
"(w.threat_events?r('caution',w.threat_events+' signals'):'')+"
"r('XP','+'+w.xp_awarded)+r('mood',w.mood)}"
"function applywalk(j){if(!j||!j.walk_id){return}"
"var h=walkhtml(j),cl='wc'+(j.threat_events>0?' alert':'');"
"var c=el('wcard2');if(c){c.innerHTML=h;c.className=cl;c.style.display='block'}}"
"function loadwalk(){fetch('/api/pup/walk/last').then(function(r){return r.json()})"
".then(applywalk).catch(function(){})}"
"loadwalk();"
"function armwalk(b){if(b.getAttribute('data-armed')){disarm(b);"
"b.textContent='Walk starting. Check SniffCheck.';b.disabled=true;"
"fetch('/api/pup/walk/start',{method:'POST'}).catch(function(){});return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again \\u2014 AP will close';"
"setTimeout(function(){disarm(b)},3000)}"
"var byosLines=[],byfiles=[],byurl='';"
"el('byfile').addEventListener('change',function(){byfiles=this.files?[].slice.call(this.files):[];"
"byosLines=[];el('bysc').disabled=true;el('bydl').style.display='none';"
"el('bystat').textContent='Ready to carve.';"
"if(!byfiles.length){el('byname').textContent='No file selected.'}"
"else if(byfiles.length==1){el('byname').textContent=byfiles[0].name+' ('+Math.round(byfiles[0].size/1024)+' KB)'}"
"else{var kb=0;for(var i=0;i<byfiles.length;i++)kb+=byfiles[i].size;"
"el('byname').textContent=byfiles.length+' files ('+Math.round(kb/1024)+' KB) — one source each'}});"
"function bypick(){el('byfile').click()}"

"function bysrcname(fn){var b=String(fn||'').replace(/\\.[^.]*$/,'');return bysan(b,16)||'src'}"
"function bynorm(m){var h=String(m==null?'':m).replace(/[^0-9A-Fa-f]/g,'').toUpperCase();"
"return h.length==12?h.match(/../g).join(':'):''}"
"function bysan(v,n){return String(v==null?'':v).replace(/[\\t\\r\\n]+/g,' ').trim().slice(0,n)}"

"function byhasmac(o){var ks=Object.keys(o);for(var i=0;i<ks.length;i++){var lp=ks[i].toLowerCase().split('.').pop();"
"if((lp=='mac'||lp=='bssid'||lp=='macaddr'||lp=='addr'||lp=='address')&&bynorm(o[ks[i]]))return true}return false}"

"function byfield(o,names,d){if(!o||typeof o!='object'||d>4)return undefined;var ks=Object.keys(o);"
"for(var n=0;n<names.length;n++){for(var i=0;i<ks.length;i++){var kl=ks[i].toLowerCase();"
"if(kl==names[n]||kl.split('.').pop()==names[n]){var v=o[ks[i]];if(v!=null&&v!==''&&typeof v!='object')return v}}}"
"for(var i=0;i<ks.length;i++){var v=o[ks[i]];if(v&&typeof v=='object'&&!Array.isArray(v)){var r=byfield(v,names,(d||0)+1);if(r!==undefined)return r}}return undefined}"

"function byrec(o,dsrc){var mac=bynorm(byfield(o,['mac','bssid','macaddr','addr','address'],0));if(!mac)return null;"
"var typ=String(byfield(o,['type','phyname','phy','technology'],0)||'').toLowerCase();"
"var ssid=byfield(o,['ssid','essid'],0),name=byfield(o,['name','local_name','devname','commonname'],0);"
"var ch=parseInt(byfield(o,['channel','chan'],0),10),rssi=parseInt(byfield(o,['rssi','signal','signal_dbm','last_signal','bestlevel'],0),10);"
"var auth=byfield(o,['authtype','authmode','auth','capabilities','encryption','security','crypt'],0);"
"var w=/wifi|wlan|802\\.11|ieee/.test(typ),b=/ble|bt|bluetooth/.test(typ);"
"var isw=w||(!b&&(ssid!=null||auth!=null)),isb=b||(!w&&!isw&&name!=null);"

"var src=bysan(byfield(o,['source_id','source','node','node_id','sensor','observer'],0),16)||dsrc||'local';"
"var lat=bysan(byfield(o,['lat','latitude','trilat','currentlatitude'],0),16);"
"var lon=bysan(byfield(o,['lon','lng','longitude','trilong','currentlongitude'],0),16);"
"var ts=bysan(byfield(o,['time','timestamp','lasttime','firsttime','firstseen','lastseen'],0),16);"
"if(isw)return ['W',mac,bysan(ssid!=null?ssid:name,32),isNaN(ch)?'':ch,isNaN(rssi)?'':rssi,bysan(auth,23),src,lat,lon,ts].join('\\t');"
"if(isb)return ['B',mac,bysan(name,32),isNaN(rssi)?'':rssi,src,lat,lon,ts].join('\\t');"
"return ['M',mac,src,lat,lon,ts].join('\\t')}"

"function bywalk(node,out){if(Array.isArray(node)){for(var i=0;i<node.length;i++)bywalk(node[i],out);return}"
"if(node&&typeof node=='object'){if(byhasmac(node)){out.push(node);return}var ks=Object.keys(node);for(var i=0;i<ks.length;i++)bywalk(node[ks[i]],out)}}"

"function bysplit(l){var o=[],c='',q=false;for(var i=0;i<l.length;i++){var ch=l[i];"
"if(q){if(ch=='\\\"'){if(l[i+1]=='\\\"'){c+='\\\"';i++}else q=false}else c+=ch}"
"else if(ch=='\\\"')q=true;else if(ch==','){o.push(c);c=''}else c+=ch}o.push(c);return o}"
"function bycsv(s,dsrc){var ls=s.split(/\\r?\\n/),h=-1,cols=[];"
"for(var i=0;i<ls.length;i++){var fs=bysplit(ls[i]).map(function(x){return x.trim().toLowerCase()});"
"if(fs.indexOf('mac')>=0||fs.indexOf('bssid')>=0){h=i;cols=fs;break}}"
"if(h<0)return [];var recs=[];"
"for(var i=h+1;i<ls.length;i++){if(!ls[i].trim())continue;var fs=bysplit(ls[i]),o={};"
"for(var j=0;j<cols.length;j++)if(j<fs.length)o[cols[j]]=fs[j];var r=byrec(o,dsrc);if(r)recs.push(r)}return recs}"

"function bysrcof(p){return p[0]=='W'?p[6]:p[0]=='B'?p[4]:p[2]}"

"function byone(s,dsrc,seen,out,cnt){var objs=[],recs=[];"
"try{objs.push(JSON.parse(s))}catch(e){var ls=s.split(/\\r?\\n/);for(var i=0;i<ls.length;i++){var t=ls[i].trim();"
"if(t&&(t[0]=='{'||t[0]=='[')){try{objs.push(JSON.parse(t))}catch(e2){}}}}"
"if(objs.length){var found=[];for(var i=0;i<objs.length;i++)bywalk(objs[i],found);"
"for(var i=0;i<found.length;i++){var r=byrec(found[i],dsrc);if(r)recs.push(r)}}"
"if(!recs.length)recs=bycsv(s,dsrc);"
"for(var i=0;i<recs.length;i++){var p=recs[i].split('\\t'),mac=p[1];if(!mac)continue;"
"var k=mac+'|'+(bysrcof(p)||dsrc);if(seen[k])continue;seen[k]=1;out.push(recs[i]);"
"if(p[0]=='W')cnt[0]++;else if(p[0]=='B')cnt[1]++;else cnt[2]++}"

"var re=/(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}|\\b[0-9A-Fa-f]{12}\\b/g,m;"
"while((m=re.exec(s))){var x=bynorm(m[0]);if(!x)continue;var k=x+'|'+dsrc;if(!seen[k]){seen[k]=1;out.push(['M',x,dsrc,'','',''].join('\\t'));cnt[2]++}}}"

"function byparse(){if(!byfiles.length){el('bystat').textContent='Choose a scan file first.';return}"
"el('bystat').textContent='Carving on this device...';"
"var seen={},out=[],cnt=[0,0,0],fi=0,multi=byfiles.length>1;"
"function done(){byosLines=out;var n=out.length;"
"el('bystat').textContent=n?(n+' sightings: '+cnt[0]+' Wi-Fi, '+cnt[1]+' BLE, '+cnt[2]+' MAC-only'+(multi?(' across '+byfiles.length+' sources'):'')+'.'):'No devices found.';"
"el('bysc').disabled=!n;"
"if(byurl)URL.revokeObjectURL(byurl);byurl=URL.createObjectURL(new Blob([out.join('\\n')],{type:'text/plain'}));"
"el('bydl').href=byurl;el('bydl').style.display=n?'block':'none'}"
"function next(){if(fi>=byfiles.length){done();return}var f=byfiles[fi++];"
"var dsrc=multi?bysrcname(f.name):'local';var fr=new FileReader();"
"fr.onload=function(){byone(String(fr.result||''),dsrc,seen,out,cnt);next()};"
"fr.onerror=function(){next()};fr.readAsText(f)}"
"next()}"
"function bysniff(){if(!byosLines.length)return;el('dig').style.display='flex';"
"fetch('/api/byos/sniffcheck',{method:'POST',headers:{'Content-Type':'text/plain'},body:byosLines.join('\\n')})"
".then(function(r){return r.json().then(function(j){if(!r.ok)throw new Error(j.error||'BYOS failed');return j})})"
".then(function(j){location.href=j.report||'/report.html'})"
".catch(function(e){el('dig').style.display='none';el('bystat').textContent=e.message||'BYOS failed'})}"
"</script><div id=dig>SniffCheck is digging<span>Decoding and scoring uploaded MACs on-device...</span></div></body></html>";

static esp_err_t root_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, DASH_HTML, sizeof(DASH_HTML) - 1);
}

static esp_err_t logo_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_webap_logo_png_end - _binary_webap_logo_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_webap_logo_png_start, len);
}

static esp_err_t favicon_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_webap_favicon_png_end - _binary_webap_favicon_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_webap_favicon_png_start, len);
}

static esp_err_t pup_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_webap_pup_png_end - _binary_webap_pup_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_webap_pup_png_start, len);
}

static esp_err_t status_get(httpd_req_t *req)
{
    capture_ring_stats_t st;
    capture_ring_get_stats(&st);

    char json[360];
    snprintf(json, sizeof(json),
        "{\"records\":%u,\"bytes\":%u,\"dropped\":%u,\"scans\":%u,"
        "\"session_id\":\"%s\",\"fw_version\":\"%s\",\"schema_version\":\"%s\","
        "\"seconds_remaining\":%u,\"clients\":%u,\"timeout_min\":%u,"
        "\"ssid\":\"%s\"}",
        (unsigned)st.records_current, (unsigned)st.bytes_used,
        (unsigned)st.records_dropped, (unsigned)capture_writer_last_scan(),
        capture_writer_session_id(), capture_writer_fw_version(),
        capture_writer_schema_version(),
        (unsigned)download_mode_get_seconds_remaining(),
        (unsigned)download_mode_get_client_count(),
        (unsigned)download_mode_get_timeout_minutes(),
        download_mode_get_ssid());
    return send_json(req, json);
}

static esp_err_t captures_get(httpd_req_t *req)
{
    capture_ring_stats_t st;
    capture_ring_get_stats(&st);

    char json[320];
    snprintf(json, sizeof(json),
        "[{\"id\":\"live\",\"name\":\"live.jsonl\",\"kind\":\"volatile\","
        "\"records\":%u,\"bytes\":%u,\"dropped\":%u,"
        "\"endpoints\":[\"/api/captures/live.jsonl\",\"/api/captures/live.json\"]}]",
        (unsigned)st.records_current,
        (unsigned)st.bytes_used,
        (unsigned)st.records_dropped);
    return send_json(req, json);
}

static esp_err_t live_jsonl_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/x-ndjson");
    char disp[80];
    snprintf(disp, sizeof(disp),
             "attachment; filename=\"sniffcheck-%s.jsonl\"",
             capture_writer_session_id());
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    size_t emitted = 0;
    esp_err_t err = stream_ring(req, false, &emitted);
    if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }
    if (err == ESP_OK) httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "live.jsonl: %u records streamed", (unsigned)emitted);
    return err;
}

static esp_err_t live_json_get(httpd_req_t *req)
{

    char *buf = heap_caps_malloc(STREAM_LINE_MAX + 2, MALLOC_CAP_SPIRAM);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"live.json\"");

    capture_ring_reader_t r;
    capture_ring_reader_open(&r);

    httpd_resp_send_chunk(req, "[", 1);

    size_t emitted = 0;
    esp_err_t err = ESP_OK;
    for (;;) {

        size_t len = capture_ring_reader_next(&r, buf + 2, STREAM_LINE_MAX);
        if (len == 0) break;
        char *out;
        size_t out_len;
        if (emitted == 0) {
            buf[1] = '\n';
            out = buf + 1; out_len = len + 1;
        } else {
            buf[0] = ','; buf[1] = '\n';
            out = buf; out_len = len + 2;
        }
        if (httpd_resp_send_chunk(req, out, out_len) != ESP_OK) {
            err = ESP_FAIL;
            break;
        }
        if (++emitted % 32 == 0) vTaskDelay(1);
    }

    heap_caps_free(buf);
    if (err == ESP_OK) {
        httpd_resp_send_chunk(req, "\n]\n", 3);
        httpd_resp_send_chunk(req, NULL, 0);
    }
    ESP_LOGI(TAG, "live.json: %u records streamed", (unsigned)emitted);
    return err;
}

static esp_err_t report_get(httpd_req_t *req)
{
    if (!s_view_head) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "viewer asset missing");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html");

    char query[16], dl[4];
    char disp[80];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "dl", dl, sizeof(dl)) == ESP_OK &&
        dl[0] == '1') {
        snprintf(disp, sizeof(disp),
                 "attachment; filename=\"sniffcheck-%s.html\"",
                 capture_writer_session_id());
        httpd_resp_set_hdr(req, "Content-Disposition", disp);
    }

    if (httpd_resp_send_chunk(req, s_view_head, s_view_head_len) != ESP_OK)
        return ESP_FAIL;

    size_t emitted = 0;
    esp_err_t err = stream_ring(req, true, &emitted);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NO_MEM)
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    if (httpd_resp_send_chunk(req, s_view_tail, s_view_tail_len) != ESP_OK)
        return ESP_FAIL;
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "report.html: %u records spliced", (unsigned)emitted);
    return ESP_OK;
}

static esp_err_t viewer_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, _binary_capture_viewer_html_start,
                           strlen(_binary_capture_viewer_html_start));
}

static esp_err_t clear_post(httpd_req_t *req)
{
    capture_ring_clear_volatile();
    ESP_LOGI(TAG, "ring cleared by client");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t extend_post(httpd_req_t *req)
{
    uint32_t rem = download_mode_extend_seconds(15 * 60);
    char json[64];
    snprintf(json, sizeof(json),
             "{\"ok\":%s,\"seconds_remaining\":%u}",
             rem ? "true" : "false", (unsigned)rem);
    ESP_LOGI(TAG, "extend requested: %u s remaining", (unsigned)rem);
    return send_json(req, json);
}

static esp_err_t disable_post(httpd_req_t *req)
{

    esp_err_t rc = send_json(req, "{\"ok\":true}");
    ESP_LOGI(TAG, "disable requested by client");
    download_mode_request_disable(CAP_END_USER_DISABLE);
    return rc;
}

static int read_body(httpd_req_t *req, char *buf, size_t buflen)
{
    size_t total = req->content_len;
    if (total > buflen - 1) total = buflen - 1;
    size_t got = 0;
    while (got < total) {
        int r = httpd_req_recv(req, buf + got, total - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    buf[got] = '\0';
    return (int)got;
}

static esp_err_t send_bad(httpd_req_t *req, const char *err)
{
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    char j[128];
    snprintf(j, sizeof(j), "{\"ok\":false,\"error\":\"%s\"}", err);
    return httpd_resp_sendstr(req, j);
}

static esp_err_t send_settings(httpd_req_t *req)
{
    char buf[192];
    app_settings_get_json(buf, sizeof(buf));
    return send_json(req, buf);
}

static bool json_int(const char *body, const char *key, int *out)
{
    const char *p = strstr(body, key);
    if (!p) return false;
    p = strchr(p + strlen(key), ':');
    if (!p) return false;
    *out = atoi(p + 1);
    return true;
}

static esp_err_t settings_get(httpd_req_t *req)
{
    return send_settings(req);
}

static esp_err_t settings_mode_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    bool adv;
    if (strstr(body, "\"adv\""))       adv = true;
    else if (strstr(body, "\"lite\"")) adv = false;
    else return send_bad(req, "mode must be lite or adv");
    app_settings_set_mode(adv);
    return send_settings(req);
}

static esp_err_t settings_brightness_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    int pct;
    if (!json_int(body, "\"pct\"", &pct)) return send_bad(req, "pct required");
    if (!app_settings_set_brightness_pct(pct))
        return send_bad(req, "pct must be 25/50/75/100");
    return send_settings(req);
}

static esp_err_t settings_led_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    bool en;
    if (strstr(body, "true"))       en = true;
    else if (strstr(body, "false")) en = false;
    else return send_bad(req, "enabled must be true or false");
    app_settings_set_led(en);
    return send_settings(req);
}

static esp_err_t settings_timeout_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    int m;
    if (!json_int(body, "\"minutes\"", &m)) return send_bad(req, "minutes required");
    if (m != 15 && m != 30 && m != 60)
        return send_bad(req, "minutes must be 15/30/60");
    download_mode_set_timeout_minutes((uint8_t)m);
    return send_settings(req);
}

static esp_err_t scan_start_post(httpd_req_t *req)
{

    esp_err_t rc = send_json(req,
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"scan_start\"}");
    ESP_LOGI(TAG, "scan-start requested by client");
    app_request_scan_after_download();
    return rc;
}

static esp_err_t send_pup(httpd_req_t *req)
{
    vp_status_t st;
    virtual_pup_get(&st);
    char json[256];
    snprintf(json, sizeof(json),
        "{\"name\":\"%s\",\"level\":%u,\"xp\":%llu,\"xp_next\":%llu,"
        "\"mood\":\"%s\",\"lifetime_scans\":%u,\"last_scan_xp\":%u,"
        "\"pets\":%u,\"treats\":%u}",
        virtual_pup_name(), (unsigned)st.level,
        (unsigned long long)st.xp_into_level, (unsigned long long)st.xp_for_level,
        virtual_pup_mood_label(), (unsigned)st.lifetime_scans,
        (unsigned)st.last_scan_xp, (unsigned)st.pets, (unsigned)st.treats);
    return send_json(req, json);
}

static esp_err_t pup_status_get(httpd_req_t *req){ return send_pup(req); }

static esp_err_t pup_pet_post(httpd_req_t *req)
{
    virtual_pup_pet();
    return send_pup(req);
}

static esp_err_t pup_treat_post(httpd_req_t *req)
{
    virtual_pup_treat();
    return send_pup(req);
}

static esp_err_t pup_name_post(httpd_req_t *req)
{
    char body[96];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");

    char *p = strstr(body, "\"name\"");
    if (p) p = strchr(p + 6, ':');
    if (p) p = strchr(p, '"');
    if (!p) return send_bad(req, "name required");
    char name[VP_NAME_MAX]; size_t j = 0;
    for (p++; *p && *p != '"' && j < sizeof(name) - 1; p++) name[j++] = *p;
    name[j] = '\0';
    virtual_pup_set_name(name);
    return send_pup(req);
}

static esp_err_t pup_reset_post(httpd_req_t *req)
{
    virtual_pup_reset();
    return send_pup(req);
}

static esp_err_t pup_walk_last_get(httpd_req_t *req)
{
    pup_walk_summary_t w;
    virtual_pup_walk_get_last(&w);

    char json[512];
    snprintf(json, sizeof(json),
        "{\"walk_id\":%u,\"pup_name\":\"%s\",\"duration_sec\":%u,"
        "\"wifi_sweeps\":%u,\"ble_windows\":%u,\"wifi_unique_bssid\":%u,"
        "\"wifi_unique_ssid\":%u,\"ble_unique_devices\":%u,\"threat_events\":%u,"
        "\"safe_networks\":%u,\"interesting_sniffs\":%u,\"xp_awarded\":%u,"
        "\"mood\":\"%s\"}",
        (unsigned)w.walk_id, virtual_pup_name(), (unsigned)w.duration_sec,
        (unsigned)w.wifi_sweeps, (unsigned)w.ble_windows,
        (unsigned)w.wifi_unique_bssid, (unsigned)w.wifi_unique_ssid,
        (unsigned)w.ble_unique_devices, (unsigned)w.threat_events,
        (unsigned)w.safe_networks, (unsigned)w.interesting_sniffs,
        (unsigned)w.xp_awarded, w.mood);
    return send_json(req, json);
}

static esp_err_t pup_walk_start_post(httpd_req_t *req)
{
    esp_err_t rc = send_json(req,
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"walk_start\","
        "\"message\":\"Sniff Walk starting. This AP will close.\"}");
    ESP_LOGI(TAG, "walk-start requested by client");
    app_request_walk_after_download();
    return rc;
}

static esp_err_t sta_get(httpd_req_t *req)
{
    const size_t cap = 16384;
    char *buf = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }
    uint16_t n = sta_tracker_entry_count();
    size_t o = 0;
    o += snprintf(buf + o, cap - o,
                  "{\"count\":%u,\"cameras\":%u,\"stations\":[",
                  (unsigned)n, (unsigned)sta_tracker_camera_count());
    for (uint16_t i = 0; i < n; i++) {
        const sta_entry_t *e = sta_tracker_at(i);
        if (!e) continue;
        if (o > cap - 400) break;
        o += snprintf(buf + o, cap - o,
            "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"vendor\":\"%s\","
            "\"class\":%u,\"frames\":%u,\"up\":%u,\"dn\":%u,\"randomized\":%s,"
            "\"camera\":%s,\"rssi_last\":%d,\"rssi_best\":%d,\"channel\":%u,"
            "\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"dur_ms\":%lu}",
            i ? "," : "",
            e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
            e->vendor ? e->vendor : "", (unsigned)e->device_class,
            (unsigned)e->frames, (unsigned)e->frames_uplink,
            (unsigned)e->frames_downlink, e->randomized ? "true" : "false",
            e->is_camera ? "true" : "false", (int)e->rssi_last, (int)e->rssi_best,
            (unsigned)e->channel,
            e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5],
            (unsigned long)(e->last_seen_ms - e->first_seen_ms));
    }
    o += snprintf(buf + o, cap - o, "]}");
    httpd_resp_set_type(req, "application/json");
    esp_err_t rc = httpd_resp_send(req, buf, o);
    heap_caps_free(buf);
    return rc;
}

static esp_err_t scan_channels_get(httpd_req_t *req)
{
    char json[1536];
    app_scan_channels_json(json, sizeof(json));
    return send_json(req, json);
}

static esp_err_t csi_get(httpd_req_t *req)
{
    const wifi_csi_result_t *r = wifi_csi_probe_last();
    char json[256];
    snprintf(json, sizeof(json),
        "{\"supported\":%s,\"ran\":%s,\"channel\":%u,\"window_ms\":%u,"
        "\"cb_count\":%u,\"len_min\":%u,\"len_max\":%u,\"len_last\":%u,"
        "\"fwi_count\":%u,\"rssi_last\":%d}",
        r->supported ? "true" : "false", r->ran ? "true" : "false",
        (unsigned)r->channel, (unsigned)r->window_ms, (unsigned)r->cb_count,
        (unsigned)r->len_min, (unsigned)r->len_max, (unsigned)r->len_last,
        (unsigned)r->fwi_count, (int)r->rssi_last);
    return send_json(req, json);
}

static void read_chan_secs(httpd_req_t *req, int *ch, int *sec)
{
    char body[96];
    *ch = 6; *sec = 5;
    if (read_body(req, body, sizeof(body)) > 0) {
        json_int(body, "\"channel\"", ch);
        json_int(body, "\"seconds\"", sec);
    }
}

static esp_err_t sta_capture_post(httpd_req_t *req)
{
    int ch, sec;
    read_chan_secs(req, &ch, &sec);
    esp_err_t rc = send_json(req,
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"sta_capture\"}");
    ESP_LOGI(TAG, "sta-capture requested: ch=%d sec=%d", ch, sec);
    app_request_sta_capture_after_download((uint8_t)ch, (uint16_t)sec);
    return rc;
}

static esp_err_t csi_run_post(httpd_req_t *req)
{
    int ch, sec;
    read_chan_secs(req, &ch, &sec);
    esp_err_t rc = send_json(req,
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"csi_run\"}");
    ESP_LOGI(TAG, "csi-run requested: ch=%d sec=%d", ch, sec);
    app_request_csi_after_download((uint8_t)ch, (uint16_t)sec);
    return rc;
}

static const char *pcap_status_str(pcap_status_t s)
{
    switch (s) {
        case PCAP_RUNNING:      return "running";
        case PCAP_READY:        return "ready";
        case PCAP_PARTIAL:      return "partial";
        case PCAP_FAILED:       return "failed";
        default:                return "idle";
    }
}

static uint8_t parse_channels(const char *body, uint8_t *out, uint8_t max)
{
    const char *p = strstr(body, "\"channels\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;
    p++;
    uint8_t n = 0;
    while (*p && *p != ']' && n < max) {
        while (*p == ' ' || *p == ',') p++;
        if (*p == ']' || !*p) break;
        if (*p >= '0' && *p <= '9') {
            int v = atoi(p);
            if (v >= 1 && v <= 177) out[n++] = (uint8_t)v;
            while (*p >= '0' && *p <= '9') p++;
        } else {
            p++;
        }
    }
    return n;
}

static esp_err_t pcap_run_post(httpd_req_t *req)
{
    char body[512];
    uint8_t chans[PCAP_MAX_CHANNELS];
    uint8_t n = 0;
    if (read_body(req, body, sizeof(body)) > 0)
        n = parse_channels(body, chans, PCAP_MAX_CHANNELS);
    if (n == 0)
        return send_bad(req, "no valid channels");

    esp_err_t rc = send_json(req,
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"pcap_run\"}");
    ESP_LOGI(TAG, "pcap-run requested: %u channels, 10s each", (unsigned)n);
    app_request_pcap_after_download(chans, n);
    return rc;
}

static esp_err_t pcap_status_get(httpd_req_t *req)
{
    const pcap_meta_t *m = pcap_capture_meta();
    char json[640];
    int o = snprintf(json, sizeof(json),
        "{\"ran\":%s,\"status\":\"%s\",\"seconds_per_channel\":%u,"
        "\"duration_s\":%lu,\"packets\":%lu,\"dropped\":%lu,\"truncated\":%lu,"
        "\"bytes\":%lu,\"scan_id\":%lu,\"download\":\"/api/pcap/latest\","
        "\"channels\":[",
        m->ran ? "true" : "false", pcap_status_str(m->status),
        (unsigned)m->seconds_per_channel, (unsigned long)m->duration_s,
        (unsigned long)m->packets, (unsigned long)m->dropped,
        (unsigned long)m->truncated, (unsigned long)m->bytes,
        (unsigned long)m->scan_id);
    for (uint8_t i = 0; i < m->channel_count && o < (int)sizeof(json) - 8; i++)
        o += snprintf(json + o, sizeof(json) - o, "%s%u",
                      i ? "," : "", (unsigned)m->channels[i]);
    o += snprintf(json + o, sizeof(json) - o, "]}");
    return send_json(req, json);
}

static esp_err_t pcap_latest_get(httpd_req_t *req)
{
    size_t len = 0;
    const uint8_t *data = pcap_capture_data(&len);
    if (!data || len == 0) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req,
            "{\"ok\":false,\"error\":\"no capture\"}");
    }
    const pcap_meta_t *m = pcap_capture_meta();
    char disp[80];
    snprintf(disp, sizeof(disp),
             "attachment; filename=\"sniffcheck-packets-scan%04lu.pcap\"",
             (unsigned long)m->scan_id);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    size_t off = 0;
    while (off < len) {
        size_t seg = len - off;
        if (seg > 4096) seg = 4096;
        if (httpd_resp_send_chunk(req, (const char *)data + off, seg) != ESP_OK)
            return ESP_FAIL;
        off += seg;
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

#define BYOS_MAX_RECS          4096
#define BYOS_UPLOAD_MAX_BYTES  (192 * 1024)
#define BYOS_TEXT_MAX          32
#define BYOS_AUTH_MAX          23
#define BYOS_SRCID_MAX         16
#define BYOS_LINE_MAX          256 

typedef struct {
    uint8_t  mac[6];
    char     type;
    uint8_t  channel;
    char     text[BYOS_TEXT_MAX + 1];
    char     auth[BYOS_AUTH_MAX + 1];

    capture_byos_sight_t sight[CAPTURE_BYOS_MAX_SIGHT];
    uint8_t  n_sight;
    uint8_t  sight_overflow;
} byos_rec_t;

typedef struct {
    byos_rec_t rec[BYOS_MAX_RECS];
    uint16_t   count;
    uint32_t   duplicates;
    uint32_t   invalid;
    uint32_t   overflow;
} byos_import_t;

static int byos_hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool byos_parse_mac_line(const char *line, uint8_t out[6])
{
    char hex[12];
    uint8_t n = 0;
    for (const char *p = line; *p; p++) {
        if (byos_hex((unsigned char)*p) >= 0) {
            if (n >= sizeof(hex)) return false;
            hex[n++] = *p;
        }
    }
    if (n != 12) return false;
    for (uint8_t i = 0; i < 6; i++) {
        int hi = byos_hex((unsigned char)hex[i * 2]);
        int lo = byos_hex((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void byos_setstr(char *dst, size_t cap, const char *src)
{
    size_t i = 0;
    for (; src && src[i] && i < cap - 1; i++) dst[i] = src[i];
    dst[i] = '\0';
}

static int byos_clamp(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

static bool byos_parse_deg_e7(const char *s, int32_t *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    double deg = strtod(s, &end);
    if (end == s || deg < -180.0 || deg > 180.0) return false;
    *out = (int32_t)llround(deg * 1e7);
    return true;
}

static bool byos_parse_epoch(const char *s, uint32_t *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s) return false;
    *out = (uint32_t)v;
    return true;
}

static void byos_add_record(byos_import_t *im, char *line)
{
    while (*line && isspace((unsigned char)*line)) line++;
    if (!*line) return;

    char *f[10] = {0};
    int nf = 0;
    f[nf++] = line;
    for (char *p = line; *p && nf < 10; p++) {
        if (*p == '\t') { *p = '\0'; f[nf++] = p + 1; }
    }

    byos_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    capture_byos_sight_t sg;
    memset(&sg, 0, sizeof(sg));
    strcpy(sg.source_id, "local");

    bool structured = (f[0][0] && f[0][1] == '\0' &&
                       (f[0][0] == 'W' || f[0][0] == 'B' || f[0][0] == 'M'));
    const char *macstr;
    if (structured) {
        rec.type = f[0][0];
        macstr = (nf > 1) ? f[1] : "";
    } else {
        rec.type = 'M';
        macstr = line;
    }
    if (!byos_parse_mac_line(macstr, rec.mac)) { im->invalid++; return; }

    int tail = 0;
    if (rec.type == 'W') {
        if (nf > 2) byos_setstr(rec.text, sizeof(rec.text), f[2]);
        if (nf > 3) rec.channel = (uint8_t)byos_clamp(atoi(f[3]), 0, 255);
        if (nf > 4) sg.rssi = (int8_t)byos_clamp(atoi(f[4]), -128, 127);
        if (nf > 5) byos_setstr(rec.auth, sizeof(rec.auth), f[5]);
        tail = 6;
    } else if (rec.type == 'B') {
        if (nf > 2) byos_setstr(rec.text, sizeof(rec.text), f[2]);
        if (nf > 3) sg.rssi = (int8_t)byos_clamp(atoi(f[3]), -128, 127);
        tail = 4;
    } else {
        tail = 2;
    }
    if (nf > tail && f[tail][0]) byos_setstr(sg.source_id, sizeof(sg.source_id), f[tail]);

    if (nf > tail + 2) {
        bool have_lat = byos_parse_deg_e7(f[tail + 1], &sg.lat_e7);
        bool have_lon = byos_parse_deg_e7(f[tail + 2], &sg.lon_e7);
        sg.has_pos = have_lat && have_lon;
    }
    if (nf > tail + 3) sg.has_ts = byos_parse_epoch(f[tail + 3], &sg.ts_s);

    for (uint16_t i = 0; i < im->count; i++) {
        byos_rec_t *ex = &im->rec[i];
        if (memcmp(ex->mac, rec.mac, 6) != 0) continue;

        if (!ex->text[0] && rec.text[0]) byos_setstr(ex->text, sizeof(ex->text), rec.text);
        if (!ex->auth[0] && rec.auth[0]) byos_setstr(ex->auth, sizeof(ex->auth), rec.auth);
        if (!ex->channel && rec.channel) ex->channel = rec.channel;
        if (ex->type == 'M' && rec.type != 'M') ex->type = rec.type;
        for (uint8_t s = 0; s < ex->n_sight; s++) {
            if (strcmp(ex->sight[s].source_id, sg.source_id) == 0) {
                if (sg.rssi > ex->sight[s].rssi) ex->sight[s].rssi = sg.rssi;
                if (sg.has_pos && !ex->sight[s].has_pos) {
                    ex->sight[s].lat_e7 = sg.lat_e7; ex->sight[s].lon_e7 = sg.lon_e7;
                    ex->sight[s].has_pos = true;
                }
                if (sg.has_ts && !ex->sight[s].has_ts) {
                    ex->sight[s].ts_s = sg.ts_s; ex->sight[s].has_ts = true;
                }
                im->duplicates++;
                return;
            }
        }
        if (ex->n_sight < CAPTURE_BYOS_MAX_SIGHT) ex->sight[ex->n_sight++] = sg;
        else ex->sight_overflow++;
        return;
    }
    if (im->count >= BYOS_MAX_RECS) { im->overflow++; return; }
    rec.sight[0] = sg;
    rec.n_sight = 1;
    im->rec[im->count++] = rec;
}

static esp_err_t byos_sniffcheck_post(httpd_req_t *req)
{
    if (req->content_len == 0) return send_bad(req, "empty upload");
    if (req->content_len > BYOS_UPLOAD_MAX_BYTES) return send_bad(req, "scan too large");

    byos_import_t *im = heap_caps_calloc(1, sizeof(*im), MALLOC_CAP_SPIRAM);
    if (!im) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    char chunk[512];
    char line[BYOS_LINE_MAX];
    size_t got = 0;
    size_t li = 0;
    bool line_trunc = false;
    while (got < req->content_len) {
        size_t want = req->content_len - got;
        if (want > sizeof(chunk)) want = sizeof(chunk);
        int r = httpd_req_recv(req, chunk, want);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) {
            heap_caps_free(im);
            return ESP_FAIL;
        }
        got += (size_t)r;
        for (int i = 0; i < r; i++) {
            char c = chunk[i];
            if (c == '\n' || c == '\r') {
                if (li > 0 && !line_trunc) {
                    line[li] = '\0';
                    byos_add_record(im, line);
                } else if (line_trunc) {
                    im->invalid++;
                }
                li = 0;
                line_trunc = false;
            } else if (!line_trunc) {
                if (li < sizeof(line) - 1) line[li++] = c;
                else line_trunc = true;
            }
        }
    }
    if (li > 0 && !line_trunc) {
        line[li] = '\0';
        byos_add_record(im, line);
    } else if (line_trunc) {
        im->invalid++;
    }

    if (im->count == 0) {
        heap_caps_free(im);
        return send_bad(req, "no records found");
    }

    capture_ring_clear_volatile();
    capture_emit_header();
    capture_emit_codebook();
    uint32_t import_id = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t wifi_n = 0, ble_n = 0, mac_n = 0;
    for (uint16_t i = 0; i < im->count; i++) {
        const byos_rec_t *rc = &im->rec[i];
        uint16_t idx = (uint16_t)(i + 1);
        switch (rc->type) {
        case 'W':
            capture_emit_byos_wifi(rc->mac, 1, import_id, idx,
                                   rc->text, rc->channel, rc->auth,
                                   rc->sight, rc->n_sight);
            wifi_n++;
            break;
        case 'B':
            capture_emit_byos_ble(rc->mac, 1, import_id, idx,
                                  rc->text[0] ? rc->text : NULL,
                                  rc->sight, rc->n_sight);
            ble_n++;
            break;
        default:
            capture_emit_byos_mac(rc->mac, 1, import_id, idx,
                                  rc->sight, rc->n_sight);
            mac_n++;
            break;
        }
        if ((i & 31) == 31) vTaskDelay(1);
    }
    capture_emit_footer(CAP_END_IMPORT, wifi_n, ble_n, 0, 0, 0, 1);

    char json[256];
    snprintf(json, sizeof(json),
             "{\"ok\":true,\"records\":%u,\"wifi\":%u,\"ble\":%u,\"mac_only\":%u,"
             "\"duplicates\":%u,\"invalid\":%u,\"overflow\":%u,"
             "\"import_id\":%u,\"report\":\"/report.html\"}",
             (unsigned)im->count, (unsigned)wifi_n, (unsigned)ble_n, (unsigned)mac_n,
             (unsigned)im->duplicates, (unsigned)im->invalid, (unsigned)im->overflow,
             (unsigned)import_id);
    ESP_LOGI(TAG, "BYOS import decoded: recs=%u wifi=%u ble=%u mac=%u dup=%u invalid=%u overflow=%u",
             (unsigned)im->count, (unsigned)wifi_n, (unsigned)ble_n, (unsigned)mac_n,
             (unsigned)im->duplicates, (unsigned)im->invalid, (unsigned)im->overflow);
    heap_caps_free(im);
    return send_json(req, json);
}

static void register_handlers(void)
{
    static const httpd_uri_t uris[] = {
        { .uri = "/",                          .method = HTTP_GET,  .handler = root_get },
        { .uri = "/logo.png",                  .method = HTTP_GET,  .handler = logo_get },
        { .uri = "/favicon.ico",               .method = HTTP_GET,  .handler = favicon_get },
        { .uri = "/pup.png",                   .method = HTTP_GET,  .handler = pup_get },
        { .uri = "/generate_204",              .method = HTTP_GET,  .handler = root_get },
        { .uri = "/hotspot-detect.html",       .method = HTTP_GET,  .handler = root_get },
        { .uri = "/connecttest.txt",           .method = HTTP_GET,  .handler = root_get },
        { .uri = "/report.html",               .method = HTTP_GET,  .handler = report_get },
        { .uri = "/viewer",                    .method = HTTP_GET,  .handler = viewer_get },
        { .uri = "/api/status",                .method = HTTP_GET,  .handler = status_get },
        { .uri = "/api/captures",              .method = HTTP_GET,  .handler = captures_get },
        { .uri = "/api/captures/live.jsonl",   .method = HTTP_GET,  .handler = live_jsonl_get },
        { .uri = "/api/captures/live.json",    .method = HTTP_GET,  .handler = live_json_get },
        { .uri = "/api/captures/clear-volatile", .method = HTTP_POST, .handler = clear_post },
        { .uri = "/api/download/extend",       .method = HTTP_POST, .handler = extend_post },
        { .uri = "/api/download/disable",      .method = HTTP_POST, .handler = disable_post },
        { .uri = "/api/settings",              .method = HTTP_GET,  .handler = settings_get },
        { .uri = "/api/settings/mode",         .method = HTTP_POST, .handler = settings_mode_post },
        { .uri = "/api/settings/brightness",   .method = HTTP_POST, .handler = settings_brightness_post },
        { .uri = "/api/settings/led",          .method = HTTP_POST, .handler = settings_led_post },
        { .uri = "/api/settings/download-timeout", .method = HTTP_POST, .handler = settings_timeout_post },
        { .uri = "/api/scan/start",            .method = HTTP_POST, .handler = scan_start_post },
        { .uri = "/api/pup/status",            .method = HTTP_GET,  .handler = pup_status_get },
        { .uri = "/api/pup/pet",               .method = HTTP_POST, .handler = pup_pet_post },
        { .uri = "/api/pup/treat",             .method = HTTP_POST, .handler = pup_treat_post },
        { .uri = "/api/pup/name",              .method = HTTP_POST, .handler = pup_name_post },
        { .uri = "/api/pup/reset",             .method = HTTP_POST, .handler = pup_reset_post },
        { .uri = "/api/pup/walk/last",         .method = HTTP_GET,  .handler = pup_walk_last_get },
        { .uri = "/api/pup/walk/start",        .method = HTTP_POST, .handler = pup_walk_start_post },
        { .uri = "/api/sta",                   .method = HTTP_GET,  .handler = sta_get },
        { .uri = "/api/sta/capture",           .method = HTTP_POST, .handler = sta_capture_post },
        { .uri = "/api/csi",                   .method = HTTP_GET,  .handler = csi_get },
        { .uri = "/api/csi/run",               .method = HTTP_POST, .handler = csi_run_post },
        { .uri = "/api/byos/sniffcheck",       .method = HTTP_POST, .handler = byos_sniffcheck_post },
        { .uri = "/api/scan/channels",         .method = HTTP_GET,  .handler = scan_channels_get },
        { .uri = "/api/pcap/run",              .method = HTTP_POST, .handler = pcap_run_post },
        { .uri = "/api/pcap/status",           .method = HTTP_GET,  .handler = pcap_status_get },
        { .uri = "/api/pcap/latest",           .method = HTTP_GET,  .handler = pcap_latest_get },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(s_server, &uris[i]);
    }
}

esp_err_t download_http_start(void)
{
    if (s_server) return ESP_OK;

    viewer_locate_marker();

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();

    cfg.max_open_sockets = 7;
    cfg.lru_purge_enable = true;
    cfg.max_uri_handlers = 40;

    cfg.stack_size = 8192;

    esp_err_t err = httpd_start(&s_server, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        s_server = NULL;
        return err;
    }
    register_handlers();
    ESP_LOGI(TAG, "HTTP server up on AP netif");
    return ESP_OK;
}

void download_http_stop(void)
{
    if (!s_server) return;
    httpd_stop(s_server);
    s_server = NULL;
    ESP_LOGI(TAG, "HTTP server stopped");
}
