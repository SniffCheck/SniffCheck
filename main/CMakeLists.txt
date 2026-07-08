set(srcs
    "app_main.c"
    "ui_activity.c"
    "led.c"
    "display.c"
    "usb_console.c"
    "wifi_scanner.c"
    "eui_db.c"
    "frame_parser.c"
    "wifi_sniffer.c"
    "analyzer.c"
    "physical_device_cluster.c"
    "ble_scanner.c"
    "ble_advise.c"
    "drone_rid.c"
    "apple_continuity.c"
    "probe_req_log.c"
    "probe_frame_ring.c"
    "ble_adv_ring.c"
    "flock_detect.c"
    "public_safety_detect.c"
    "medical_responder_detect.c"
    "sta_tracker.c"
    "wifi_csi_probe.c"
    "pcap_capture.c"
    "seq_analyzer.c"
    "ie_signature.c"
    "anqp_analyzer.c"
    "vetter.c"
    "capture_ring.c"
    "capture_writer.c"
    "download_mode.c"
    "download_http.c"
    "self_test.c"
    "virtual_pup.c"
    "virtual_pup_walk.c"
    "pup_trophy.c"
)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        esp_driver_spi
        esp_driver_gpio
        esp_driver_ledc
        esp_lcd
        nvs_flash
        esp_wifi
        esp_event
        esp_netif
        esp_http_server
        esp_partition
        spi_flash
        esp_psram
        bt
        lwip
        mbedtls
        esp_timer
        esp_hw_support
        opendroneid
    REQUIRES
        lcd_st7735
)

target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../tools/capture_viewer/index.html" TEXT
    RENAME_TO capture_viewer_html)

target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/webap_logo.png" BINARY
    RENAME_TO webap_logo_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/webap_favicon.png" BINARY
    RENAME_TO webap_favicon_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/webap_pup.png" BINARY
    RENAME_TO webap_pup_png)
