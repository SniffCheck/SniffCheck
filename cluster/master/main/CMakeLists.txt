idf_component_register(
    SRCS
        "master_main.c"
        "master_shim.c"
        "cluster_web.c"
        "../../common/cluster_proto.c"
        "../../../dogpark-node/main/node_display.c"
        "../../../main/led.c"

        "../../../main/download_http.c"
        "../../../main/download_mode.c"
        "../../../main/capture_ring.c"
        "../../../main/virtual_pup.c"
        "../../../main/virtual_pup_walk.c"
        "../../../main/pup_trophy.c"
    INCLUDE_DIRS
        "."
        "../../common"
        "../../../dogpark-node/main"
        "../../../main"
    PRIV_REQUIRES
        esp_driver_i2c esp_driver_spi esp_driver_gpio esp_driver_ledc esp_lcd
        esp_timer esp_http_server esp_wifi esp_netif esp_event nvs_flash
        esp_hw_support spi_flash driver
    REQUIRES
        lcd_st7735
)

target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../tools/capture_viewer/index.html" TEXT
    RENAME_TO capture_viewer_html)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/dogpark_dashboard.html" TEXT
    RENAME_TO dogpark_dashboard_html)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/webap_logo.png" BINARY
    RENAME_TO webap_logo_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/webap_favicon.png" BINARY
    RENAME_TO webap_favicon_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/webap_pup.png" BINARY
    RENAME_TO webap_pup_png)
