idf_component_register(
    SRCS
        "arm_main.c"
        "arm_scan.c"
        "../../common/cluster_proto.c"
        "../../../dogpark-node/main/node_display.c"
        "../../../main/led.c"

        "../../../main/wifi_scanner.c"
        "../../../main/wifi_sniffer.c"
        "../../../main/frame_parser.c"
        "../../../main/eui_db.c"
        "../../../main/analyzer.c"
        "../../../main/physical_device_cluster.c"
        "../../../main/ble_scanner.c"
        "../../../main/ble_advise.c"
        "../../../main/drone_rid.c"
        "../../../main/apple_continuity.c"
        "../../../main/probe_req_log.c"
        "../../../main/probe_frame_ring.c"
        "../../../main/ble_adv_ring.c"
        "../../../main/flock_detect.c"
        "../../../main/public_safety_detect.c"
        "../../../main/medical_responder_detect.c"
        "../../../main/sta_tracker.c"
        "../../../main/wifi_csi_probe.c"
        "../../../main/pcap_capture.c"
        "../../../main/seq_analyzer.c"
        "../../../main/ie_signature.c"
        "../../../main/anqp_analyzer.c"
        "../../../main/capture_ring.c"
        "../../../main/capture_writer.c"
        "../../../main/virtual_pup.c"
        "../../../main/virtual_pup_walk.c"
        "../../../main/pup_trophy.c"
    INCLUDE_DIRS
        "."
        "../../common"
        "../../../dogpark-node/main"
        "../../../main"
    PRIV_REQUIRES
        esp_driver_i2c
        esp_driver_spi
        esp_driver_gpio
        esp_driver_ledc
        esp_lcd
        esp_timer
        esp_wifi
        esp_event
        esp_netif
        esp_partition
        spi_flash
        esp_psram
        esp_hw_support
        nvs_flash
        bt
        lwip
        mbedtls
    REQUIRES
        lcd_st7735
        opendroneid
)

if(NOT DEFINED ARM_INDEX)
    if(DEFINED ENV{ARM_INDEX})
        set(ARM_INDEX $ENV{ARM_INDEX})
    else()
        set(ARM_INDEX 1)
    endif()
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE ARM_INDEX=${ARM_INDEX})
message(STATUS "cluster arm index = ${ARM_INDEX}")
