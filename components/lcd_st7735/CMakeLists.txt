idf_component_register(
    SRCS "st7735.c"
    INCLUDE_DIRS "include"
    REQUIRES
        driver
        esp_lcd
)
