#pragma once

#define HEAD_I2C_PORT     0
#define HEAD_I2C_SDA_GPIO 43
#define HEAD_I2C_SCL_GPIO 44
#define HEAD_I2C_HZ       1000000

#define HEAD_BRAIN_ADDR   0x10
#define HEAD_ARM1_ADDR    0x11
#define HEAD_ARM2_ADDR    0x12

#define HEAD_LED_DIN_GPIO 40
#define HEAD_LED_CLK_GPIO 39
#define HEAD_LED_SPI_HOST 2

#define HEAD_BTN_GPIO     0

#define HEAD_SD_ENABLE    1
#define HEAD_SD_CLK_GPIO  12
#define HEAD_SD_CMD_GPIO  16
#define HEAD_SD_D0_GPIO   14
#define HEAD_SD_D1_GPIO   17
#define HEAD_SD_D2_GPIO   21
#define HEAD_SD_D3_GPIO   18

#define HEAD_LCD_SPI_HOST 1
#define HEAD_LCD_MOSI_GPIO 3
#define HEAD_LCD_CLK_GPIO  5
#define HEAD_LCD_CS_GPIO   4
#define HEAD_LCD_DC_GPIO   2
#define HEAD_LCD_RST_GPIO  1
#define HEAD_LCD_BL_GPIO   38
