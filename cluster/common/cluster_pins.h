#pragma once

#define CL_I2C_PORT     0
#define CL_I2C_SDA_GPIO 11
#define CL_I2C_SCL_GPIO 12
#define CL_I2C_HZ       100000

#define CL_BRAIN_ADDR   0x10
#define CL_ARM1_ADDR    0x11
#define CL_ARM2_ADDR    0x12
#define CL_S3_ADDR      0x13
#define CL_ARM_ADDR(idx) ((idx) == 1 ? CL_ARM1_ADDR : CL_ARM2_ADDR)

#define CL_LCD_SPI_HOST 1
#define CL_LCD_MOSI     2
#define CL_LCD_MISO     7
#define CL_LCD_SCK      6
