// Extra bindgen surface for touch: the new i2c_master bus API, the esp_lcd
// I2C panel-IO layer (v2 entry point), and the espressif/esp_lcd_touch_gt911
// component (which pulls in the esp_lcd_touch base API).
// ESP_LCD_TOUCH_IO_I2C_GT911_CONFIG() is a function-like macro and cannot be
// bound by bindgen; its values are replicated in src/touch.rs.
#include "driver/i2c_master.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_touch.h"
#include "esp_lcd_touch_gt911.h"
