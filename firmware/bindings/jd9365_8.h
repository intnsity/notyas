// Extra bindgen surface for the Waveshare Touch-LCD-8 "X" (board-waveshare-8x):
// the waveshare/esp_lcd_jd9365_8 DSI panel driver (suffixed symbols:
// esp_lcd_new_panel_jd9365_8 / jd9365_8_vendor_config_t - no clash with the
// 10.1 driver's unsuffixed names). DSI bus / LDO / panel-ops surfaces come
// via bindings/st7703.h.
#include "esp_lcd_jd9365_8.h"
