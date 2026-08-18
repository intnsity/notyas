// Extra bindgen surface for the Waveshare Touch-LCD-10.1 "X"
// (board-waveshare-101x): the waveshare/esp_lcd_jd9365_10_1 DSI panel driver.
// Despite the component name it exports UNSUFFIXED symbols
// (esp_lcd_new_panel_jd9365 / jd9365_vendor_config_t). DSI bus / LDO /
// panel-ops surfaces come via bindings/st7703.h.
#include "esp_lcd_jd9365_10_1.h"
