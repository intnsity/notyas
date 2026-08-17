// Extra bindgen surface for the display pipeline, beyond esp-idf-sys's
// default binding set: internal LDO regulator (DPHY power), the MIPI-DSI
// bus/DBI/DPI esp_lcd layer, and the waveshare/esp_lcd_st7703 panel driver.
// Function-like config macros in these headers (ST7703_*_CONFIG) cannot be
// bound by bindgen; their values are replicated in src/display.rs.
#include "esp_ldo_regulator.h"
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7703.h"
