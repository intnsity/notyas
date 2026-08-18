// Extra bindgen surface for the Elecrow CrowPanel Advanced boards:
// - esp_lcd_panel_rgb.h: core-IDF parallel RGB panel driver (LCDCAM), used by
//   the 5 inch 800x480 panel (board-elecrow-5).
// - esp_lcd_ek79007.h: EK79007 MIPI-DSI panel component, used by the 1024x600
//   7/9/10.1 inch siblings (board-elecrow-7/-9/-101).
// The DSI bus / LDO / panel-ops / i2c_master surfaces are already bound via
// bindings/st7703.h and bindings/gt911.h (bindings are a global union across
// all extra_components entries).
// EK79007_1024_600_PANEL_60HZ_CONFIG() is a function-like macro and cannot be
// bound by bindgen; the Elecrow factory firmware's explicit values are
// replicated in src/board/elecrow_dsi.rs.
#include "esp_lcd_panel_rgb.h"
#include "esp_lcd_ek79007.h"
