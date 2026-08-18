// Extra bindgen surface for the Waveshare Touch-LCD-5 (board-waveshare-5):
// the waveshare/esp_lcd_hx8394 DSI panel driver. The DSI bus / LDO /
// panel-ops surfaces are already bound via bindings/st7703.h (bindings are
// a global union across all extra_components entries).
// HX8394_720_1280_PANEL_30HZ_DPI_CONFIG() is a function-like macro and
// cannot be bound by bindgen; its values are replicated in
// src/board/waveshare_5.rs.
#include "esp_lcd_hx8394.h"
