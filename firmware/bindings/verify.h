// Extra bindgen surface for the Verify screen (SECURITY.md invariant 5): everything
// on it is READ from the running system at boot, never a compiled-in claim.
// - esp_partition.h / esp_ota_ops.h: the running app partition and its SHA256
//   (esp_partition_get_sha256 hashes the image the flash actually holds).
// - esp_flash_encrypt.h: esp_flash_encryption_enabled() - a real function.
// - esp_efuse.h + esp_efuse_table.h: esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN).
//   esp_secure_boot_enabled() itself is static inline (not bindgen-able); this is the
//   same eFuse bit its non-virtual arm reads through efuse_ll. The table header
//   dispatches on CONFIG_ESP32P4_SELECTS_REV_LESS_V3, so the pre-v3 descriptor set is
//   used on our rev v1.3 dev silicon (firmware/README.md pitfall 4).
// - hal/efuse_hal.h: efuse_hal_chip_revision() (major*100 + minor), which composes the
//   pre-v3 split wafer-major LO/HI fields exactly like IDF's efuse_ll.h.
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_flash_encrypt.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "hal/efuse_hal.h"
