//! UNTESTED BOARD CONFIG - compile-checked scaffold, never run on hardware.
//! Board: Elecrow CrowPanel Advanced 7inch ESP32-P4 (1024x600 MIPI-DSI).
//! The 7/9/10.1 inch siblings share one electrical design (each verified
//! against its own factory sdkconfig + V1.0 Eagle schematic); everything but
//! the name lives in elecrow_dsi.rs.

pub use super::elecrow_dsi::*;

pub const BOARD_NAME: &str = "Elecrow CrowPanel Advanced 7inch ESP32-P4 (UNTESTED)";
