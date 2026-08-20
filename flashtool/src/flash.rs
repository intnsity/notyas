// SPDX-License-Identifier: GPL-3.0-or-later
// COM port detection and esptool wrapper.

use std::path::Path;
use std::process::Command;

pub struct PortInfo {
    pub name: String,
    pub description: String,
}

pub fn list_ports() -> Vec<PortInfo> {
    match serialport::available_ports() {
        Ok(ports) => ports
            .into_iter()
            .map(|p| {
                let desc = match &p.port_type {
                    serialport::SerialPortType::UsbPort(info) => {
                        let chip = info
                            .product
                            .as_deref()
                            .or(info.manufacturer.as_deref())
                            .unwrap_or("USB Serial");
                        format!("{} (vid {:04x})", chip, info.vid)
                    }
                    serialport::SerialPortType::PciPort => "PCI".to_string(),
                    _ => "Serial".to_string(),
                };
                PortInfo {
                    name: p.port_name,
                    description: desc,
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Find an esptool executable. Tries `esptool` on PATH, then `python -m esptool`.
pub fn find_esptool() -> Option<String> {
    // Try standalone esptool
    if let Ok(out) = Command::new("esptool").arg("version").output() {
        if out.status.success() {
            return Some("esptool".to_string());
        }
    }
    // Try python -m esptool
    if let Ok(out) = Command::new("python")
        .args(["-m", "esptool", "version"])
        .output()
    {
        if out.status.success() {
            return Some("python -m esptool".to_string());
        }
    }
    None
}

/// Flash a merged.bin to the device. Returns log lines via the sender.
pub fn flash_merged(
    esptool: &str,
    port: &str,
    bin_path: &Path,
    tx: std::sync::mpsc::Sender<crate::WorkMsg>,
) {
    let mut cmd_parts = esptool.split_whitespace();
    let exe = cmd_parts.next().unwrap_or("python");
    let extra: Vec<&str> = cmd_parts.collect();

    let mut args = extra;
    args.extend_from_slice(&[
        "--port",
        port,
        "--baud",
        "921600",
        "write_flash",
        "0x0",
    ]);

    let bin_str = bin_path.to_string_lossy().to_string();
    args.push(&bin_str);

    let _ = tx.send(crate::WorkMsg::Log(format!(
        "Flashing {} to {}...",
        bin_path.file_name().unwrap_or_default().to_string_lossy(),
        port
    )));

    match Command::new(exe).args(&args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stdout.lines().chain(stderr.lines()) {
                let _ = tx.send(crate::WorkMsg::Log(line.to_string()));
            }
            if out.status.success() {
                let _ = tx.send(crate::WorkMsg::Done(true, "Flash complete".to_string()));
            } else {
                let _ = tx.send(crate::WorkMsg::Done(
                    false,
                    format!("esptool exited with code {}", out.status.code().unwrap_or(-1)),
                ));
            }
        }
        Err(e) => {
            let _ = tx.send(crate::WorkMsg::Done(false, format!("Failed to run esptool: {}", e)));
        }
    }
}
