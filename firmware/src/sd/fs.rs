// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`notyas_wallet::sd::Volume`] over ESP-IDF's FATFS, through the VFS and therefore
//! through `std::fs`.
//!
//! The whole file is six operations and no logic. That is the design: everything that
//! decides anything - what a name may contain, what a listing may cost, whether a file is
//! too large, what a delivered file is called, in what order a write is staged and
//! verified - lives in `notyas_wallet::sd`, where it runs on a host against a hostile
//! simulated card. What is left here is the part that cannot be tested without silicon,
//! and it is kept small enough that reading it is a substitute for testing it.
//!
//! # `std::fs`, not `f_open`
//!
//! `esp_vfs_fat_sdmmc_mount` registers FatFs with the VFS, which is what the Rust standard
//! library's file API on this target talks to. Going through `std::fs` rather than the raw
//! FatFs entry points buys the three obligations the trait states - a read that stops at
//! its limit, an exclusive create, and a flush before close - out of code that already
//! exists, instead of out of a second hand-written layer over `f_read`.
//!
//! # The three obligations, and where each is discharged
//!
//! 1. **`read` stops at the limit and does not allocate past it.** `Read::take` bounds the
//!    transfer, and - the part that matters - it is also what `read_to_end` asks for its
//!    buffer size, so the growth follows the LIMIT rather than the file's claimed length.
//!    Reading through `File::read_to_end` directly would size the buffer from the directory
//!    entry, which is a number off the card.
//! 2. **`create_exclusive` fails if the target exists.** `create_new` sets `O_CREAT |
//!    O_EXCL`, which ESP-IDF's FATFS VFS maps to `FA_CREATE_NEW`. This is not decoration:
//!    the existence check `deliver` performs happens before the write, and a card can be
//!    swapped in between.
//! 3. **`create_exclusive` flushes before returning.** `sync_all` is `fsync`, which the
//!    same VFS maps to `f_sync`. Without it the bytes sit in FatFs's own window buffer and
//!    the read-back that follows would be checking RAM against RAM.
//!
//! # Names are bytes
//!
//! `OsStr::as_encoded_bytes` rather than `to_string_lossy`. Under
//! `CONFIG_FATFS_API_ENCODING_ANSI_OEM` - the ESP-IDF default - a directory entry can hold
//! bytes that are not UTF-8, and a lossy conversion would turn one of those into a name
//! that renders plausibly and opens something else. The bytes go up to `Name::new`
//! unaltered and are refused there.

use std::fs;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use notyas_wallet::sd::{Location, Name, Raw, ReadOutcome, Volume, Walk};

use super::mount::{Card, MOUNT_POINT};

/// A filesystem call that failed, with enough context to be actionable in a log.
///
/// The path is carried because "open failed" is not a bug report and "open
/// `/sd/spend.psbt` failed: No such file or directory" is. It is rendered through the
/// `Debug` impl of `String`, so an attacker-chosen name holding a newline cannot forge a
/// second log line.
#[derive(Debug)]
pub struct FsError {
    pub op: &'static str,
    pub path: String,
    pub source: std::io::Error,
}

impl FsError {
    fn at(op: &'static str, path: &str, source: std::io::Error) -> Self {
        FsError {
            op,
            path: String::from(path),
            source,
        }
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {:?}: {}", self.op, self.path, self.source)
    }
}

/// The absolute path of a directory one level below the mount point, or of the mount point
/// itself.
///
/// Not `Location::render`, because a `Location` names a FILE. Kept next to it so the two
/// path-building sites are read together; there are no others.
fn dir_path(dir: Option<&Name>) -> String {
    let mut out = String::from(MOUNT_POINT);
    if let Some(dir) = dir {
        out.push('/');
        out.push_str(dir.as_str());
    }
    out
}

/// Seconds since the POSIX epoch, or `None` for a timestamp that predates it.
///
/// ESP-IDF's FATFS VFS builds `st_mtime` with `mktime` from the directory entry's date and
/// time fields, on a device with no time zone configured. Reading it back as UTC therefore
/// recovers the wall-clock digits the card recorded, which is what the picker is specified
/// to show. `notyas_wallet::sd::Timestamp` refuses anything outside FAT's own range, so a
/// zeroed date field arrives here as a number and leaves the catalog as "no timestamp".
fn epoch_seconds(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

impl Volume for Card {
    type Error = FsError;

    fn walk(
        &mut self,
        dir: Option<&Name>,
        visit: &mut dyn FnMut(Raw<'_>) -> Walk,
    ) -> Result<(), Self::Error> {
        let path = dir_path(dir);
        let entries = fs::read_dir(&path).map_err(|e| FsError::at("read_dir", &path, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| FsError::at("readdir", &path, e))?;
            // One stat per row. `d_type` would answer `is_dir` without it, but the size
            // and the timestamp need the stat anyway, and a listing that reported a size
            // for some rows and not others would be worse than a slightly slower one.
            //
            // A stat that fails on an entry readdir just returned means the card is going
            // away underneath us. That is R-23 "unreadable card", not a row to skip: a
            // listing silently missing the file the user came for is the one outcome a
            // picker must never produce.
            let meta = entry
                .metadata()
                .map_err(|e| FsError::at("stat", &path, e))?;
            let name = entry.file_name();
            let raw = Raw {
                name: name.as_encoded_bytes(),
                is_dir: meta.is_dir(),
                len: meta.len(),
                modified: meta.modified().ok().and_then(epoch_seconds),
            };
            if visit(raw) == Walk::Stop {
                break;
            }
        }
        Ok(())
    }

    fn read(
        &mut self,
        at: Location<'_>,
        limit: u32,
        out: &mut Vec<u8>,
    ) -> Result<ReadOutcome, Self::Error> {
        out.clear();
        let path = at.render(MOUNT_POINT);
        let mut file = fs::File::open(&path).map_err(|e| FsError::at("open", &path, e))?;
        Read::by_ref(&mut file)
            .take(u64::from(limit))
            .read_to_end(out)
            .map_err(|e| FsError::at("read", &path, e))?;
        // One byte past the limit is the whole question: it separates a file that happens
        // to be exactly `limit` bytes long from one that is longer and was truncated. The
        // caller cannot tell those apart from the buffer, and treating the second as the
        // first would hand a parser a prefix.
        let mut probe = [0u8; 1];
        let extra = file
            .read(&mut probe)
            .map_err(|e| FsError::at("read", &path, e))?;
        if extra == 0 {
            Ok(ReadOutcome::Complete)
        } else {
            Ok(ReadOutcome::OverLimit)
        }
    }

    fn create_exclusive(&mut self, at: Location<'_>, data: &[u8]) -> Result<(), Self::Error> {
        let path = at.render(MOUNT_POINT);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| FsError::at("create", &path, e))?;
        file.write_all(data)
            .map_err(|e| FsError::at("write", &path, e))?;
        // Before the handle closes, and before the read-back that follows. A write this
        // call reported as done must be a write FatFs has pushed at the card, or the
        // verification step is comparing the buffer against itself.
        file.sync_all()
            .map_err(|e| FsError::at("fsync", &path, e))?;
        Ok(())
    }

    fn rename(&mut self, from: Location<'_>, to: Location<'_>) -> Result<(), Self::Error> {
        let from = from.render(MOUNT_POINT);
        let to = to.render(MOUNT_POINT);
        // FatFs `f_rename` refuses an existing target, which is why the caller removes it
        // first and why the module docs above `deliver` describe that gap honestly instead
        // of claiming an atomic replace this filesystem cannot perform.
        fs::rename(&from, &to).map_err(|e| FsError::at("rename", &from, e))
    }

    fn remove(&mut self, at: Location<'_>) -> Result<(), Self::Error> {
        let path = at.render(MOUNT_POINT);
        fs::remove_file(&path).map_err(|e| FsError::at("remove", &path, e))
    }

    fn exists(&mut self, at: Location<'_>) -> Result<bool, Self::Error> {
        let path = at.render(MOUNT_POINT);
        match fs::metadata(&path) {
            Ok(_) => Ok(true),
            // "Not there" is an answer, not a failure. Anything else - a bus error, a
            // filesystem that has stopped responding - is reported, because answering
            // "no" to it would let a delivery overwrite a file it never managed to look
            // at.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(FsError::at("stat", &path, e)),
        }
    }
}
