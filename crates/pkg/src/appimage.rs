//! Find the filesystem inside an AppImage.
//!
//! A type-2 AppImage is a small ELF runtime with a squashfs image concatenated
//! onto the end of it, so the payload starts wherever the ELF stops — the
//! furthest point named by its section and program header tables. Type 1 (an
//! ELF plus an ISO 9660 image) predates 2016 and is not read here.
//!
//! The type marker lives in the ELF header's padding bytes: `0x41 0x49` ("AI")
//! followed by the version. Some builds zero it out, so the file extension is
//! accepted as a second opinion.

use crate::{squashfs, PkgError};

const ELF_MAGIC: &[u8] = b"\x7fELF";
/// Offset of the AppImage type marker inside `e_ident`'s padding.
const TYPE_MARKER: usize = 8;

/// How far past the computed end of the ELF to look for the payload before
/// giving up on the header and scanning the whole file.
const SEARCH_WINDOW: usize = 64 << 10;

pub fn is_appimage(bytes: &[u8], lower_filename: &str) -> bool {
    if !bytes.starts_with(ELF_MAGIC) {
        return false;
    }
    marker(bytes).is_some() || lower_filename.ends_with(".appimage")
}

/// The AppImage version byte, if the marker is present.
fn marker(bytes: &[u8]) -> Option<u8> {
    let m = bytes.get(TYPE_MARKER..TYPE_MARKER + 3)?;
    (m[0] == 0x41 && m[1] == 0x49).then_some(m[2])
}

/// The squashfs image appended to the runtime.
pub fn payload(bytes: &[u8]) -> Result<&[u8], PkgError> {
    if marker(bytes) == Some(1) {
        return Err(PkgError::Unsupported(
            "this is a type-1 AppImage (an ISO 9660 payload, the pre-2016 format); \
             only type-2 AppImages can be read"
                .into(),
        ));
    }

    let start = elf_end(bytes)
        .and_then(|end| find_superblock(bytes, end, end.saturating_add(SEARCH_WINDOW)))
        // A stripped or unusual runtime can leave the header tables pointing
        // short of the payload; the image itself is still findable.
        .or_else(|| find_superblock(bytes, ELF_MAGIC.len(), bytes.len()))
        .ok_or_else(|| {
            PkgError::Malformed(
                "AppImage",
                "no squashfs image found after the runtime".into(),
            )
        })?;

    Ok(&bytes[start..])
}

/// First offset in `from..to` (4-byte aligned) that begins a squashfs 4.0
/// superblock.
fn find_superblock(bytes: &[u8], from: usize, to: usize) -> Option<usize> {
    let to = to.min(bytes.len());
    let mut at = from - (from % 4);
    while at < to {
        let candidate = bytes.get(at..)?;
        // The version check keeps the scan from stopping on the four magic
        // bytes appearing inside compressed data.
        if squashfs::is_squashfs(candidate)
            && candidate
                .get(28..30)
                .map(|v| u16::from_le_bytes([v[0], v[1]]) == 4)
                .unwrap_or(false)
        {
            return Some(at);
        }
        at += 4;
    }
    None
}

/// The first byte past the ELF: the furthest end of its section and program
/// header tables, which is where a tool appending a payload starts writing.
fn elf_end(bytes: &[u8]) -> Option<usize> {
    let ident = bytes.get(..16)?;
    if !ident.starts_with(ELF_MAGIC) {
        return None;
    }
    // AppImage runtimes are little-endian; a big-endian one would need its own
    // field reads, and the payload scan covers that case anyway.
    if ident[5] != 1 {
        return None;
    }

    let (is_64, shoff_at, shentsize_at, phoff_at, phentsize_at) = match ident[4] {
        2 => (true, 0x28, 0x3A, 0x20, 0x36),
        1 => (false, 0x20, 0x2E, 0x1C, 0x2A),
        _ => return None,
    };

    let word = |at: usize| -> Option<u64> {
        if is_64 {
            let b = bytes.get(at..at + 8)?;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(b);
            Some(u64::from_le_bytes(buf))
        } else {
            let b = bytes.get(at..at + 4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
        }
    };
    let half = |at: usize| -> Option<u64> {
        let b = bytes.get(at..at + 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]) as u64)
    };

    let sections = word(shoff_at)? + half(shentsize_at)? * half(shentsize_at + 2)?;
    let programs = word(phoff_at)? + half(phentsize_at)? * half(phentsize_at + 2)?;
    usize::try_from(sections.max(programs)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit ELF header whose section table ends at `end`, followed by
    /// `payload` at that offset.
    fn stub(type_marker: Option<u8>, end: usize, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; end];
        out[..4].copy_from_slice(ELF_MAGIC);
        out[4] = 2; // 64-bit
        out[5] = 1; // little-endian
        if let Some(version) = type_marker {
            out[8..11].copy_from_slice(&[0x41, 0x49, version]);
        }
        // Section header table: 2 entries of 64 bytes ending exactly at `end`.
        let shoff = (end - 128) as u64;
        out[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        out[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        out[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Just enough of a superblock for the scan to accept it.
    fn superblock() -> Vec<u8> {
        let mut sb = vec![0u8; 96];
        sb[..4].copy_from_slice(b"hsqs");
        sb[28..30].copy_from_slice(&4u16.to_le_bytes());
        sb
    }

    #[test]
    fn payload_starts_where_the_elf_ends() {
        let image = stub(Some(2), 4096, &superblock());
        assert!(is_appimage(&image, "foo.appimage"));
        assert_eq!(payload(&image).unwrap(), &superblock()[..]);
    }

    #[test]
    fn an_unmarked_runtime_is_recognised_by_its_extension() {
        let image = stub(None, 4096, &superblock());
        assert!(is_appimage(&image, "foo-1.2.3-x86_64.appimage"));
        assert!(!is_appimage(&image, "foo"));
    }

    #[test]
    fn a_payload_past_the_header_tables_is_still_found() {
        // Header tables that stop short: the scan has to find the image.
        let mut image = stub(Some(2), 4096, &vec![0u8; 8192]);
        let at = image.len();
        image.extend_from_slice(&superblock());
        assert_eq!(payload(&image).unwrap().len(), image.len() - at);
    }

    #[test]
    fn type_1_appimages_are_named_rather_than_misread() {
        let image = stub(Some(1), 4096, &superblock());
        let err = payload(&image).unwrap_err();
        assert!(err.to_string().contains("type-1"));
    }
}
