//! Split-DWARF `.dwo` fixups.

use object::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::read::elf::ElfFile64;
use std::fs;
use std::io;
use std::path::Path;

/// BFD, and so gdb (checked with 13.1 and 16.3), treats a compressed section as corrupt
/// ("section is too large") when its uncompressed size exceeds roughly ten times the size of
/// the whole file, and then drops that unit's DWARF. Files are kept at least this fraction of
/// their largest uncompressed section, which stays clear of that limit.
const MAX_RATIO_TO_FILE: u64 = 8;

/// Makes a `.dwo` file whose compressed sections compress too well for BFD readable again by
/// extending the file with a trailing hole. Small `.dwo` files with long, repetitive type names
/// trigger the check. The hole allocates no disk blocks, ELF readers ignore trailing bytes,
/// and the file is changed in place, so hard links to it stay valid. Returns whether the file
/// was extended.
pub fn make_readable_by_bfd(path: &Path) -> io::Result<bool> {
    let data = fs::read(path)?;
    let Ok(file) = ElfFile64::<LittleEndian>::parse(&*data) else {
        return Ok(false);
    };
    let largest = file
        .sections()
        .filter_map(|section| section.compressed_file_range().ok())
        .filter(|range| range.format != object::CompressionFormat::None)
        .map(|range| range.uncompressed_size)
        .max()
        .unwrap_or(0);
    let required = largest.div_ceil(MAX_RATIO_TO_FILE);
    if required <= data.len() as u64 {
        return Ok(false);
    }
    fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_len(required)?;
    Ok(true)
}
