//! Experimental compact ELF objects: eager symbol metadata and lazy payload blocks.
//!
//! A compact object is not an ELF file. Its metadata block contains an ELF header,
//! section headers and symbol/string tables; cold section offsets are tagged indexes
//! into independently compressed blocks. Readers must resolve those indexes explicitly.
//! `WILD_COMPACT_CACHE_BYTES` enables a file-backed, bounded resident-page mode.

use hashbrown::HashMap;
use memmap2::Mmap;
use memmap2::MmapOptions;
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

pub mod library;

pub const MAGIC: &[u8; 8] = b"RCOBJ001";
pub const VIRTUAL_OFFSET: u64 = 1 << 63;
const HEADER: usize = 96;
const SECTION_ENTRY: usize = 16;
const BLOCK_ENTRY: usize = 64;
const HOT: u32 = u32::MAX;
const MAX_METADATA: usize = 256 * 1024 * 1024;
const MAX_BLOCK: usize = 1024 * 1024 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static OBJECTS: AtomicU64 = AtomicU64::new(0);
static RAW_BYTES: AtomicU64 = AtomicU64::new(0);
static STORED_BYTES: AtomicU64 = AtomicU64::new(0);
static METADATA_BYTES: AtomicU64 = AtomicU64::new(0);
static PAYLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
static DECODED_BYTES: AtomicU64 = AtomicU64::new(0);
static BLOCKS: AtomicU64 = AtomicU64::new(0);
static READ_BLOCKS: AtomicU64 = AtomicU64::new(0);
static CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static CACHE_ADVISED_BYTES: AtomicU64 = AtomicU64::new(0);
static CACHE_LIMIT: OnceLock<Option<usize>> = OnceLock::new();
static DECODED_CACHE: OnceLock<Mutex<DecodedCache>> = OnceLock::new();

pub fn statistics() -> String {
    let cache_bytes = DECODED_CACHE
        .get()
        .and_then(|cache| cache.lock().ok().map(|cache| cache.bytes))
        .unwrap_or(0);
    let cache_limit = decoded_cache_limit();
    format!(
        "{{\"objects\":{},\"raw_bytes\":{},\"stored_bytes\":{},\"metadata_bytes\":{},\"payload_bytes\":{},\"decoded_bytes\":{},\"blocks\":{},\"read_blocks\":{},\"cache_enabled\":{},\"cache_limit_bytes\":{},\"cache_tracked_bytes\":{},\"cache_evictions\":{},\"cache_advised_bytes\":{}}}",
        OBJECTS.load(Ordering::Relaxed),
        RAW_BYTES.load(Ordering::Relaxed),
        STORED_BYTES.load(Ordering::Relaxed),
        METADATA_BYTES.load(Ordering::Relaxed),
        PAYLOAD_BYTES.load(Ordering::Relaxed),
        DECODED_BYTES.load(Ordering::Relaxed),
        BLOCKS.load(Ordering::Relaxed),
        READ_BLOCKS.load(Ordering::Relaxed),
        cache_limit.is_some(),
        cache_limit.unwrap_or(0),
        cache_bytes,
        CACHE_EVICTIONS.load(Ordering::Relaxed),
        CACHE_ADVISED_BYTES.load(Ordering::Relaxed)
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub level: i32,
    pub block_size: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            level: 3,
            block_size: 256 * 1024,
        }
    }
}

#[derive(Debug)]
struct Section {
    block: u32,
    offset: usize,
    len: usize,
}

#[derive(Debug)]
struct Block {
    offset: usize,
    stored_len: usize,
    raw_len: usize,
    codec: u32,
    digest: [u8; 32],
    decoded: OnceLock<Result<DecodedPayload, String>>,
    verified: OnceLock<Result<(), String>>,
}

#[derive(Debug)]
enum DecodedPayload {
    Pinned(Box<[u8]>),
    Bounded(Arc<DecodedBlock>),
}

impl DecodedPayload {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Pinned(bytes) => bytes,
            Self::Bounded(block) => block.bytes(),
        }
    }
}

#[derive(Debug)]
struct DecodedBlock {
    map: Mmap,
}

impl DecodedBlock {
    fn bytes(&self) -> &[u8] {
        &self.map
    }

    fn advise_cold(&self) -> bool {
        #[cfg(unix)]
        {
            // Safety: this is a read-only, file-backed mapping. Discarded pages
            // can be faulted back from the immutable temporary backing file.
            unsafe {
                self.map
                    .unchecked_advise(memmap2::UncheckedAdvice::DontNeed)
                    .is_ok()
            }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

#[derive(Default)]
struct DecodedCache {
    bytes: usize,
    tick: u64,
    entries: HashMap<usize, CacheEntry>,
    order: VecDeque<(u64, usize)>,
}

struct CacheEntry {
    block: Weak<DecodedBlock>,
    bytes: usize,
    last_touch: u64,
}

fn decoded_cache_limit() -> Option<usize> {
    *CACHE_LIMIT.get_or_init(|| {
        std::env::var("WILD_COMPACT_CACHE_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
    })
}

fn touch_decoded_block(block: &Arc<DecodedBlock>) {
    let cache = DECODED_CACHE.get_or_init(|| Mutex::new(DecodedCache::default()));
    let Ok(mut cache) = cache.lock() else {
        return;
    };
    let key = Arc::as_ptr(block) as usize;
    cache.tick = cache.tick.wrapping_add(1);
    let tick = cache.tick;
    if let Some(entry) = cache.entries.get_mut(&key) {
        entry.last_touch = tick;
    } else {
        let bytes = block.bytes().len();
        cache.bytes = cache.bytes.saturating_add(bytes);
        cache.entries.insert(
            key,
            CacheEntry {
                block: Arc::downgrade(block),
                bytes,
                last_touch: tick,
            },
        );
    }
    cache.order.push_back((tick, key));

    let Some(limit) = decoded_cache_limit() else {
        return;
    };
    while cache.bytes > limit {
        let Some((queued_tick, oldest)) = cache.order.pop_front() else {
            break;
        };
        let Some(entry) = cache.entries.get(&oldest) else {
            continue;
        };
        if entry.last_touch != queued_tick {
            continue;
        }
        let entry = cache.entries.remove(&oldest).unwrap();
        cache.bytes = cache.bytes.saturating_sub(entry.bytes);
        if let Some(block) = entry.block.upgrade()
            && block.advise_cold()
        {
            CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
            CACHE_ADVISED_BYTES.fetch_add(entry.bytes as u64, Ordering::Relaxed);
        }
    }

    if cache.order.len() > cache.entries.len().saturating_mul(4).max(1024) {
        // This iteration only rebuilds the LRU queue; sorting makes the result
        // deterministic before it can affect future cache decisions.
        #[allow(rustc::potential_query_instability)]
        let mut newest_first: Vec<_> = cache
            .entries
            .iter()
            .map(|(&key, entry)| (entry.last_touch, key))
            .collect();
        newest_first.sort_unstable();
        cache.order = newest_first.into();
    }
}

fn decode_to_mmap(
    stored: &[u8],
    raw_len: usize,
    digest: &[u8; 32],
) -> io::Result<Arc<DecodedBlock>> {
    let mut file = tempfile::tempfile()?;
    let mut decoder = zstd::stream::read::Decoder::new(io::Cursor::new(stored))?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = decoder.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| invalid("decoded compact block length overflow"))?;
        if total > raw_len {
            return Err(invalid("decoded compact block exceeds declared length"));
        }
        file.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
    }
    if total != raw_len {
        return Err(invalid("decoded compact block length mismatch"));
    }
    if hasher.finalize().as_bytes() != digest {
        return Err(invalid("compact payload checksum mismatch"));
    }
    file.flush()?;
    // The file is immutable after mapping. Keeping it file-backed lets the OS
    // drop cold pages while the linker's borrowed section slices remain valid:
    // later reads fault the bytes back from the temporary backing file.
    let map = unsafe { MmapOptions::new().map(&file)? };
    if map.len() != raw_len {
        return Err(invalid("mapped compact block length mismatch"));
    }
    Ok(Arc::new(DecodedBlock { map }))
}

/// Owns small, eagerly decoded metadata and pins only payload blocks actually read.
/// Compressed source bytes remain in the caller's mapping.
#[derive(Debug)]
pub struct CompactObject {
    metadata: Box<[u8]>,
    sections: Vec<Section>,
    blocks: Vec<Block>,
    original_len: u64,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn range(bytes: &[u8], offset: usize, len: usize) -> io::Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(len)
                    .ok_or_else(|| invalid("range overflow"))?,
        )
        .ok_or_else(|| invalid("compact artifact range is outside input"))
}

fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        range(bytes, offset, 8)?.try_into().unwrap(),
    ))
}

fn usize_at(bytes: &[u8], offset: usize) -> io::Result<usize> {
    usize::try_from(u64_at(bytes, offset)?).map_err(|_| invalid("length exceeds address space"))
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn decode(bytes: &[u8], codec: u32, raw_len: usize) -> io::Result<Vec<u8>> {
    let result = match codec {
        0 => bytes.to_vec(),
        1 => zstd::bulk::decompress(bytes, raw_len)?,
        _ => return Err(invalid("unknown compact artifact codec")),
    };
    if result.len() != raw_len {
        return Err(invalid("decoded compact artifact length mismatch"));
    }
    Ok(result)
}

fn encode(bytes: &[u8], level: i32) -> io::Result<(Vec<u8>, u32)> {
    let compressed = zstd::bulk::compress(bytes, level)?;
    Ok(if compressed.len() < bytes.len() {
        (compressed, 1)
    } else {
        (bytes.to_vec(), 0)
    })
}

impl CompactObject {
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if range(data, 0, 8)? != MAGIC || u32_at(data, 8)? != 1 || u32_at(data, 12)? != 0 {
            return Err(invalid("unsupported compact object header"));
        }
        let raw_len = usize_at(data, 24)?;
        if raw_len > MAX_METADATA {
            return Err(invalid("compact metadata exceeds limit"));
        }
        let stored_len = usize_at(data, 32)?;
        let block_count = u32_at(data, 40)? as usize;
        let section_count = u32_at(data, 44)? as usize;
        if u32_at(data, 52)? != 0 {
            return Err(invalid("nonzero compact header reserved field"));
        }
        let table_len = section_count
            .checked_mul(SECTION_ENTRY)
            .and_then(|n| {
                block_count
                    .checked_mul(BLOCK_ENTRY)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or_else(|| invalid("compact table size overflow"))?;
        if usize_at(data, 56)? != table_len {
            return Err(invalid("compact table length mismatch"));
        }
        let index_len = stored_len
            .checked_add(table_len)
            .ok_or_else(|| invalid("index overflow"))?;
        let index = range(data, HEADER, index_len)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(range(data, 0, 64)?);
        hasher.update(index);
        if hasher.finalize().as_bytes() != range(data, 64, 32)? {
            return Err(invalid("compact metadata/index checksum mismatch"));
        }
        let metadata = decode(&index[..stored_len], u32_at(data, 48)?, raw_len)?.into_boxed_slice();
        if metadata.get(..6) != Some(b"\x7fELF\x02\x01") {
            return Err(invalid("compact metadata is not ELF64 little endian"));
        }
        let mut sections = Vec::with_capacity(section_count);
        let mut cursor = stored_len;
        for _ in 0..section_count {
            sections.push(Section {
                block: u32_at(index, cursor)?,
                offset: u32_at(index, cursor + 4)? as usize,
                len: usize_at(index, cursor + 8)?,
            });
            cursor += SECTION_ENTRY;
        }
        let mut blocks = Vec::with_capacity(block_count);
        let mut payload_end = HEADER + index_len;
        for _ in 0..block_count {
            let offset = usize_at(index, cursor)?;
            let stored_len = usize_at(index, cursor + 8)?;
            let raw_len = usize_at(index, cursor + 16)?;
            let codec = u32_at(index, cursor + 24)?;
            if raw_len > MAX_BLOCK
                || offset != payload_end
                || codec > 1
                || (codec == 0 && stored_len != raw_len)
                || u32_at(index, cursor + 28)? != 0
            {
                return Err(invalid("invalid compact payload descriptor"));
            }
            range(data, offset, stored_len)?;
            payload_end = offset + stored_len;
            blocks.push(Block {
                offset,
                stored_len,
                raw_len,
                codec,
                digest: range(index, cursor + 32, 32)?.try_into().unwrap(),
                decoded: OnceLock::new(),
                verified: OnceLock::new(),
            });
            cursor += BLOCK_ENTRY;
        }
        if payload_end != data.len() {
            return Err(invalid("trailing compact artifact data"));
        }
        for section in &sections {
            let limit = if section.block == HOT {
                metadata.len()
            } else {
                blocks
                    .get(section.block as usize)
                    .ok_or_else(|| invalid("invalid compact block index"))?
                    .raw_len
            };
            if section
                .offset
                .checked_add(section.len)
                .is_none_or(|end| end > limit)
            {
                return Err(invalid("compact section exceeds its block"));
            }
        }
        OBJECTS.fetch_add(1, Ordering::Relaxed);
        RAW_BYTES.fetch_add(u64_at(data, 16)?, Ordering::Relaxed);
        STORED_BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);
        METADATA_BYTES.fetch_add(metadata.len() as u64, Ordering::Relaxed);
        PAYLOAD_BYTES.fetch_add(
            blocks.iter().map(|b| b.raw_len as u64).sum(),
            Ordering::Relaxed,
        );
        BLOCKS.fetch_add(blocks.len() as u64, Ordering::Relaxed);
        Ok(Self {
            metadata,
            sections,
            blocks,
            original_len: u64_at(data, 16)?,
        })
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
    pub fn original_len(&self) -> u64 {
        self.original_len
    }
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
    pub fn decoded_blocks(&self) -> usize {
        self.blocks
            .iter()
            .filter(|b| b.decoded.get().is_some())
            .count()
    }

    pub fn read_section<'a>(&'a self, source: &'a [u8], index: usize) -> io::Result<&'a [u8]> {
        let section = self
            .sections
            .get(index)
            .ok_or_else(|| invalid("compact section index out of bounds"))?;
        if section.block == HOT {
            return range(&self.metadata, section.offset, section.len);
        }
        let block = &self.blocks[section.block as usize];
        let stored = range(source, block.offset, block.stored_len)?;
        let data = if block.codec == 0 {
            block
                .verified
                .get_or_init(|| {
                    READ_BLOCKS.fetch_add(1, Ordering::Relaxed);
                    if blake3::hash(stored).as_bytes() == &block.digest {
                        Ok(())
                    } else {
                        Err("compact payload checksum mismatch".into())
                    }
                })
                .as_ref()
                .map_err(|e| invalid(e.clone()))?;
            stored
        } else {
            let decoded = block
                .decoded
                .get_or_init(|| {
                    READ_BLOCKS.fetch_add(1, Ordering::Relaxed);
                    DECODED_BYTES.fetch_add(block.raw_len as u64, Ordering::Relaxed);
                    if decoded_cache_limit().is_some() {
                        decode_to_mmap(stored, block.raw_len, &block.digest)
                            .map(DecodedPayload::Bounded)
                            .map_err(|e| e.to_string())
                    } else {
                        let decoded = decode(stored, block.codec, block.raw_len)
                            .map_err(|e| e.to_string())?;
                        if blake3::hash(&decoded).as_bytes() != &block.digest {
                            return Err("compact payload checksum mismatch".into());
                        }
                        Ok(DecodedPayload::Pinned(decoded.into_boxed_slice()))
                    }
                })
                .as_ref()
                .map_err(|e| invalid(e.clone()))?;
            if let DecodedPayload::Bounded(mapped) = decoded {
                touch_decoded_block(mapped);
            }
            decoded.bytes()
        };
        range(data, section.offset, section.len)
    }
}

/// The returned metadata view has the original section indexes and attributes.
/// Cold offsets deliberately lie outside that view, so unsupported reads fail.
pub fn pack_elf(data: &[u8], options: Options) -> io::Result<Vec<u8>> {
    if data.get(..6) != Some(b"\x7fELF\x02\x01")
        || range(data, 16, 2)? != [1, 0]
        || range(data, 54, 2)? != [0, 0]
        || range(data, 58, 2)? != [64, 0]
    {
        return Err(invalid(
            "compact objects require ELF64 little-endian relocatable input without program headers",
        ));
    }
    if options.block_size < 1024 || options.block_size > 4 * 1024 * 1024 {
        return Err(invalid("compact block size must be 1024..4194304"));
    }
    let shoff = usize_at(data, 40)?;
    let short_count = u16::from_le_bytes(range(data, 60, 2)?.try_into().unwrap()) as usize;
    let count = if short_count == 0 {
        usize_at(data, shoff + 32)?
    } else {
        short_count
    };
    let headers_len = count
        .checked_mul(64)
        .ok_or_else(|| invalid("section count overflow"))?;
    let headers = range(data, shoff, headers_len)?;
    let mut metadata = range(data, 0, 64)?.to_vec();
    put64(&mut metadata, 40, 64);
    metadata.extend_from_slice(headers);
    let mut sections = Vec::with_capacity(count);
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for index in 0..count {
        let header = range(headers, index * 64, 64)?;
        let kind = u32_at(header, 4)?;
        let size = usize_at(header, 32)?;
        if kind == 0 || kind == 8 || size == 0 {
            sections.push(Section {
                block: HOT,
                offset: 0,
                len: 0,
            });
            continue;
        }
        let bytes = range(data, usize_at(header, 24)?, size)?;
        // Symbol resolution, COMDAT, names and architecture notes stay in metadata.
        // Code/data, relocation streams and DWARF payloads are cold.
        let cold = matches!(kind, 1 | 4 | 9);
        if cold {
            if blocks
                .last()
                .is_none_or(|b| b.len().saturating_add(size) > options.block_size)
            {
                blocks.push(Vec::new());
            }
            let block_index = blocks.len() - 1;
            let block = blocks.last_mut().unwrap();
            // Preserve alignment for typed relocation readers.
            block.resize(block.len().next_multiple_of(8), 0);
            if block.len().saturating_add(size) > MAX_BLOCK {
                return Err(invalid("compact payload block exceeds limit"));
            }
            sections.push(Section {
                block: block_index
                    .try_into()
                    .map_err(|_| invalid("too many blocks"))?,
                offset: block.len(),
                len: size,
            });
            block.extend_from_slice(bytes);
            put64(
                &mut metadata,
                64 + index * 64 + 24,
                VIRTUAL_OFFSET | index as u64,
            );
        } else {
            metadata.resize(metadata.len().next_multiple_of(8), 0);
            let offset = metadata.len();
            sections.push(Section {
                block: HOT,
                offset,
                len: size,
            });
            metadata.extend_from_slice(bytes);
            put64(&mut metadata, 64 + index * 64 + 24, offset as u64);
        }
    }
    if metadata.len() > MAX_METADATA {
        return Err(invalid("compact metadata exceeds limit"));
    }
    let (meta_stored, meta_codec) = encode(&metadata, options.level)?;
    let table_len = count * SECTION_ENTRY + blocks.len() * BLOCK_ENTRY;
    let mut out = vec![0; HEADER];
    out[..8].copy_from_slice(MAGIC);
    put32(&mut out, 8, 1);
    put64(&mut out, 16, data.len() as u64);
    put64(&mut out, 24, metadata.len() as u64);
    put64(&mut out, 32, meta_stored.len() as u64);
    put32(
        &mut out,
        40,
        blocks
            .len()
            .try_into()
            .map_err(|_| invalid("too many blocks"))?,
    );
    put32(
        &mut out,
        44,
        count.try_into().map_err(|_| invalid("too many sections"))?,
    );
    put32(&mut out, 48, meta_codec);
    put64(&mut out, 56, table_len as u64);
    out.extend_from_slice(&meta_stored);
    for s in &sections {
        out.extend_from_slice(&s.block.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(s.offset)
                .map_err(|_| invalid("section offset too large"))?
                .to_le_bytes(),
        );
        out.extend_from_slice(&(s.len as u64).to_le_bytes());
    }
    let block_table = out.len();
    out.resize(out.len() + blocks.len() * BLOCK_ENTRY, 0);
    let payload_start = out.len();
    for (index, block) in blocks.iter().enumerate() {
        let (stored, codec) = encode(block, options.level)?;
        let cursor = block_table + index * BLOCK_ENTRY;
        let offset = out.len();
        put64(&mut out, cursor, offset as u64);
        put64(&mut out, cursor + 8, stored.len() as u64);
        put64(&mut out, cursor + 16, block.len() as u64);
        put32(&mut out, cursor + 24, codec);
        out[cursor + 32..cursor + 64].copy_from_slice(blake3::hash(block).as_bytes());
        out.extend_from_slice(&stored);
    }
    let mut hash = blake3::Hasher::new();
    hash.update(&out[..64]);
    hash.update(&out[HEADER..payload_start]);
    out[64..96].copy_from_slice(hash.finalize().as_bytes());
    Ok(out)
}

/// Write a content-addressed object, checking an existing entry before reuse.
pub fn store_object(data: &[u8], store: &Path, options: Options) -> io::Result<PathBuf> {
    let packed = if data.starts_with(MAGIC) {
        data.to_vec()
    } else {
        pack_elf(data, options)?
    };
    let key = blake3::hash(&packed).to_hex();
    fs::create_dir_all(store)?;
    let path = store.join(format!("{key}.rco"));
    if path.exists() {
        if fs::read(&path)? != packed {
            return Err(invalid(
                "existing compact object does not match its content address",
            ));
        }
    } else {
        // Concurrent writers have identical bytes and unique scratch names.
        atomic_write(&path, &packed)?;
    }
    Ok(path)
}

/// The name under which `store_object` published `path` inside its store.
pub fn store_file_name(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| invalid("compact object path has no UTF-8 file name"))
}

pub fn relative_path(path: &Path, base: &Path) -> io::Result<String> {
    let path = fs::canonicalize(path)?;
    let base = fs::canonicalize(base)?;
    let left: Vec<_> = path.components().collect();
    let right: Vec<_> = base.components().collect();
    let common = left.iter().zip(&right).take_while(|(a, b)| a == b).count();
    let mut result = PathBuf::new();
    for _ in common..right.len() {
        result.push("..");
    }
    for component in &left[common..] {
        result.push(component.as_os_str());
    }
    result
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("compact manifest path is not UTF-8"))
}

/// Publish complete bytes with scratch names unique across threads and processes.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".compact.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    // Failure to create does not give us ownership of an existing scratch file.
    let mut file = fs::File::create_new(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Share an immutable store entry with an incremental work product. Cross-device
/// stores use a copy; callers must include that copy in storage accounting.
pub fn link_object(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".compact-link.{}.{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut copy = match fs::hard_link(source, &temp) {
        Ok(()) => None,
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            Some(fs::File::create_new(&temp)?)
        }
        Err(error) => return Err(error),
    };
    let result = (|| {
        if let Some(file) = &mut copy {
            io::copy(&mut fs::File::open(source)?, file)?;
        }
        fs::rename(&temp, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn pack_archive(
    input: &Path,
    output: &Path,
    store: &Path,
    options: Options,
) -> io::Result<usize> {
    let data = fs::read(input)?;
    let archive = object::read::archive::ArchiveFile::parse(data.as_slice())
        .map_err(|e| invalid(e.to_string()))?;
    if archive.is_thin() {
        return Err(invalid("input archive is already thin"));
    }
    fs::create_dir_all(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    fs::create_dir_all(store)?;
    let mut library = library::Library {
        store: relative_path(
            store,
            output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?,
        ..Default::default()
    };
    for member in archive.members() {
        let member = member.map_err(|e| invalid(e.to_string()))?;
        let bytes = member
            .data(data.as_slice())
            .map_err(|e| invalid(e.to_string()))?;
        let path = store_object(bytes, store, options)?;
        library.members.push(library::Member {
            name: String::from_utf8(member.name().to_vec())
                .map_err(|_| invalid("non-UTF8 member name"))?,
            path: store_file_name(&path)?,
            kind: 1,
        });
    }
    library.write(output)?;
    Ok(library.members.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_integrity_and_concurrent_store_publication() {
        let directory = std::env::temp_dir().join(format!(
            "compact-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let raw = sample();
        let paths = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| store_object(&raw, &directory, Options::default()).unwrap())
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(paths.iter().all(|p| p == &paths[0]));
        let work = directory.join("work.o");
        link_object(&paths[0], &work).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&paths[0]).unwrap().ino(),
                fs::metadata(&work).unwrap().ino()
            );
        }
        let manifest = library::Library {
            metadata: "../crate.rmeta".into(),
            link_metadata: vec![1, 2, 3],
            store: ".".into(),
            members: paths
                .iter()
                .enumerate()
                .map(|(i, p)| library::Member {
                    name: format!("object-{i}.o"),
                    path: store_file_name(p).unwrap(),
                    kind: 0,
                })
                .collect(),
        };
        let path = directory.join("crate.rlib");
        manifest.write(&path).unwrap();
        let bytes = fs::read(&path).unwrap();
        let loaded = library::Library::parse(&bytes).unwrap();
        assert_eq!(loaded.metadata, manifest.metadata);
        assert_eq!(loaded.link_metadata, manifest.link_metadata);
        assert_eq!(loaded.store, manifest.store);
        assert_eq!(loaded.member_paths(&path).unwrap(), paths);
        assert_eq!(
            loaded.members.iter().map(|m| &m.name).collect::<Vec<_>>(),
            manifest.members.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        for len in 0..bytes.len() {
            assert!(library::Library::parse(&bytes[..len]).is_err());
        }
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(library::Library::parse(&corrupt).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }

    fn sample() -> Vec<u8> {
        let mut data = vec![0; 64 + 3 * 64];
        data[..6].copy_from_slice(b"\x7fELF\x02\x01");
        data[16] = 1;
        data[52] = 64;
        data[58] = 64;
        data[60] = 3;
        put64(&mut data, 40, 64);
        for (index, byte) in [(1, 42), (2, 91)] {
            put32(&mut data, 64 + index * 64 + 4, 1);
            let offset = data.len();
            put64(&mut data, 64 + index * 64 + 24, offset as u64);
            put64(&mut data, 64 + index * 64 + 32, 4096);
            data.extend(std::iter::repeat_n(byte, 4096));
        }
        data
    }

    #[test]
    fn payload_is_lazy_and_pinned_once() {
        let packed = pack_elf(
            &sample(),
            Options {
                block_size: 1024,
                ..Options::default()
            },
        )
        .unwrap();
        let object = CompactObject::parse(&packed).unwrap();
        assert_eq!(object.decoded_blocks(), 0);
        assert_eq!(object.read_section(&packed, 1).unwrap(), vec![42; 4096]);
        let first = object.read_section(&packed, 1).unwrap().as_ptr();
        assert_eq!(object.read_section(&packed, 1).unwrap().as_ptr(), first);
        assert_eq!(object.decoded_blocks(), 1);
        assert_eq!(object.read_section(&packed, 2).unwrap(), vec![91; 4096]);
        assert_eq!(object.decoded_blocks(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn file_backed_payload_remains_valid_after_pages_are_evicted() {
        let packed = pack_elf(
            &sample(),
            Options {
                block_size: 1024,
                ..Options::default()
            },
        )
        .unwrap();
        let object = CompactObject::parse(&packed).unwrap();
        let section = object.read_section(&packed, 1).unwrap().to_vec();
        let block_index = object.sections[1].block as usize;
        let decoded = object.blocks[block_index]
            .decoded
            .get()
            .unwrap()
            .as_ref()
            .unwrap();
        let DecodedPayload::Bounded(mapped) = decoded else {
            // The normal default intentionally keeps the old in-memory cache.
            // Exercise the bounded mapping path directly in this test instead.
            let mapped = decode_to_mmap(
                &packed[object.blocks[block_index].offset
                    ..object.blocks[block_index].offset + object.blocks[block_index].stored_len],
                object.blocks[block_index].raw_len,
                &object.blocks[block_index].digest,
            )
            .unwrap();
            assert!(mapped.advise_cold());
            assert_eq!(
                mapped.bytes()[object.sections[1].offset..][..object.sections[1].len],
                section
            );
            return;
        };
        assert!(mapped.advise_cold());
        assert_eq!(object.read_section(&packed, 1).unwrap(), section);
    }

    #[cfg(unix)]
    #[test]
    fn configured_decoded_cache_stays_within_its_budget() {
        let limit = decoded_cache_limit();
        let packed = pack_elf(
            &sample(),
            Options {
                block_size: 1024,
                ..Options::default()
            },
        )
        .unwrap();
        let object = CompactObject::parse(&packed).unwrap();
        for section in 1..object.sections.len() {
            object.read_section(&packed, section).unwrap();
        }
        if let Some(limit) = limit {
            let cache = DECODED_CACHE.get().unwrap().lock().unwrap();
            assert!(
                cache.bytes <= limit,
                "{} bytes tracked over {limit}-byte cap",
                cache.bytes
            );
        }
    }

    #[test]
    fn unused_payload_is_not_touched_and_used_corruption_is_rejected() {
        let mut packed = pack_elf(
            &sample(),
            Options {
                block_size: 1024,
                ..Options::default()
            },
        )
        .unwrap();
        let object = CompactObject::parse(&packed).unwrap();
        let offset = object.blocks[1].offset;
        packed[offset] ^= 1;
        let object = CompactObject::parse(&packed).unwrap();
        assert_eq!(object.read_section(&packed, 1).unwrap(), vec![42; 4096]);
        assert!(object.read_section(&packed, 2).is_err());
    }

    #[test]
    fn every_truncation_and_index_corruption_is_rejected() {
        let packed = pack_elf(&sample(), Options::default()).unwrap();
        for end in 0..packed.len() {
            assert!(CompactObject::parse(&packed[..end]).is_err());
        }
        let mut corrupt = packed.clone();
        corrupt[HEADER] ^= 1;
        assert!(CompactObject::parse(&corrupt).is_err());
        let mut trailing = packed;
        trailing.push(0);
        assert!(CompactObject::parse(&trailing).is_err());
    }
}
