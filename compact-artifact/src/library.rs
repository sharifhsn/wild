//! Ordered library manifest. Object payloads and Rust metadata live exactly once
//! outside the manifest. Entry names remain independent of content-addressed paths.
use crate::atomic_write;
use crate::invalid;
use crate::range;
use crate::u32_at;
use std::io;
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"RCLIB001";

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub path: String,
    /// 0: Rust object, 1: native object, 2: opaque bundled native archive.
    pub kind: u32,
}

#[derive(Default, Debug)]
pub struct Library {
    /// Relative to the manifest. Empty for a native library without Rust metadata.
    pub metadata: String,
    /// Compiler-owned late metadata, independent of object bytes.
    pub link_metadata: Vec<u8>,
    pub members: Vec<Member>,
}

impl Library {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if range(bytes, 0, 8)? != MAGIC || u32_at(bytes, 8)? != 1 || u32_at(bytes, 12)? != 0 {
            return Err(invalid("unsupported compact library"));
        }
        let body = bytes
            .get(48..)
            .ok_or_else(|| invalid("truncated compact library"))?;
        if blake3::hash(body).as_bytes() != range(bytes, 16, 32)? {
            return Err(invalid("compact library checksum mismatch"));
        }
        let mut cursor = 0;
        let mut take = |len| -> io::Result<&[u8]> {
            let value = range(body, cursor, len)?;
            cursor += len;
            Ok(value)
        };
        let meta_len = u32_at(take(4)?, 0)? as usize;
        let link_len = u32_at(take(4)?, 0)? as usize;
        let count = u32_at(take(4)?, 0)? as usize;
        let metadata = path_string(take(meta_len)?)?;
        let link_metadata = take(link_len)?.to_vec();
        // Even an empty entry requires 12 bytes; reject malicious capacities.
        if count > body.len() / 12 {
            return Err(invalid("invalid compact member count"));
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = u32_at(take(4)?, 0)?;
            if kind > 2 {
                return Err(invalid("unknown compact member kind"));
            }
            let name_len = u32_at(take(4)?, 0)? as usize;
            let path_len = u32_at(take(4)?, 0)? as usize;
            let name = path_string(take(name_len)?)?;
            let path = path_string(take(path_len)?)?;
            if path.is_empty() {
                return Err(invalid("empty compact member path"));
            }
            members.push(Member { name, path, kind });
        }
        if cursor != body.len() {
            return Err(invalid("trailing compact library bytes"));
        }
        Ok(Self {
            metadata,
            link_metadata,
            members,
        })
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        fn length(out: &mut Vec<u8>, len: usize) -> io::Result<()> {
            out.extend_from_slice(
                &u32::try_from(len)
                    .map_err(|_| invalid("manifest too large"))?
                    .to_le_bytes(),
            );
            Ok(())
        }
        let mut body = Vec::new();
        length(&mut body, self.metadata.len())?;
        length(&mut body, self.link_metadata.len())?;
        length(&mut body, self.members.len())?;
        body.extend_from_slice(self.metadata.as_bytes());
        body.extend_from_slice(&self.link_metadata);
        for member in &self.members {
            body.extend_from_slice(&member.kind.to_le_bytes());
            length(&mut body, member.name.len())?;
            length(&mut body, member.path.len())?;
            body.extend_from_slice(member.name.as_bytes());
            body.extend_from_slice(member.path.as_bytes());
        }
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(blake3::hash(&body).as_bytes());
        out.extend_from_slice(&body);
        Self::parse(&out)?;
        atomic_write(path, &out)
    }
}

fn path_string(bytes: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF8 manifest string"))?;
    if text.contains('\0') {
        return Err(invalid("NUL in compact manifest path"));
    }
    Ok(text.to_owned())
}
