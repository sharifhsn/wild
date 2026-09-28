//! Ordered library manifest. Object payloads and Rust metadata live exactly once
//! outside the manifest. Entry names remain independent of content-addressed paths.
//!
//! Version 2 manifests contain no absolute paths. Members name content-addressed
//! objects inside a store, and the store and metadata are recorded relative to the
//! manifest's directory. Readers fall back to searching ancestor directories, so a
//! manifest remains valid when the whole target directory moves, and when Cargo
//! hard-links it to another directory (for example `target/debug/libfoo.rlib`
//! beside `target/debug/deps/libfoo-<hash>.rlib`). Version 1 manifests, whose
//! member paths are relative to the manifest or absolute, remain readable.
use crate::atomic_write;
use crate::invalid;
use crate::range;
use crate::u32_at;
use std::io;
use std::path::Path;
use std::path::PathBuf;

pub const MAGIC: &[u8; 8] = b"RCLIB001";
const VERSION: u32 = 2;

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    /// Version 2: an object file name inside the store. Version 1: a path relative
    /// to the manifest directory, or absolute.
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
    /// The object store, relative to the manifest directory. Empty only when read
    /// from a version 1 manifest.
    pub store: String,
    pub members: Vec<Member>,
}

impl Library {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let version = u32_at(bytes, 8)?;
        if range(bytes, 0, 8)? != MAGIC
            || !(1..=VERSION).contains(&version)
            || u32_at(bytes, 12)? != 0
        {
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
        let store_len = if version >= 2 {
            u32_at(take(4)?, 0)? as usize
        } else {
            0
        };
        let metadata = path_string(take(meta_len)?)?;
        let link_metadata = take(link_len)?.to_vec();
        let store = path_string(take(store_len)?)?;
        if version >= 2 && store.is_empty() {
            return Err(invalid("missing compact object store"));
        }
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
            if version >= 2 && !is_file_name(&path) {
                return Err(invalid("compact member is not a store file name"));
            }
            members.push(Member { name, path, kind });
        }
        if cursor != body.len() {
            return Err(invalid("trailing compact library bytes"));
        }
        Ok(Self {
            metadata,
            link_metadata,
            store,
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
        length(&mut body, self.store.len())?;
        body.extend_from_slice(self.metadata.as_bytes());
        body.extend_from_slice(&self.link_metadata);
        body.extend_from_slice(self.store.as_bytes());
        for member in &self.members {
            body.extend_from_slice(&member.kind.to_le_bytes());
            length(&mut body, member.name.len())?;
            length(&mut body, member.path.len())?;
            body.extend_from_slice(member.name.as_bytes());
            body.extend_from_slice(member.path.as_bytes());
        }
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(blake3::hash(&body).as_bytes());
        out.extend_from_slice(&body);
        Self::parse(&out)?;
        atomic_write(path, &out)
    }

    /// Resolve every member's object file for the manifest stored at `manifest`.
    pub fn member_paths(&self, manifest: &Path) -> io::Result<Vec<PathBuf>> {
        let directory = manifest_directory(manifest)?;
        if self.store.is_empty() {
            return Ok(self
                .members
                .iter()
                .map(|member| directory.join(&member.path))
                .collect());
        }
        let store = self.find_store(&directory, manifest)?;
        Ok(self
            .members
            .iter()
            .map(|member| store.join(&member.path))
            .collect())
    }

    /// Resolve the Rust metadata file, or `None` for a library without metadata.
    pub fn metadata_path(&self, manifest: &Path) -> io::Result<Option<PathBuf>> {
        if self.metadata.is_empty() {
            return Ok(None);
        }
        let directory = manifest_directory(manifest)?;
        let direct = directory.join(&self.metadata);
        if self.store.is_empty() || direct.is_file() {
            return Ok(Some(direct));
        }
        // A hard-linked or copied manifest lives above the metadata's directory, or
        // beside a Cargo `deps` directory that holds it.
        let name = Path::new(&self.metadata)
            .file_name()
            .ok_or_else(|| invalid("compact metadata reference is not a file"))?;
        directory
            .ancestors()
            .flat_map(|ancestor| [ancestor.join(name), ancestor.join("deps").join(name)])
            .find(|candidate| candidate.is_file())
            .map(Some)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "metadata `{}` for compact library `{}` was not found",
                        self.metadata,
                        manifest.display()
                    ),
                )
            })
    }

    fn find_store(&self, directory: &Path, manifest: &Path) -> io::Result<PathBuf> {
        let recorded = directory.join(&self.store);
        // Only a named store directory can be searched for in ancestors.
        let name = Path::new(&self.store).file_name();
        // Any store holding the first member serves the manifest: objects are named by
        // their content hash and verified when parsed.
        let holds_members = |store: &Path| match self.members.first() {
            Some(member) => store.join(&member.path).is_file(),
            None => store.is_dir(),
        };
        std::iter::once(recorded)
            .chain(
                name.into_iter()
                    .flat_map(|name| directory.ancestors().map(move |a| a.join(name))),
            )
            .find(|candidate| holds_members(candidate))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "compact object store `{}` for `{}` was not found",
                        self.store,
                        manifest.display()
                    ),
                )
            })
    }
}

fn manifest_directory(manifest: &Path) -> io::Result<PathBuf> {
    let parent = manifest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::path::absolute(parent)
}

fn is_file_name(path: &str) -> bool {
    let path = Path::new(path);
    path.file_name()
        .is_some_and(|name| name == path.as_os_str())
}

fn path_string(bytes: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF8 manifest string"))?;
    if text.contains('\0') {
        return Err(invalid("NUL in compact manifest path"));
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn canonical(paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths
            .iter()
            .map(|path| fs::canonicalize(path).unwrap())
            .collect()
    }

    fn scratch(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "compact-library-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        fs::canonicalize(directory).unwrap()
    }

    /// Mimics Cargo: `target/debug/deps/libx-h.rlib`, its metadata, and a store at
    /// `target/compact-store`.
    fn cargo_layout(root: &Path) -> (PathBuf, Library) {
        let deps = root.join("target/debug/deps");
        let store = root.join("target/compact-store");
        fs::create_dir_all(&deps).unwrap();
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("aa.rco"), b"a").unwrap();
        fs::write(store.join("bb.rco"), b"b").unwrap();
        fs::write(deps.join("libx-h.rmeta"), b"m").unwrap();
        let library = Library {
            metadata: "libx-h.rmeta".into(),
            link_metadata: Vec::new(),
            store: crate::relative_path(&store, &deps).unwrap(),
            members: ["aa.rco", "bb.rco"]
                .into_iter()
                .map(|path| Member {
                    name: format!("{path}.o"),
                    path: path.into(),
                    kind: 0,
                })
                .collect(),
        };
        let manifest = deps.join("libx-h.rlib");
        library.write(&manifest).unwrap();
        (manifest, library)
    }

    #[test]
    fn references_are_relative_and_survive_moves_and_aliases() {
        let root = scratch("moves");
        let (manifest, library) = cargo_layout(&root);
        assert_eq!(library.store, "../../compact-store");
        let parsed = Library::parse(&fs::read(&manifest).unwrap()).unwrap();
        assert!(!parsed.store.starts_with('/'));

        // Moving the whole target directory keeps every reference valid.
        let moved = root.join("moved");
        fs::rename(root.join("target"), &moved).unwrap();
        let manifest = moved.join("debug/deps/libx-h.rlib");
        let store = moved.join("compact-store");
        assert_eq!(
            canonical(parsed.member_paths(&manifest).unwrap()),
            [store.join("aa.rco"), store.join("bb.rco")]
        );
        assert_eq!(
            parsed.metadata_path(&manifest).unwrap().unwrap(),
            moved.join("debug/deps/libx-h.rmeta")
        );

        // Cargo's uplifted alias in `target/debug` finds the store and `deps` metadata.
        let alias = moved.join("debug/libx.rlib");
        fs::hard_link(&manifest, &alias).unwrap();
        assert_eq!(
            canonical(parsed.member_paths(&alias).unwrap()),
            [store.join("aa.rco"), store.join("bb.rco")]
        );
        assert_eq!(
            parsed.metadata_path(&alias).unwrap().unwrap(),
            moved.join("debug/deps/libx-h.rmeta")
        );

        // A manifest copied outside the target cannot silently resolve elsewhere.
        let outside = scratch("outside").join("libx.rlib");
        fs::copy(&manifest, &outside).unwrap();
        assert_eq!(
            parsed.member_paths(&outside).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(outside.parent().unwrap()).unwrap();
    }

    #[test]
    fn version_one_manifests_remain_readable() {
        let root = scratch("v1");
        let body = {
            let mut body = Vec::new();
            for value in [0u32, 0, 1] {
                body.extend_from_slice(&value.to_le_bytes());
            }
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&3u32.to_le_bytes());
            body.extend_from_slice(&6u32.to_le_bytes());
            body.extend_from_slice(b"a.o");
            body.extend_from_slice(b"sub/aa");
            body
        };
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(blake3::hash(&body).as_bytes());
        bytes.extend_from_slice(&body);
        let library = Library::parse(&bytes).unwrap();
        assert!(library.store.is_empty());
        let manifest = root.join("lib.rlib");
        assert_eq!(
            library.member_paths(&manifest).unwrap(),
            [root.join("sub/aa")]
        );
        assert_eq!(library.metadata_path(&manifest).unwrap(), None);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn version_two_rejects_paths_in_member_names() {
        let root = scratch("reject");
        let library = Library {
            store: "store".into(),
            members: vec![Member {
                name: "a.o".into(),
                path: "../escape.rco".into(),
                kind: 0,
            }],
            ..Default::default()
        };
        assert!(library.write(&root.join("lib.rlib")).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
