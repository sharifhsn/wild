use compact_artifact::CompactObject;
use compact_artifact::Options;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = Options {
        level: std::env::var("COMPACT_LEVEL")
            .ok()
            .map(|x| x.parse())
            .transpose()?
            .unwrap_or(3),
        block_size: std::env::var("COMPACT_BLOCK_SIZE")
            .ok()
            .map(|x| x.parse())
            .transpose()?
            .unwrap_or(256 * 1024),
    };
    match args.first().map(String::as_str) {
        Some("references") if args.len() == 2 => {
            use std::io::Write;
            let path = Path::new(&args[1]);
            let library = compact_artifact::library::Library::parse(&std::fs::read(path)?)?;
            let mut stdout = std::io::stdout().lock();
            for resolved in library.member_paths(path)? {
                stdout.write_all(resolved.to_str().ok_or("non-UTF8 path")?.as_bytes())?;
                stdout.write_all(&[0])?;
            }
        }
        Some("object") if args.len() == 3 => {
            let raw = std::fs::read(&args[1])?;
            let packed = compact_artifact::pack_elf(&raw, options)?;
            let reader = CompactObject::parse(&packed)?;
            println!(
                "{{\"raw_bytes\":{},\"stored_bytes\":{},\"metadata_bytes\":{},\"blocks\":{}}}",
                raw.len(),
                packed.len(),
                reader.metadata().len(),
                reader.block_count()
            );
            std::fs::write(&args[2], packed)?;
        }
        Some("archive") if args.len() == 4 => {
            let count = compact_artifact::pack_archive(
                Path::new(&args[1]),
                Path::new(&args[2]),
                Path::new(&args[3]),
                options,
            )?;
            println!("{{\"members\":{count}}}");
        }
        Some("inspect") if args.len() == 2 => {
            let bytes = std::fs::read(&args[1])?;
            let reader = CompactObject::parse(&bytes)?;
            println!(
                "{{\"raw_bytes\":{},\"stored_bytes\":{},\"metadata_bytes\":{},\"blocks\":{},\"decoded_blocks\":{}}}",
                reader.original_len(),
                bytes.len(),
                reader.metadata().len(),
                reader.block_count(),
                reader.decoded_blocks()
            );
        }
        _ => {
            return Err(
                "usage: wild-pack object INPUT OUTPUT | archive INPUT OUTPUT STORE | inspect INPUT | references MANIFEST"
                    .into(),
            );
        }
    }
    Ok(())
}
