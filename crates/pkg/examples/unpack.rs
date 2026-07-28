//! Inspect what a package holds, without writing anything.
//!
//! ```text
//! cargo run -p pkg --example unpack -- Foo.AppImage
//! cargo run -p pkg --example unpack -- app.deb --extract /tmp/out
//! ```

use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(file) = args.next() else {
        eprintln!("usage: unpack <package> [--extract <dir>]");
        std::process::exit(2);
    };
    let extract_to = match (args.next().as_deref(), args.next()) {
        (Some("--extract"), Some(dir)) => Some(PathBuf::from(dir)),
        _ => None,
    };

    let bytes = std::fs::read(&file)?;
    let name = Path::new(&file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let format = pkg::sniff(&bytes, &name).ok_or("not a package format we recognise")?;
    println!("{name}: {format} ({} bytes)", bytes.len());

    let base = Path::new("/scan");
    let summary = match &extract_to {
        Some(dir) => {
            let mut sink = pkg::DirSink::new(dir)?;
            let summary = pkg::unpack(&bytes, format, dir, &mut sink)?;
            sink.finish()?;
            summary
        }
        None => {
            let mut sink = pkg::Collector::default();
            let summary = pkg::unpack(&bytes, format, base, &mut sink)?;
            for entry in sink.entries.iter().take(40) {
                match entry {
                    pkg::Entry::Dir(p) => println!("  dir  {}", p.display()),
                    pkg::Entry::File { path, data, mode } => {
                        println!("  file {} ({} bytes, {mode:o})", path.display(), data.len())
                    }
                    pkg::Entry::Symlink { path, target } => {
                        println!("  link {} -> {}", path.display(), target.display())
                    }
                }
            }
            if sink.entries.len() > 40 {
                println!("  … and {} more entries", sink.entries.len() - 40);
            }
            summary
        }
    };

    println!(
        "\n{} files, {:.1} MiB",
        summary.files,
        summary.bytes as f64 / (1024.0 * 1024.0)
    );
    for warning in &summary.warnings {
        println!("warning: {warning}");
    }
    Ok(())
}
