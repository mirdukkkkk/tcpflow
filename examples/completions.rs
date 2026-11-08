//! Write the shell completions to `doc/completions/` (src/completions.rs).
//!
//!     cargo run --example completions

fn main() -> std::io::Result<()> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("doc/completions");
    std::fs::create_dir_all(&dir)?;
    for (name, content) in tcpflow::completions::all() {
        std::fs::write(dir.join(name), content)?;
        println!("doc/completions/{name}");
    }
    Ok(())
}
