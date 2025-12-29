use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rayon::prelude::*;
use zip::ZipArchive;
use zip::result::ZipError;

#[derive(Parser, Debug)]
#[command(author, version, about = "Fast, parallel ZIP password brute forcer.")]
struct Args {
    /// Path to the password-protected ZIP file.
    #[arg(short = 'z', long, value_name = "FILE")]
    zip: PathBuf,

    /// Wordlist containing one password candidate per line.
    #[arg(short = 'w', long, value_name = "FILE")]
    wordlist: PathBuf,

    /// Specific file path inside the archive to validate (defaults to first non-directory).
    #[arg(short = 't', long, value_name = "PATH")]
    target: Option<String>,

    /// Number of worker threads to use (defaults to available logical cores).
    #[arg(long, default_value_t = num_cpus::get())]
    threads: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.threads == 0 {
        bail!("--threads must be at least 1");
    }

    rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
        .context("Unable to configure thread pool")?;

    let archive_bytes = std::fs::read(&args.zip)
        .with_context(|| format!("Failed to read archive: {}", args.zip.display()))?;

    let candidates = load_wordlist(&args.wordlist)?;
    if candidates.is_empty() {
        bail!("Wordlist is empty");
    }

    let found = AtomicBool::new(false);
    let winning_password: Mutex<Option<String>> = Mutex::new(None);
    let started_at = Instant::now();

    candidates.par_iter().for_each(|candidate| {
        if found.load(Ordering::Relaxed) {
            return;
        }

        match password_matches(&archive_bytes, candidate, args.target.as_deref()) {
            Ok(true) => {
                found.store(true, Ordering::Relaxed);
                let mut guard = winning_password.lock().expect("poisoned mutex");
                *guard = Some(candidate.clone());
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("Error while trying \"{candidate}\": {error}");
            }
        }
    });

    if let Some(password) = winning_password
        .into_inner()
        .expect("poisoned mutex during teardown")
    {
        println!("Password found: {password}");
        println!(
            "Tried {} candidates in {:.2?}",
            candidates.len(),
            started_at.elapsed()
        );
        Ok(())
    } else {
        println!(
            "Password not found in the provided wordlist ({} candidates tried) after {:.2?}",
            candidates.len(),
            started_at.elapsed()
        );
        std::process::exit(1);
    }
}

fn load_wordlist(path: &Path) -> Result<Vec<String>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open wordlist: {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            entries.push(trimmed.to_owned());
        }
    }

    Ok(entries)
}

fn password_matches(archive_bytes: &[u8], password: &str, target: Option<&str>) -> Result<bool> {
    let cursor = std::io::Cursor::new(archive_bytes);
    let mut archive = ZipArchive::new(cursor)?;

    let target_index = match target {
        Some(name) => {
            let index = (0..archive.len()).find(|&i| match archive.by_index(i) {
                Ok(file) => !file.is_dir() && file.name() == name,
                Err(_) => false,
            });
            index.ok_or_else(|| anyhow!("Target file \"{name}\" not found in archive"))?
        }
        None => (0..archive.len())
            .find(|&i| match archive.by_index(i) {
                Ok(file) => !file.is_dir(),
                Err(_) => false,
            })
            .ok_or_else(|| anyhow!("Archive contains no files to test"))?,
    };

    let mut file = match archive.by_index_decrypt(target_index, password.as_bytes()) {
        Ok(file) => file,
        Err(ZipError::InvalidPassword) => return Ok(false),
        Err(error) => return Err(error.into()),
    };

    let mut buffer = [0u8; 1];
    match file.read(&mut buffer) {
        Ok(_) => Ok(true),
        Err(error) => Err(error.into()),
    }
}
