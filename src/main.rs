//! CLI front end for the mrtgen library.

use std::path::PathBuf;
use std::process::ExitCode;

use mrtgen::{generate, FatalKind, GeneratorConfig};

const USAGE: &str = "\
mrtgen - deterministic synthetic MRT corpus generator (RFC 6396 / 8050)

USAGE:
    mrtgen [OPTIONS]

OPTIONS:
    -o, --out <FILE>         Output MRT file [default: corpus.mrt]
    -m, --manifest <FILE>    Manifest JSON path [default: <out>.manifest.json]
        --no-valid           Omit the well-formed records
        --no-skip            Omit the skip-class malformed records
        --no-combo           Omit the communities x ADD-PATH combination records
        --no-attr-errors     Omit the RFC 7606 attribute error-handling records
        --fatal <KIND>       Append one abort-class tail to the main file.
                             KIND: length-overrun | truncated-header | huge-length
        --fatal-dir <DIR>    Additionally write one file per abort-class case
                             into DIR (each with its own manifest); these
                             files contain the same records as the main file
                             plus the fatal tail
        --base-timestamp <N> Timestamp of record 0 [default: 1600000000]
    -h, --help               Show this help
";

struct Args {
    out: PathBuf,
    manifest: Option<PathBuf>,
    no_valid: bool,
    no_skip: bool,
    no_combo: bool,
    no_attr_errors: bool,
    fatal: Option<FatalKind>,
    fatal_dir: Option<PathBuf>,
    base_timestamp: u32,
}

fn parse_fatal(s: &str) -> Result<FatalKind, String> {
    match s {
        "length-overrun" => Ok(FatalKind::LengthOverrunsEof),
        "truncated-header" => Ok(FatalKind::TruncatedHeader),
        "huge-length" => Ok(FatalKind::HugeLength),
        other => Err(format!("unknown --fatal kind '{other}'")),
    }
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        out: PathBuf::from("corpus.mrt"),
        manifest: None,
        no_valid: false,
        no_skip: false,
        no_combo: false,
        no_attr_errors: false,
        fatal: None,
        fatal_dir: None,
        base_timestamp: 1_600_000_000,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} requires a value"));
        match a.as_str() {
            "-h" | "--help" => return Ok(None),
            "-o" | "--out" => args.out = PathBuf::from(value("--out")?),
            "-m" | "--manifest" => args.manifest = Some(PathBuf::from(value("--manifest")?)),
            "--no-valid" => args.no_valid = true,
            "--no-skip" => args.no_skip = true,
            "--no-combo" => args.no_combo = true,
            "--no-attr-errors" => args.no_attr_errors = true,
            "--fatal" => args.fatal = Some(parse_fatal(&value("--fatal")?)?),
            "--fatal-dir" => args.fatal_dir = Some(PathBuf::from(value("--fatal-dir")?)),
            "--base-timestamp" => {
                args.base_timestamp = value("--base-timestamp")?.parse().map_err(|e| format!("--base-timestamp: {e}"))?
            }
            other => return Err(format!("unknown argument '{other}' (see --help)")),
        }
    }
    Ok(Some(args))
}

fn write_corpus(cfg: &GeneratorConfig, mrt_path: &PathBuf, manifest_path: &PathBuf) -> std::io::Result<()> {
    let corpus = generate(cfg);
    std::fs::write(mrt_path, &corpus.bytes)?;
    std::fs::write(manifest_path, corpus.manifest.to_json())?;
    println!(
        "wrote {} ({} bytes, {} records: {} valid, {} skip, {} abort) + {}",
        mrt_path.display(),
        corpus.manifest.file_size,
        corpus.manifest.records.len(),
        corpus.manifest.counts.valid,
        corpus.manifest.counts.skip,
        corpus.manifest.counts.abort,
        manifest_path.display(),
    );
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = GeneratorConfig {
        base_timestamp: args.base_timestamp,
        include_valid: !args.no_valid,
        include_skip: !args.no_skip,
        include_combo: !args.no_combo,
        include_attr_errors: !args.no_attr_errors,
        fatal: args.fatal,
    };

    let manifest_path = args.manifest.clone().unwrap_or_else(|| {
        let mut p = args.out.as_os_str().to_owned();
        p.push(".manifest.json");
        PathBuf::from(p)
    });

    if let Err(e) = write_corpus(&cfg, &args.out, &manifest_path) {
        eprintln!("error writing {}: {e}", args.out.display());
        return ExitCode::FAILURE;
    }

    if let Some(dir) = args.fatal_dir {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("error creating {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
        for kind in FatalKind::ALL {
            let cfg = GeneratorConfig { fatal: Some(kind), ..cfg.clone() };
            let mrt = dir.join(format!("{}.mrt", kind.kind_name()));
            let man = dir.join(format!("{}.mrt.manifest.json", kind.kind_name()));
            if let Err(e) = write_corpus(&cfg, &mrt, &man) {
                eprintln!("error writing {}: {e}", mrt.display());
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
