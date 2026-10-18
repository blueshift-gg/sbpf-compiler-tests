mod compiler;
mod logging;
mod manifest;
mod model;
mod report;
mod runner;

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    ffi::OsString,
    fmt, fs, io,
    path::{Path, PathBuf},
    process::Output,
};

pub use mollusk_svm::Mollusk;
pub use mollusk_svm::result::Check;
pub use solana_account::Account;
pub use solana_instruction::AccountMeta;
pub use solana_instruction::Instruction;
pub use solana_instruction::error::InstructionError;
pub use solana_pubkey::Pubkey;

pub use compiler::Compiler;
pub use compiler::build_local_compiler;

/// Environment variable which contains the absolute path of the program ELF to load
pub(crate) const SBPF_PROGRAM_ELF_ENV: &str = "SBPF_PROGRAM_ELF";

/// Returns the path of the current program's ELF.
pub fn program_elf() -> String {
    let mut path = match env::var_os(SBPF_PROGRAM_ELF_ENV) {
        Some(path) => PathBuf::from(path),
        // Fallback to `cargo-build-sbpf` elf path.
        None => {
            let compiler = compiler::Compiler::CargoBuildSbpf;
            let package_dir =
                env::current_dir().expect("test working directory is the package directory");
            let target = package_dir
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.replace('-', "_"))
                .expect("test working directory is the package directory");
            let root = package_dir
                .parent()
                .and_then(Path::parent)
                .expect("package directory is inside the workspace `programs/` directory");
            compiler.elf_path(root, &target)
        }
    };
    path.set_extension("");
    path.into_os_string()
        .into_string()
        .unwrap_or_else(|path| path.to_string_lossy().into_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkResult {
    pub name: String,
    pub compute_units: u64,
    pub error: Option<String>,
}

pub type BenchmarkRunner = fn(&Mollusk, Pubkey) -> Result<Vec<BenchmarkResult>, BenchmarkError>;

#[derive(Clone, Copy, Debug)]
pub struct ProgramRegistration {
    pub(crate) name: &'static str,
    pub(crate) runner: BenchmarkRunner,
}

impl ProgramRegistration {
    pub const fn new(name: &'static str, runner: BenchmarkRunner) -> Self {
        Self { name, runner }
    }
}

pub fn run(
    root: &Path,
    compiler: Compiler,
    local_binary: Option<PathBuf>,
    registrations: &[ProgramRegistration],
    programs: &[String],
    skip_programs: &[String],
) -> Result<(), Box<dyn Error>> {
    logging::init();
    let binary = local_binary
        .as_deref()
        .unwrap_or_else(|| Path::new(compiler.tool_name()));
    let mut manifest = manifest::load(&root.join("programs/manifest.json"))?;
    let packages = manifest::load_packages(root)?;
    manifest::validate(&manifest, &packages)?;
    if !programs.is_empty() || !skip_programs.is_empty() {
        let skip = programs.is_empty();
        let list = if skip { skip_programs } else { programs };
        let available: BTreeSet<_> = manifest
            .programs
            .iter()
            .map(|program| program.name.as_str())
            .collect();

        // Check if any unknown programs are provided in the list.
        let unknown: Vec<_> = list
            .iter()
            .filter(|name| !available.contains(name.as_str()))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(format!("unknown programs provided: `{}`", unknown.join("`, `"),).into());
        }

        manifest
            .programs
            .retain(|program| skip != list.contains(&program.name));
    }
    let compiler_version = compiler.version(&binary)?;
    let now = jiff::Zoned::now();
    let run_timestamp = format!(
        "{:04}-{:02}-{:02}_{:02}-{:02}-{:02}-{:03}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    );

    let (report, saved_artifacts) = {
        let (programs, saved_artifacts) = runner::run_programs(
            root,
            compiler,
            registrations,
            &manifest,
            &packages,
            &run_timestamp,
            &binary,
        )?;

        (
            model::Report {
                compiler: compiler_version,
                programs,
            },
            saved_artifacts,
        )
    };
    let artifacts_dir = Path::new("/tmp")
        .join(compiler.tool_name())
        .join(&run_timestamp);
    let rendered = report::render(&report);
    println!("{rendered}");
    if saved_artifacts {
        println!(
            "[WARN] Issues detected! Artifacts generated at: {}.",
            artifacts_dir.display()
        );
        // Save report to artifacts.
        let report_path = artifacts_dir.join(format!("sbpf_test_report_{run_timestamp}.txt"));
        if let Err(error) = fs::write(&report_path, rendered) {
            eprintln!("warning: failed to write report.txt: {error}");
        }
    }
    Ok(())
}

fn cargo() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

fn command_error(command: &str, output: &Output) -> Box<dyn Error> {
    invalid_data(format!(
        "`{command}` failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

pub struct Benchmark {
    name: String,
}

impl Benchmark {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn run(
        self,
        mollusk: &Mollusk,
        instruction: &Instruction,
        accounts: &[(Pubkey, Account)],
    ) -> Result<BenchmarkResult, BenchmarkError> {
        validate_name(&self.name).map_err(BenchmarkError::InvalidBenchmarkName)?;

        let result = mollusk.process_instruction(instruction, accounts);

        let error = result
            .raw_result
            .as_ref()
            .err()
            .map(|error| error.to_string());

        Ok(BenchmarkResult {
            name: self.name,
            compute_units: result.compute_units_consumed,
            error,
        })
    }
}

#[derive(Debug)]
pub enum BenchmarkError {
    InvalidBenchmarkName(String),
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBenchmarkName(message) => formatter.write_str(message),
        }
    }
}

impl Error for BenchmarkError {}

pub(crate) fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(format!(
            "benchmark name `{name}` must contain only ASCII letters, digits, `-`, or `_`"
        ));
    }
    Ok(())
}
