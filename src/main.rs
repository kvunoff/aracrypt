mod pe;
mod crypto;
mod fasm;

use clap::Parser;
use std::path::PathBuf;
use std::process;

const ASCII_LOGO: &str = r"
    ___                    _____                  _
   / _ \                  / ____|                | |
  / /_\ \_ __ __ _  ___ _| |     _ __ _   _ _ __ | |_
 / /_\ \ '__/ _` |/ __| | |    | '__| | | | '_ \| __|
/ _____ \ | | (_| | (__| |____| |  | |_| | |_) | |_
\/_/   \_\|  \__,_|\___|\_____|_|   \__, | .__/ \__|
                                     __/ | |
                                    |___/|_|
";

#[derive(Parser)]
#[command(
    name = "aracrypt",
    version,
    about = "PE Encryptor for Linux — encrypts Windows PE executables into self-decrypting containers.",
    long_about = format!("{}\nPE Encryptor for Linux — encrypts Windows PE executables into self-decrypting containers.\nRequires FASM (flat assembler) to be installed.\n\nBased on Hyperion by Christian Ammann (nullsecurity team).", ASCII_LOGO),
)]
struct Cli {
    #[arg(help = "Input PE (.exe) file")]
    input: PathBuf,

    #[arg(help = "Output encrypted executable")]
    output: PathBuf,

    #[arg(
        short = 'k',
        long = "key-length",
        default_value = "6",
        value_parser = clap::value_parser!(u16).range(1..=16),
        help = "AES key length in bytes (1-16)"
    )]
    key_length: u16,

    #[arg(
        short = 's',
        long = "key-space",
        default_value = "4",
        value_parser = clap::value_parser!(u16).range(2..=255),
        help = "Key byte value range, 0 to N-1 (2-255)"
    )]
    key_space: u16,

    #[arg(
        short = 'l',
        long = "logfile",
        help = "Generate log.txt at runtime for debugging"
    )]
    logfile: bool,

    #[arg(short = 'v', long = "verbose", help = "Verbose output")]
    verbose: bool,
}

fn msg_status(text: &str) {
    println!("\x1b[34m[*]\x1b[0m {}", text);
}

fn msg_success(text: &str) {
    println!("\x1b[32m[+]\x1b[0m {}", text);
}

fn msg_error(text: &str) {
    eprintln!("\x1b[31m[!]\x1b[0m {}", text);
}

fn msg_verbose(text: &str, verbose: bool) {
    if verbose {
        println!("\x1b[90m    {}\x1b[0m", text);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    if !fasm::check_fasm_installed() {
        msg_error("FASM (flat assembler) not found in PATH.");
        eprintln!();
        eprintln!("Install FASM to compile self-decrypting loaders:");
        eprintln!("  Debian/Ubuntu:  sudo apt install fasm");
        eprintln!("  Arch:           sudo pacman -S fasm");
        eprintln!("  Fedora:         sudo dnf install fasm");
        eprintln!("  Or download from: https://flatassembler.net");
        return Err("FASM not installed".into());
    }

    if !cli.input.exists() {
        return Err(format!("Input file not found: {}", cli.input.display()));
    }

    msg_status(&format!("Analyzing input file: {}", cli.input.display()));

    let input_data = std::fs::read(&cli.input)
        .map_err(|e| format!("Cannot read input file: {}", e))?;

    let pe_data = pe::parse_pe(&input_data).ok_or("PE parsing failed")?;

    let bits = if pe_data.is_64bit { "64" } else { "32" };
    let subsys = if pe_data.is_gui { "GUI" } else { "console" };
    msg_success(&format!(
        "Found {}-bit PE, ImageBase: 0x{:x}, SizeOfImage: 0x{:x}, Subsystem: {}",
        bits, pe_data.image_base, pe_data.size_of_image, subsys
    ));

    if !pe_data.is_64bit {
        msg_status("32-bit support is deprecated, use with caution");
    }

    msg_status(&format!(
        "Encrypting with AES-128-ECB (key: {} bytes, space: {} values)...",
        cli.key_length, cli.key_space
    ));

    let (key, encrypted) = crypto::encrypt_file(&input_data, cli.key_length as usize, cli.key_space as u8);

    msg_success(&format!("Checksum: 0x{:08x}", crypto::get_checksum(&input_data)));
    msg_success(&format!(
        "Original data: {} bytes | Encrypted: {} bytes (padded to AES block)",
        input_data.len(),
        encrypted.len()
    ));

    if cli.verbose {
        let key_str: String = key
            .iter()
            .take(cli.key_length as usize)
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        msg_verbose(&format!("AES key: {}", key_str), cli.verbose);
    }

    msg_status("Generating self-decrypting loader...");

    let ctx = fasm::FasmContext::new(pe_data.is_64bit);

    ctx.clean_generated()
        .map_err(|e| format!("Cannot clean generated files: {}", e))?;

    ctx.write_header(pe_data.is_gui)
        .map_err(|e| format!("Cannot write header: {}", e))?;
    msg_verbose("Written main_prolog.inc", cli.verbose);

    ctx.write_encrypted_output(&encrypted, input_data.len())
        .map_err(|e| format!("Cannot write encrypted output: {}", e))?;
    msg_verbose("Written infile_array.inc + infile_size.inc", cli.verbose);

    ctx.write_define(fasm::IMAGE_BASE_FILENAME, "IMAGE_BASE", pe_data.image_base, false)
        .map_err(|e| format!("Cannot write image base: {}", e))?;
    msg_verbose(&format!("Written image base: 0x{:x}", pe_data.image_base), cli.verbose);

    ctx.write_define(fasm::IMAGE_SIZE_FILENAME, "IMAGE_SIZE", pe_data.size_of_image as u64, false)
        .map_err(|e| format!("Cannot write image size: {}", e))?;

    ctx.write_define(fasm::KEY_SIZE_FILENAME, "REAL_KEY_SIZE", cli.key_length as u64, false)
        .map_err(|e| format!("Cannot write key size: {}", e))?;

    ctx.write_define(fasm::KEY_SIZE_FILENAME, "REAL_KEY_RANGE", cli.key_space as u64, true)
        .map_err(|e| format!("Cannot write key range: {}", e))?;
    msg_verbose("Written key_size.inc", cli.verbose);

    ctx.write_logfile_select(cli.logfile)
        .map_err(|e| format!("Cannot write logfile select: {}", e))?;
    msg_verbose("Written logfile_select.asm", cli.verbose);

    let has_resources = pe_data.resources.is_some();
    if let Some(ref resources) = pe_data.resources {
        ctx.write_resource_output(resources)
            .map_err(|e| format!("Cannot write resource output: {}", e))?;
        msg_verbose(&format!("Written resources: {} bytes", resources.len()), cli.verbose);
    }
    ctx.write_resource_select(has_resources)
        .map_err(|e| format!("Cannot write resource select: {}", e))?;
    msg_verbose("Written resource_select.asm", cli.verbose);

    ctx.write_decryption_includes()
        .map_err(|e| format!("Cannot write decryption includes: {}", e))?;
    msg_verbose("Written decryption_includes.asm", cli.verbose);

    msg_status("Compiling with FASM...");

    let failed = fasm::compile_container(pe_data.is_64bit, &cli.output, cli.verbose)
        .map_err(|e| format!("FASM invocation failed: {}", e))?;

    if failed {
        msg_error("FASM returned an error");

        if !cli.verbose {
            eprintln!("[*] Re-run with -v to see FASM output");
        }

        ctx.clean_generated()
            .map_err(|e| format!("Cleanup failed: {}", e))?;
        return Err("FASM compilation failed".into());
    }

    msg_success(&format!(
        "Final executable: {} ({} bytes)",
        cli.output.display(),
        std::fs::metadata(&cli.output)
            .map(|m| m.len().to_string())
            .unwrap_or_else(|_| "?".into())
    ));

    ctx.clean_generated()
        .map_err(|e| format!("Cleanup failed: {}", e))?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        msg_error(&e);
        process::exit(1);
    }
}
