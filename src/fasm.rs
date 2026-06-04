use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTAINER32_DIR: &str = "stub/Container/32";
const CONTAINER64_DIR: &str = "stub/Container/64";

pub const MAIN_PROLOG_FILENAME: &str = "main_prolog.inc";
pub const IMAGE_BASE_FILENAME: &str = "image_base.inc";
pub const IMAGE_SIZE_FILENAME: &str = "image_size.inc";
pub const INFILE_ARRAY_FILENAME: &str = "infile_array.inc";
pub const INFILE_SIZE_FILENAME: &str = "infile_size.inc";
pub const KEY_SIZE_FILENAME: &str = "key_size.inc";
const LOGFILE_SELECT_FILENAME: &str = "logfile_select.asm";
const DECRYPTION_INCLUDES_FILENAME: &str = "decryption_includes.asm";
const CONTAINER_MAIN_FILENAME: &str = "main.asm";
pub const RESOURCE_ARRAY_FILENAME: &str = "resource.inc";
const RESOURCE_SELECT_FILENAME: &str = "resource_select.asm";

const LOG_ENABLE_FILENAME: &str = "logfile_enable.asm";
const LOG_DISABLE_FILENAME: &str = "logfile_disable.asm";

const AES32_DIR: &str = "../../Aes/32";
const AES64_DIR: &str = "../../Aes/64";
const AES_INC_FILENAME: &str = "aes.inc";
const AES_ASM_FILENAME: &str = "aes.asm";
const AES_DECRYPTION_FILENAME: &str = "decryptexecutable.asm";

pub fn container_dir(is_64bit: bool) -> &'static str {
    if is_64bit { CONTAINER64_DIR } else { CONTAINER32_DIR }
}

pub struct FasmContext {
    pub dir: PathBuf,
    pub is_64bit: bool,
}

impl FasmContext {
    pub fn new(is_64bit: bool) -> Self {
        let dir = PathBuf::from(container_dir(is_64bit));
        FasmContext { dir, is_64bit }
    }

    pub fn write_header(&self, is_gui: bool) -> std::io::Result<()> {
        let mut content = String::new();
        if self.is_64bit {
            content.push_str("format PE64 ");
        } else {
            content.push_str("format PE ");
        }

        if is_gui {
            content.push_str("GUI ");
        } else {
            content.push_str("console ");
        }

        if self.is_64bit {
            content.push_str("5.0 at IMAGE_BASE\n");
        } else {
            content.push_str("4.0 at IMAGE_BASE\n");
        }

        let path = self.dir.join(MAIN_PROLOG_FILENAME);
        fs::write(&path, &content)
    }

    pub fn write_define(&self, filename: &str, label: &str, value: u64, append: bool) -> std::io::Result<()> {
        let content = format!("{} equ 0x{:x}\n", label, value);
        let path = self.dir.join(filename);

        if append {
            let mut file = fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(content.as_bytes())?;
        } else {
            fs::write(&path, &content)?;
        }
        Ok(())
    }

    pub fn write_include(&self, filename: &str, include_label: &str, append: bool) -> std::io::Result<()> {
        let content = format!("include '{}'\n", include_label);
        let path = self.dir.join(filename);

        if append {
            let mut file = fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(content.as_bytes())?;
        } else {
            fs::write(&path, &content)?;
        }
        Ok(())
    }

    pub fn write_encrypted_output(
        &self,
        encrypted: &[u8],
        _original_size: usize,
    ) -> std::io::Result<()> {
        self.write_define(INFILE_SIZE_FILENAME, "INFILE_SIZE", encrypted.len() as u64, false)?;

        let mut fasm_output = String::from("db ");
        for (i, &byte) in encrypted.iter().enumerate() {
            if i != 0 {
                if i % 10 == 0 {
                    fasm_output.push_str("\\\n");
                }
                fasm_output.push_str(", ");
            }
            fasm_output.push_str(&format!("0x{:x}", byte));
        }
        fasm_output.push('\n');

        let path = self.dir.join(INFILE_ARRAY_FILENAME);
        fs::write(&path, &fasm_output)?;
        Ok(())
    }

    pub fn write_decryption_includes(&self) -> std::io::Result<()> {
        let aes_dir = if self.is_64bit { AES64_DIR } else { AES32_DIR };

        let aes_inc = format!("{}/{}", aes_dir, AES_INC_FILENAME);
        let aes_asm = format!("{}/{}", aes_dir, AES_ASM_FILENAME);
        let decr_asm = format!("{}/{}", aes_dir, AES_DECRYPTION_FILENAME);

        self.write_include(DECRYPTION_INCLUDES_FILENAME, &aes_inc, false)?;
        self.write_include(DECRYPTION_INCLUDES_FILENAME, &aes_asm, true)?;
        self.write_include(DECRYPTION_INCLUDES_FILENAME, &decr_asm, true)?;
        Ok(())
    }

    pub fn write_logfile_select(&self, enable_log: bool) -> std::io::Result<()> {
        let label = if enable_log { LOG_ENABLE_FILENAME } else { LOG_DISABLE_FILENAME };
        self.write_include(LOGFILE_SELECT_FILENAME, label, false)
    }

    pub fn write_resource_output(&self, resources: &[u8]) -> std::io::Result<()> {
        let mut fasm_output = String::from("db ");
        for (i, &byte) in resources.iter().enumerate() {
            if i != 0 {
                if i % 10 == 0 {
                    fasm_output.push_str("\\\n");
                }
                fasm_output.push_str(", ");
            }
            fasm_output.push_str(&format!("0x{:x}", byte));
        }
        fasm_output.push('\n');

        let path = self.dir.join(RESOURCE_ARRAY_FILENAME);
        fs::write(&path, &fasm_output)
    }

    pub fn write_resource_select(&self, has_resources: bool) -> std::io::Result<()> {
        let path = self.dir.join(RESOURCE_SELECT_FILENAME);
        if has_resources {
            fs::write(&path, "section '.rsrc' data readable resource\n    include 'resource.inc'\n")
        } else {
            fs::write(&path, "; no resources in original PE\n")
        }
    }

    pub fn clean_generated(&self) -> std::io::Result<()> {
        let files = [
            MAIN_PROLOG_FILENAME,
            IMAGE_BASE_FILENAME,
            IMAGE_SIZE_FILENAME,
            INFILE_ARRAY_FILENAME,
            INFILE_SIZE_FILENAME,
            KEY_SIZE_FILENAME,
            LOGFILE_SELECT_FILENAME,
            DECRYPTION_INCLUDES_FILENAME,
            RESOURCE_ARRAY_FILENAME,
            RESOURCE_SELECT_FILENAME,
        ];
        for f in &files {
            let path = self.dir.join(f);
            if path.exists() {
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

pub fn compile_container(
    is_64bit: bool,
    output_path: &Path,
    verbose: bool,
) -> std::io::Result<bool> {
    let dir = container_dir(is_64bit);
    let main_asm = format!("{}/{}", dir, CONTAINER_MAIN_FILENAME);

    if verbose {
        let status = Command::new("fasm")
            .arg("-m")
            .arg("524288")
            .arg(&main_asm)
            .arg(output_path)
            .status()?;
        Ok(!status.success())
    } else {
        let output = Command::new("fasm")
            .arg("-m")
            .arg("524288")
            .arg(&main_asm)
            .arg(output_path)
            .output()?;
        if !output.status.success() {
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        }
        Ok(!output.status.success())
    }
}

pub fn check_fasm_installed() -> bool {
    Command::new("fasm")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok()
}
