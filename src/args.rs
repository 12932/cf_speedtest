use argh::FromArgs;

use super::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsCipher {
    Chacha20Poly1305,
    Aes128Gcm,
}

impl std::str::FromStr for TlsCipher {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "chacha20" | "chacha20poly1305" => Ok(TlsCipher::Chacha20Poly1305),
            "aes128" | "aes128gcm" => Ok(TlsCipher::Aes128Gcm),
            other => Err(format!(
                "unknown cipher '{other}' (valid: chacha20, aes128)"
            )),
        }
    }
}

#[derive(FromArgs, Clone)]
/// A speedtest CLI written in Rust
pub struct UserArgs {
    /// how many download threads to use (default 8)
    #[argh(option, default = "8")]
    pub download_threads: u32,

    /// how many upload threads to use (default 8)
    #[argh(option, default = "8")]
    pub upload_threads: u32,

    /// when set, only run the download test
    #[argh(switch, short = 'd')]
    pub download_only: bool,

    /// when set, only run the upload test
    #[argh(switch, short = 'u')]
    pub upload_only: bool,

    /// the amount of bytes to download in a single request (default 100MB)
    #[argh(option, default = "100 * 1024 * 1024")]
    pub bytes_to_download: usize,

    /// the amount of bytes to upload in a single request (default 50MB)
    #[argh(option, default = "50 * 1024 * 1024")]
    pub bytes_to_upload: usize,

    /// how many seconds to run each upload/download test for (default 12)
    #[argh(option, default = "12")]
    pub test_duration_seconds: u64,

    /// output format: json or csv (default: human-readable)
    #[argh(option)]
    pub format: Option<String>,

    /// when set, omit the header row from CSV output
    #[argh(switch)]
    pub no_header: bool,

    /// base URL of the speedtest server (default https://speedtest.obscenegaming.net)
    #[argh(
        option,
        default = "String::from(\"https://speedtest.obscenegaming.net\")"
    )]
    pub server: String,

    /// TLS cipher: chacha20 (default, CPU-constant) or aes128 (faster on AES-NI hosts)
    #[argh(option, default = "String::from(\"chacha20\")")]
    pub cipher: String,
}

impl UserArgs {
    pub fn validate(&mut self) -> Result<()> {
        if self.download_only && self.upload_only {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot specify both --download-only and --upload-only",
            )));
        }
        if let Some(ref mut fmt) = self.format {
            *fmt = fmt.to_ascii_lowercase();
            if fmt != "json" && fmt != "csv" {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid format. Supported formats: json, csv",
                )));
            }
        }
        // raw_socket.rs requires https:// for the TLS bypass download path
        let trimmed = self.server.trim_end_matches('/');
        if !trimmed.starts_with("https://") {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--server must start with https:// (raw download path requires TLS)",
            )));
        }
        self.server = trimmed.to_string();

        // validate the cipher string parses (we still re-parse on demand via cipher())
        if let Err(msg) = self.cipher.parse::<TlsCipher>() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                msg,
            )));
        }
        Ok(())
    }

    pub fn cipher(&self) -> TlsCipher {
        // validate() guarantees this parses
        self.cipher.parse().expect("cipher validated")
    }
}
