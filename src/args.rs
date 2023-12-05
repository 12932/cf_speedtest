use argh::FromArgs;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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

    /// the amount of bytes to download in a single request (default 50MB)
    #[argh(option, default = "50 * 1024 * 1024")]
    pub bytes_to_download: usize,

    /// the amount of bytes to upload in a single request (default 50MB)
    #[argh(option, default = "50 * 1024 * 1024")]
    pub bytes_to_upload: usize,

    /// how many seconds to run each upload/download test for (default 12)
    #[argh(option, default = "12")]
    pub test_duration_seconds: u64,
}

impl UserArgs {
    pub fn validate(&self) -> Result<()> {
        if self.download_only && self.upload_only {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot specify both --download-only and --upload-only",
            )))
        } else {
            Ok(())
        }
    }
}
