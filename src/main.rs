use argh::FromArgs;
use std::io::Read;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;
use std::net::TcpStream;
use std::thread::JoinHandle;
use rustls::RootCertStore;
use rustls::OwnedTrustAnchor;

#[cfg(test)]
mod tests;

mod locations;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

static CLOUDFLARE_SPEEDTEST_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down?measId=0";
static CLOUDFLARE_SPEEDTEST_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up?measId=0";
static CLOUDFLARE_SPEEDTEST_SERVER_URL: &str =
    "https://speed.cloudflare.com/__down?measId=0&bytes=0";
static CLOUDFLARE_SPEEDTEST_CGI_URL: &str = "https://speed.cloudflare.com/cdn-cgi/trace";
static OUR_USER_AGENT: &str = "cf_speedtest (0.3.9) https://github.com/12932/cf_speedtest";

static CONNECT_TIMEOUT_MILLIS: u64 = 9600;

impl std::io::Read for UploadHelper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // upload is finished, or we are exiting
        if self.byte_ctr.load(Ordering::SeqCst) >= self.bytes_to_send
            || self.exit_signal.load(Ordering::SeqCst)
        {
            // dbg!("Exiting");
            return Ok(0);
        }

        // fill the buffer with 1s
        for byte in buf.iter_mut() {
            *byte = 1;
        }

        self.byte_ctr.fetch_add(buf.len(), Ordering::SeqCst);
        self.total_uploaded_counter
            .fetch_add(buf.len(), Ordering::SeqCst);
        Ok(buf.len())
    }
}

struct UploadHelper {
    bytes_to_send: usize,
    byte_ctr: Arc<AtomicUsize>,
    total_uploaded_counter: Arc<AtomicUsize>,
    exit_signal: Arc<AtomicBool>,
}

#[derive(FromArgs, Clone)]
/// A speedtest CLI written in Rust
struct UserArgs {
    /// how many download threads to use (default 4)
    #[argh(option, default = "4")]
    download_threads: usize,

    /// how many upload threads to use (default 4)
    #[argh(option, default = "4")]
    upload_threads: usize,

	/// when set, only run the download test
	#[argh(switch, short = 'd')]
    download_only: bool,

	/// when set, only run the upload test
    #[argh(switch, short = 'u')]
    upload_only: bool,

	/// the amount of bytes to download in a single request (default 50MB)
	#[argh(option, default = "50 * 1024 * 1024")]
    bytes_to_download: usize,

    /// the amount of bytes to upload in a single request (default 50MB)
	#[argh(option, default = "50 * 1024 * 1024")]
    bytes_to_upload: usize,
}

impl UserArgs {
    fn validate(&self) -> Result<()> {
        if self.download_only && self.upload_only {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot specify both --download-only and --upload-only. Please only specify one.",
            )))
        } else {
            Ok(())
        }
    }
}


fn get_secs_since_unix_epoch() -> usize {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();

    since_the_epoch.as_secs() as usize
}

/* Given n bytes, return
 	a: unit of measurement in sensible form of bytes
 	b: unit of measurement in sensible form of bits
 i.e 12939428 -> (12.34 MB, 98.76 Mb)
 		 814811 -> (795.8 KB, 6.36 Mb)
 basically, the BYTE value should always be greater than 1
 and never more than 1024. the bit value should just be calculated off
 the byte value
*/
fn get_appropriate_byte_unit(bytes: u64) -> (String, String) {
    const UNITS: [&str; 5] = ["", "K", "M", "G", "T"];
    const KILOBYTE: f64 = 1024.0;

    let mut bytes = bytes as f64;
    let mut level = 0;

    while bytes >= KILOBYTE && level < UNITS.len() - 1 {
        bytes /= KILOBYTE;
        level += 1;
    }

    let byte_unit = UNITS[level];
    let mut bits = bytes * 8.0;
    let mut bit_unit = byte_unit.to_ascii_lowercase();

    if bits >= 1000.0 {
        bits /= 1000.0;
        bit_unit = match byte_unit {
            "" => "k",
            "K" => "m",
            "M" => "g",
            "G" => "t",
            "T" => "p",
            _ => "?",
        }.to_string();
    }

    (
        format!("{:.2} {}B", bytes, byte_unit),
        format!("{:.2} {}b", bits, bit_unit),
    )
}


fn get_appropriate_buff_size(speed: usize) -> u64 {
    match speed {
        0..=1000 => 4,
        1001..=10000 => 32,
        10001..=100000 => 512,
        100001..=1000000 => 4096,
        1000001.. => 16384,
        _ => 16384,
    }
}

// Use cloudflare's cdn-cgi endpoint to get our ip address country
// (they use Maxmind)
fn get_our_ip_address_country() -> Result<String> {
    let resp = ureq::get(CLOUDFLARE_SPEEDTEST_CGI_URL).call()?;
    let mut body = String::new();
    resp.into_reader().read_to_string(&mut body)?;

    for line in body.lines() {
        if let Some(loc) = line.strip_prefix("loc=") {
            return Ok(loc.to_string());
        }
    }

    panic!(
        "Could not find loc= in cdn-cgi response\n
			Please update to the latest version and make a Github issue if the issue persists"
    );
}

// Get http latency by requesting the cgi endpoint 8 times
// and taking the fastest
fn get_download_server_http_latency() -> Result<std::time::Duration> {
    let start = Instant::now();
    let my_agent = ureq::AgentBuilder::new().build();
    let mut latency_vec = Vec::new();

    for _ in 0..8 {
        // if vec length 2 or greater and we've spent a lot of time
        // calculating latency, exit early
        if latency_vec.len() >= 2 && start.elapsed() > std::time::Duration::from_secs(1) {
            break;
        }

        let now = Instant::now();
        let _response = my_agent
            .get(CLOUDFLARE_SPEEDTEST_CGI_URL)
            .set("accept-encoding", "mcdonalds") // https://github.com/algesten/ureq/issues/549
            .call()?
            .into_string()?;

        let total_time = now.elapsed();
        latency_vec.push(total_time);
    }

    let best_time = latency_vec.iter().min().unwrap().to_owned();
    Ok(best_time)
}

// return all cloufdlare headers from a request
fn get_download_server_info() -> Result<std::collections::HashMap<String, String>> {
    let mut server_headers = std::collections::HashMap::new();
    let resp = ureq::get(CLOUDFLARE_SPEEDTEST_SERVER_URL)
        .call()
        .expect("Failed to get server info");

    for key in resp.headers_names() {
        if key.starts_with("cf-") {
            server_headers.insert(key.clone(), resp.header(&key).unwrap().to_string());
        }
    }

    Ok(server_headers)
}

// send cloudflare some bytes
fn upload_test(
    bytes: usize,
    total_up_bytes_counter: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let my_agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_millis(CONNECT_TIMEOUT_MILLIS))
        .redirects(0)
        .build();

    loop {
        let upload_helper = UploadHelper {
            bytes_to_send: bytes,
            byte_ctr: Arc::new(AtomicUsize::new(0)),
            total_uploaded_counter: total_up_bytes_counter.clone(),
            exit_signal: exit_signal.clone(),
        };

        let resp = match my_agent
            .post(CLOUDFLARE_SPEEDTEST_UPLOAD_URL)
            .set("Content-Type", "text/plain;charset=UTF-8")
            .set("User-Agent", OUR_USER_AGENT)
            .send(upload_helper)
        {
            Ok(resp) => resp,
            Err(err) => {
                eprintln!("Error in upload thread: {err}");
                return Ok(());
            }
        };

        // read the POST response body into the void if response is okay
        let _ = std::io::copy(&mut resp.into_reader(), &mut std::io::sink());

        if exit_signal.load(Ordering::Relaxed) {
            return Ok(());
        }
    }
}

fn upload_test_no_decrypt(
    bytes: usize,
    total_up_bytes_counter: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    let my_slick_cipher_suites = vec![rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
	
    let tls_config = rustls::ClientConfig::builder()
        .with_cipher_suites(&my_slick_cipher_suites)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    let my_agent = ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls_config))
        .timeout_connect(std::time::Duration::from_millis(CONNECT_TIMEOUT_MILLIS))
        .redirects(0)
        .build();

    loop {
        let upload_helper = UploadHelper {
            bytes_to_send: bytes,
            byte_ctr: Arc::new(AtomicUsize::new(0)),
            total_uploaded_counter: total_up_bytes_counter.clone(),
            exit_signal: exit_signal.clone(),
        };

        let resp = match my_agent
            .post(CLOUDFLARE_SPEEDTEST_UPLOAD_URL)
            .set("Content-Type", "text/plain;charset=UTF-8")
            .set("User-Agent", OUR_USER_AGENT)
            .send(upload_helper)
        {
            Ok(resp) => resp,
            Err(err) => {
                eprintln!("Error in upload thread: {err}");
                return Ok(());
            }
        };

        // read the POST response body into the void if response is okay
        let _ = std::io::copy(&mut resp.into_reader(), &mut std::io::sink());

        if exit_signal.load(Ordering::Relaxed) {
            return Ok(());
        }
    }
}

// download some bytes from cloudflare
fn download_test(
    bytes: usize,
    total_bytes_counter: &Arc<AtomicUsize>,
    current_down_speed: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    let my_slick_cipher_suites = vec![rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
	
    let tls_config = rustls::ClientConfig::builder()
        .with_cipher_suites(&my_slick_cipher_suites)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    let my_agent = ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls_config))
        .timeout_connect(std::time::Duration::from_millis(CONNECT_TIMEOUT_MILLIS))
        .redirects(0)
        .build();

    let resp = match my_agent
        .get(format!("{CLOUDFLARE_SPEEDTEST_DOWNLOAD_URL}&bytes={bytes}").as_str())
        .set("User-Agent", OUR_USER_AGENT)
        .call()
    {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("Error in download thread: {err}");
            return Ok(());
        }
    };

    let mut resp_reader = resp.into_reader();
    let mut total_bytes_sank: usize = 0;

    loop {
        // exit if we have passed deadline
        if exit_signal.load(Ordering::Relaxed) {
            return Ok(());
        }

        // if we are fast, take big chunks
        // if we are slow, take small chunks
        let current_down_speed = current_down_speed.load(Ordering::Relaxed);
        let current_recv_buff = get_appropriate_buff_size(current_down_speed);

        // copy bytes into the void
        let bytes_sank = std::io::copy(
            &mut resp_reader.by_ref().take(current_recv_buff),
            &mut std::io::sink(),
        )? as usize;

        if bytes_sank == 0 {
            if total_bytes_sank == 0 {
                panic!("Cloudflare is sending us empty responses?!")
            }

            return Ok(());
        }

        total_bytes_sank += bytes_sank;
        total_bytes_counter.fetch_add(bytes_sank, Ordering::SeqCst);
    }
}

fn print_test_preamble() {
    let now = chrono::Local::now();
    println!(
        "{:<32} {} {}",
        "Start:",
        now.format("%Y-%m-%d %H:%M:%S"),
        now.format("%Z")
    );

    let iata_mapping = locations::generate_iata_to_city_map();
    let country_mapping = locations::generate_cca2_to_full_country_name_map();

    let our_country = get_our_ip_address_country().expect("Couldn't get our country");
    let our_country_full = country_mapping.get(&our_country as &str);
    let latency = get_download_server_http_latency().expect("Couldn't get server latency");
    let headers = get_download_server_info().expect("Couldn't get download server info");

    let unknown_colo = &"???".to_owned();
    let unknown_colo_info = &("UNKNOWN", "UNKNOWN");
    let cf_colo = headers.get("cf-meta-colo").unwrap_or(unknown_colo);
    let colo_info = iata_mapping
        .get(cf_colo as &str)
        .unwrap_or(unknown_colo_info);

    println!(
        "{:<32} {}",
        "Your Location:",
        our_country_full.unwrap_or(&"UNKNOWN")
    );
    println!(
        "{:<32} {} - {}, {}",
        "Server Location:",
        cf_colo,
        colo_info.0,
        country_mapping.get(colo_info.1).unwrap_or(&"UNKNOWN")
    );

    println!("{:<32} {:.2}ms\n", "Latency (HTTP):", latency.as_millis());
}

fn spawn_download_threads(
	config: &UserArgs, 
	total_downloaded_bytes_counter: &Arc<AtomicUsize>, 
	current_down_speed: &Arc<AtomicUsize>, 
	exit_signal: &Arc<AtomicBool>) -> Vec<JoinHandle<()>> 
{
	let mut download_threads = vec![];

	for i in 0..config.download_threads {
		let total_downloaded_bytes_counter = Arc::clone(&total_downloaded_bytes_counter.clone());
        let current_down_clone = Arc::clone(&current_down_speed.clone());
        let exit_signal_clone = Arc::clone(&exit_signal.clone());
		let config_clone = config.clone();
        let handle = std::thread::spawn(move || {
            if i > 0 {
                // sleep a little to hit a new cloudflare metal
                // (each metal will throttle to 1 gigabit)
                std::thread::sleep(std::time::Duration::from_millis(
                    (i * 250).try_into().unwrap(),
                ));
            }

            loop {
                match download_test(
                    config_clone.bytes_to_download,
                    &total_downloaded_bytes_counter,
                    &current_down_clone,
                    &exit_signal_clone,
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Error in download test thread {i}: {e:?}");
                        return;
                    }
                }

                // exit if we have passed the deadline
                if exit_signal_clone.load(Ordering::Relaxed) {
                    // println!("Thread {} exiting...", i);
                    return;
                }
            }
		});
		download_threads.push(handle);
    }

	download_threads
}

fn main() {
    let config: UserArgs = argh::from_env();

    print_test_preamble();

    let total_downloaded_bytes_counter = Arc::new(AtomicUsize::new(0));
    let total_uploaded_bytes_counter = Arc::new(AtomicUsize::new(0));

    let current_down_speed = Arc::new(AtomicUsize::new(0));

    // these are just the file sizes of our upload/download http requests
    // the tests are duration-based not size-based
    const BYTES_TO_UPLOAD: usize = 50 * 1024 * 1024;
    const BYTES_TO_DOWNLOAD: usize = 50 * 1024 * 1024;
     let exit_signal = Arc::new(AtomicBool::new(false));

    if !config.upload_only
    {
        let down_deadline = get_secs_since_unix_epoch() + 12;
       
        let down_handles = spawn_download_threads(&config, &total_downloaded_bytes_counter, &current_down_speed, &exit_signal);

        let mut last_bytes_down = 0;
        total_downloaded_bytes_counter.store(0, Ordering::SeqCst);
        let mut down_measurements = vec![];
        // print download speed
        loop {
            let bytes_down = total_downloaded_bytes_counter.load(Ordering::Relaxed);
            let bytes_down_diff = bytes_down - last_bytes_down;

            // set current_down
            current_down_speed.store(bytes_down_diff, Ordering::SeqCst);
            down_measurements.push(bytes_down_diff);

            let speed_values = get_appropriate_byte_unit(bytes_down_diff as u64);
            // only print progress if we are before deadline
            if get_secs_since_unix_epoch() < down_deadline {
                println!(
                    "Download: {byte_speed:>12.*}/s {bit_speed:>14.*}it/s",
                    16,
                    16,
                    byte_speed = speed_values.0,
                    bit_speed = speed_values.1
                );
            }
            io::stdout().flush().unwrap();

            // if we need to spawn more threads, do it here
            std::thread::sleep(std::time::Duration::from_millis(1000));

            last_bytes_down = bytes_down;

            // exit if we have passed the deadline
            if get_secs_since_unix_epoch() > down_deadline {
                exit_signal.store(true, Ordering::SeqCst);
                break;
            }
        }

        println!("Waiting for download threads to finish...");
        for handle in down_handles {
            handle.join().expect("Couldn't join download thread");
        }
    }


    if !config.download_only
    {
        // re-use exit_signal for upload tests
        exit_signal.store(false, Ordering::SeqCst);

        println!("Starting upload tests...");
        let up_deadline = get_secs_since_unix_epoch() + 12;

        let function_to_call = upload_test_no_decrypt;

        // spawn x uploader threads
        let mut up_handles = vec![];
        for i in 0..config.upload_threads {
            let total_bytes_uploaded_counter = Arc::clone(&total_uploaded_bytes_counter);
            let exit_signal_clone = Arc::clone(&exit_signal);
            let handle = std::thread::spawn(move || {
                loop {
                    match function_to_call(
                        BYTES_TO_UPLOAD,
                        &total_bytes_uploaded_counter,
                        &exit_signal_clone,
                    ) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("Error in upload test thread {i}: {e:?}");
                        }
                    }

                    // exit if we have passed the deadline
                    if get_secs_since_unix_epoch() > up_deadline {
                        return;
                    }
                }
            });
            up_handles.push(handle);
        }

        let mut last_bytes_up = 0;
        let mut up_measurements = vec![];
        total_uploaded_bytes_counter.store(0, Ordering::SeqCst);
        // print total bytes downloaded in a loop
        loop {
            let bytes_up = total_uploaded_bytes_counter.load(Ordering::Relaxed);

            let bytes_up_diff = bytes_up - last_bytes_up;
            up_measurements.push(bytes_up_diff);

            let speed_values = get_appropriate_byte_unit(bytes_up_diff as u64);

            println!(
                "Upload: {byte_speed:>14.*}/s {bit_speed:>14.*}it/s",
                16,
                16,
                byte_speed = speed_values.0,
                bit_speed = speed_values.1
            );

            std::thread::sleep(std::time::Duration::from_millis(1000));

            last_bytes_up = bytes_up;

            // exit if we have passed the deadline
            if get_secs_since_unix_epoch() > up_deadline {
                exit_signal.store(true, Ordering::SeqCst);
                break;
            }
        }

        // wait for upload threads to finish
        println!("Waiting for upload threads to finish...");
        for handle in up_handles {
            handle.join().expect("Couldn't join upload thread");
        }

    }

    println!("Work complete!");
}
