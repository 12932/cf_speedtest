use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use ureq::Agent;

static CTRL_C_PRESSED: AtomicBool = AtomicBool::new(false);

static OUR_USER_AGENT: &str = concat!(
    "cf_speedtest (",
    env!("CARGO_PKG_VERSION"),
    ") https://github.com/12932/cf_speedtest"
);

static CONNECT_TIMEOUT_MILLIS: u64 = 9600;
static LATENCY_TEST_COUNT: u8 = 8;
static NEW_METAL_SLEEP_MILLIS: u64 = 250;
// Upper bound on total ramp-up time. We pick a per-thread stagger of
// TARGET_TOTAL_STAGGER_MS / threads, clamped to [MIN, NEW_METAL_SLEEP_MILLIS].
static TARGET_TOTAL_STAGGER_MS: u64 = 4000;
static MIN_STAGGER_MS: u64 = 20;

mod args;
use args::{TlsCipher, UserArgs};

mod agent;
use crate::agent::create_configured_agent;

mod raw_socket;

mod locations;
mod table;
#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Default)]
struct TestResults {
    down_measurements: Vec<usize>,
    up_measurements: Vec<usize>,
    download_completed: bool,
    upload_completed: bool,
}

struct PreambleData {
    timestamp: String,
    user_country_full: String,
    server_iata: String,
    server_city: String,
    server_country: String,
    latency: Duration,
    jitter: Duration,
}

struct SpeedtestResult {
    timestamp: String,
    server_iata: String,
    server_city: String,
    server_country: String,
    user_country: String,
    latency_ms: f64,
    jitter_ms: f64,
    download_median_bps: u64,
    download_avg_bps: u64,
    download_p90_bps: u64,
    upload_median_bps: u64,
    upload_avg_bps: u64,
    upload_p90_bps: u64,
}

impl SpeedtestResult {
    fn bps_to_mbps(bps: u64) -> f64 {
        bps as f64 * 8.0 / 1_000_000.0
    }
}

struct UploadHelper {
    bytes_to_send: usize,
    byte_ctr: Arc<AtomicUsize>,
    total_uploaded_counter: Arc<AtomicUsize>,
    exit_signal: Arc<AtomicBool>,
}

impl std::io::Read for UploadHelper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // upload is finished, or we are exiting
        if self.byte_ctr.load(Ordering::SeqCst) >= self.bytes_to_send
            || self.exit_signal.load(Ordering::SeqCst)
        {
            return Ok(0);
        }

        buf.fill(1);

        self.byte_ctr.fetch_add(buf.len(), Ordering::SeqCst);
        self.total_uploaded_counter
            .fetch_add(buf.len(), Ordering::SeqCst);
        Ok(buf.len())
    }
}

// Default test duration + a little bit more if we have extra threads
fn get_test_time(test_duration_seconds: u64, thread_count: u32) -> u64 {
    if thread_count > 4 {
        return test_duration_seconds + (thread_count as u64 - 4) / 4;
    }

    test_duration_seconds
}

/* Given n bytes, return
     a: unit of measurement in sensible form of bytes
     b: unit of measurement in sensible form of bits
 i.e 12939428 	-> (12.34 MB, 98.76 Mb)
     814811 	-> (795.8 KB, 6.36 Mb)
*/
fn get_appropriate_byte_unit(bytes: u64) -> (String, String) {
    const UNITS: [&str; 5] = [" ", "K", "M", "G", "T"];
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
            " " => "k",
            "K" => "m",
            "M" => "g",
            "G" => "t",
            "T" => "p",
            _ => "?",
        }
        .to_string();
    }

    (
        format!("{bytes:.2} {byte_unit}B"),
        format!("{bits:.2} {bit_unit}b"),
    )
}

fn get_appropriate_byte_unit_rate(bytes: u64) -> (String, String) {
    let (a, b) = get_appropriate_byte_unit(bytes);
    (format!("{a}/s"), format!("{b}it/s"))
}

fn get_appropriate_buff_size(speed: usize) -> u64 {
    match speed {
        0..=1000 => 4,
        1001..=10000 => 32,
        10001..=100000 => 512,
        100001..=1000000 => 4096,
        _ => 16384,
    }
}

/// Extract a JSON string value by key, e.g. extract_json_string(json, "country") for "country":"AU"
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let end = start + json[start..].find('"')?;
    Some(json[start..end].to_string())
}

/// Returns (user_country, colo_iata) from the /meta endpoint
fn get_meta_info(server: &str, cipher: TlsCipher) -> Result<(String, String)> {
    let agent = create_configured_agent(cipher);
    let resp = agent
        .get(format!("{server}/meta"))
        .header("Referer", format!("{server}/"))
        .call()?;
    let body: String = resp.into_body().read_to_string()?;

    let country = extract_json_string(&body, "country");
    // colo is nested: "colo":{"iata":"PER",...}
    let colo_iata = body
        .find("\"colo\":{")
        .and_then(|pos| extract_json_string(&body[pos..], "iata"));

    match (country, colo_iata) {
        (Some(c), Some(i)) => Ok((c, i)),
        _ => Err("Could not parse /meta response. \
            Please update to the latest version and make a Github issue if the issue persists"
            .into()),
    }
}

// Compute jitter: mean absolute difference between consecutive latency samples
// Skips the first sample (TLS handshake warmup)
fn compute_jitter(latency_samples: &[Duration]) -> Duration {
    if latency_samples.len() <= 2 {
        return Duration::ZERO;
    }
    let samples = &latency_samples[1..];
    let diffs = samples.windows(2).map(|w| w[1].abs_diff(w[0]));
    let count = samples.len() - 1;
    let total: Duration = diffs.sum();
    total / count as u32
}

// Get http latency and jitter by requesting the cgi endpoint 8 times
// Latency = fastest sample, Jitter = mean absolute difference between consecutive samples (skipping first)
fn get_latency_and_jitter(server: &str, cipher: TlsCipher) -> Result<(Duration, Duration)> {
    let start = Instant::now();

    let my_agent = create_configured_agent(cipher);
    let cgi_url = format!("{server}/cdn-cgi/trace");
    let mut latency_vec = Vec::new();

    for _ in 0..LATENCY_TEST_COUNT {
        // if vec length 2 or greater and we've spent a lot of time
        // 	calculating latency, exit early (we could be on satellite or sumthin)
        if latency_vec.len() >= 2 && start.elapsed() > Duration::from_secs(1) {
            break;
        }

        let now = Instant::now();

        let _response = my_agent.get(&cgi_url).call()?.body_mut().read_to_string();

        let total_time = now.elapsed();
        latency_vec.push(total_time);
    }

    let best_time = latency_vec.iter().min().unwrap().to_owned();
    let jitter = compute_jitter(&latency_vec);

    Ok((best_time, jitter))
}

fn get_current_timestamp() -> String {
    let now = chrono::Local::now();

    format!("{} {}", now.format("%Y-%m-%d %H:%M:%S"), now.format("%Z"))
}

fn upload_test(
    server: &str,
    cipher: TlsCipher,
    bytes: usize,
    total_up_bytes_counter: &Arc<AtomicUsize>,
    _current_speed: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let agent: Agent = create_configured_agent(cipher);
    let upload_url = format!("{server}/__up?measId=0");

    loop {
        let upload_helper = UploadHelper {
            bytes_to_send: bytes,
            byte_ctr: Arc::new(AtomicUsize::new(0)),
            total_uploaded_counter: total_up_bytes_counter.clone(),
            exit_signal: exit_signal.clone(),
        };

        let body = ureq::SendBody::from_owned_reader(upload_helper);

        let resp = match agent
            .post(&upload_url)
            .header("Content-Type", "text/plain;charset=UTF-8")
            .send(body)
        {
            Ok(resp) => resp,
            Err(err) => {
                if !CTRL_C_PRESSED.load(Ordering::Relaxed) {
                    eprintln!("Error in upload thread: {err}");
                }
                return Ok(());
            }
        };

        // Process the response
        let _ = std::io::copy(&mut resp.into_body().into_reader(), &mut std::io::sink());

        if exit_signal.load(Ordering::Relaxed) {
            return Ok(());
        }
    }
}

// download some bytes from the speedtest server using raw encrypted byte reading
fn download_test(
    server: &str,
    cipher: TlsCipher,
    bytes_to_request: usize,
    total_bytes_counter: &Arc<AtomicUsize>,
    current_down_speed: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let download_url = format!("{server}/__down?measId=0");
    // Keep making new requests until exit_signal is set
    loop {
        // exit if we have passed deadline
        if exit_signal.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Establish connection, perform TLS handshake, send HTTP request
        let mut conn = match raw_socket::RawDownloadConnection::connect(
            &download_url,
            bytes_to_request,
            cipher,
        ) {
            Ok(conn) => conn,
            Err(err) => {
                if !CTRL_C_PRESSED.load(Ordering::Relaxed) {
                    eprintln!("Error in download thread: {err}");
                }
                return Ok(());
            }
        };

        let mut total_bytes_sank: usize = 0;
        let mut buf = vec![0u8; 16384]; // pre-allocate at max buffer size

        // Read from this connection until it's exhausted
        loop {
            // exit if we have passed deadline
            if exit_signal.load(Ordering::Relaxed) {
                return Ok(());
            }

            // if we are fast, take big chunks
            // if we are slow, take small chunks
            let current_recv_buff =
                get_appropriate_buff_size(current_down_speed.load(Ordering::Relaxed)) as usize;

            // Read raw encrypted bytes directly from socket (no TLS decryption!)
            let bytes_read = match conn.read_encrypted_bytes(&mut buf[..current_recv_buff]) {
                Ok(n) => n,
                Err(err) => {
                    if !CTRL_C_PRESSED.load(Ordering::Relaxed) {
                        eprintln!("Error reading from socket: {err}");
                    }
                    // Connection error, break to create a new connection
                    break;
                }
            };

            if bytes_read == 0 {
                if total_bytes_sank == 0 {
                    eprintln!("Cloudflare sent an empty response?");
                }
                // Connection exhausted, break inner loop to make a new request
                break;
            }

            // Count the encrypted bytes we received (wire bytes including TLS overhead)
            total_bytes_sank += bytes_read;
            total_bytes_counter.fetch_add(bytes_read, Ordering::SeqCst);
        }
    }
}

fn collect_preamble_data(server: &str, cipher: TlsCipher) -> PreambleData {
    let timestamp = get_current_timestamp();
    let (user_country, server_iata) =
        get_meta_info(server, cipher).expect("Couldn't get meta info");
    let user_country_full = locations::CCA2_TO_COUNTRY_NAME
        .get(&user_country as &str)
        .unwrap_or(&"UNKNOWN")
        .to_string();
    let (latency, jitter) =
        get_latency_and_jitter(server, cipher).expect("Couldn't get server latency");

    let unknown_colo_info = ("UNKNOWN", "UNKNOWN");
    let colo_info = locations::IATA_TO_CITY_COUNTRY
        .get(&server_iata as &str)
        .unwrap_or(&unknown_colo_info);

    let server_city = colo_info.0.to_string();
    let server_country = locations::CCA2_TO_COUNTRY_NAME
        .get(colo_info.1)
        .unwrap_or(&"UNKNOWN")
        .to_string();

    PreambleData {
        timestamp,
        user_country_full,
        server_iata,
        server_city,
        server_country,
        latency,
        jitter,
    }
}

fn print_preamble(data: &PreambleData) {
    println!(
        "{:<32} cf_speedtest v{}",
        "Version:",
        env!("CARGO_PKG_VERSION")
    );
    println!("{:<32} {}", "Start:", data.timestamp);
    println!("{:<32} {}", "Your Location:", data.user_country_full);
    println!(
        "{:<32} {} - {}, {}",
        "Server Location:", data.server_iata, data.server_city, data.server_country
    );
    println!("{:<32} {}ms", "Latency (HTTP):", data.latency.as_millis());
    println!("{:<32} {}ms\n", "Jitter (HTTP):", data.jitter.as_millis());
}

// Spawn a given amount of threads to run a specific test
fn spawn_test_threads<F>(
    threads_to_spawn: u32,
    target_test: Arc<F>,
    bytes_to_request: usize,
    total_bytes_counter: &Arc<AtomicUsize>,
    current_speed: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Vec<JoinHandle<()>>
where
    F: Fn(
            usize,
            &Arc<AtomicUsize>,
            &Arc<AtomicUsize>,
            &Arc<AtomicBool>,
        ) -> std::result::Result<(), Box<dyn std::error::Error>>
        + Send
        + Sync
        + 'static,
{
    let mut thread_handles = vec![];

    let per_thread_stagger_ms = (TARGET_TOTAL_STAGGER_MS / threads_to_spawn.max(1) as u64)
        .clamp(MIN_STAGGER_MS, NEW_METAL_SLEEP_MILLIS);

    for i in 0..threads_to_spawn {
        let target_test_clone = Arc::clone(&target_test);
        let total_downloaded_bytes_counter = Arc::clone(total_bytes_counter);
        let current_down_clone = Arc::clone(current_speed);
        let exit_signal_clone = Arc::clone(exit_signal);
        let handle = std::thread::spawn(move || {
            if i > 0 {
                // sleep a little so each connection lands on a new cloudflare metal
                // (each metal throttles to ~1 gigabit per flow)
                std::thread::sleep(std::time::Duration::from_millis(
                    i as u64 * per_thread_stagger_ms,
                ));
            }

            match target_test_clone(
                bytes_to_request,
                &total_downloaded_bytes_counter,
                &current_down_clone,
                &exit_signal_clone,
            ) {
                Ok(_) => {}
                Err(e) => {
                    if !CTRL_C_PRESSED.load(Ordering::Relaxed) {
                        eprintln!("Error in test thread {i}: {e:?}");
                    }
                }
            }
        });
        thread_handles.push(handle);
    }

    thread_handles
}

fn run_download_test(config: &UserArgs, results: Arc<Mutex<TestResults>>, quiet: bool) {
    let total_downloaded_bytes_counter = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));
    let current_down_speed = Arc::new(AtomicUsize::new(0));
    let down_deadline = Instant::now()
        + Duration::from_secs(get_test_time(
            config.test_duration_seconds,
            config.download_threads,
        ));

    let server = config.server.clone();
    let cipher = config.cipher();
    let target_test = Arc::new(
        move |bytes: usize,
              total: &Arc<AtomicUsize>,
              speed: &Arc<AtomicUsize>,
              exit: &Arc<AtomicBool>|
              -> Result<()> { download_test(&server, cipher, bytes, total, speed, exit) },
    );
    let down_handles = spawn_test_threads(
        config.download_threads,
        target_test,
        config.bytes_to_download,
        &total_downloaded_bytes_counter,
        &current_down_speed,
        &exit_signal,
    );

    let mut last_bytes_down = 0;
    total_downloaded_bytes_counter.store(0, Ordering::SeqCst);
    let mut down_measurements = vec![];

    // Calculate and print download speed
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));

        // exit if we have passed the deadline
        if Instant::now() > down_deadline {
            exit_signal.store(true, Ordering::SeqCst);
            break;
        }

        let bytes_down = total_downloaded_bytes_counter.load(Ordering::Relaxed);
        let bytes_down_diff = bytes_down.saturating_sub(last_bytes_down);

        // set current_down
        current_down_speed.store(bytes_down_diff, Ordering::SeqCst);
        down_measurements.push(bytes_down_diff);

        // Update shared results
        results
            .lock()
            .expect("Results lock poisoned, please try re-running")
            .down_measurements = down_measurements.clone();

        if !quiet {
            let speed_values = get_appropriate_byte_unit(bytes_down_diff as u64);
            println!(
                "Download: {bit_speed:>12.*}it/s       ({byte_speed:>10.*}/s)",
                16,
                16,
                byte_speed = speed_values.0,
                bit_speed = speed_values.1
            );
            io::stdout().flush().unwrap();
        }
        last_bytes_down = bytes_down;
    }

    if !quiet {
        println!("Waiting for download threads to finish...");
    }
    for handle in down_handles {
        handle.join().expect("Couldn't join download thread");
    }

    // Mark download as completed
    if let Ok(mut shared_results) = results.lock() {
        shared_results.down_measurements = down_measurements;
        shared_results.download_completed = true;
    }
}

fn run_upload_test(config: &UserArgs, results: Arc<Mutex<TestResults>>, quiet: bool) {
    let exit_signal = Arc::new(AtomicBool::new(false));
    let total_uploaded_bytes_counter = Arc::new(AtomicUsize::new(0));
    let current_up_speed = Arc::new(AtomicUsize::new(0));

    let up_deadline = Instant::now()
        + Duration::from_secs(get_test_time(
            config.test_duration_seconds,
            config.upload_threads,
        ));

    let server = config.server.clone();
    let cipher = config.cipher();
    let target_test = Arc::new(
        move |bytes: usize,
              total: &Arc<AtomicUsize>,
              speed: &Arc<AtomicUsize>,
              exit: &Arc<AtomicBool>|
              -> Result<()> { upload_test(&server, cipher, bytes, total, speed, exit) },
    );
    let up_handles = spawn_test_threads(
        config.upload_threads,
        target_test,
        config.bytes_to_upload,
        &total_uploaded_bytes_counter,
        &current_up_speed,
        &exit_signal,
    );

    let mut last_bytes_up = 0;
    let mut up_measurements = vec![];
    total_uploaded_bytes_counter.store(0, Ordering::SeqCst);

    // Calculate and print upload speed
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));

        // exit if we have passed the deadline
        if Instant::now() > up_deadline {
            exit_signal.store(true, Ordering::SeqCst);
            break;
        }

        let bytes_up = total_uploaded_bytes_counter.load(Ordering::Relaxed);

        let bytes_up_diff = bytes_up.saturating_sub(last_bytes_up);
        up_measurements.push(bytes_up_diff);

        // Update shared results
        results
            .lock()
            .expect("Results lock poisoned, please try re-running")
            .up_measurements = up_measurements.clone();

        if !quiet {
            let speed_values = get_appropriate_byte_unit(bytes_up_diff as u64);

            println!(
                "Upload:   {bit_speed:>12.*}it/s       ({byte_speed:>10.*}/s)",
                16,
                16,
                byte_speed = speed_values.0,
                bit_speed = speed_values.1
            );

            io::stdout().flush().unwrap();
        }
        last_bytes_up = bytes_up;
    }

    // wait for upload threads to finish
    if !quiet {
        println!("Waiting for upload threads to finish...");
    }
    for handle in up_handles {
        handle.join().expect("Couldn't join upload thread");
    }

    // Mark upload as completed
    if let Ok(mut shared_results) = results.lock() {
        shared_results.up_measurements = up_measurements;
        shared_results.upload_completed = true;
    }
}

fn compute_statistics(data: &mut [usize]) -> (f64, f64, usize, usize, usize, usize) {
    if data.is_empty() {
        return (0f64, 0f64, 0, 0, 0, 0);
    }

    data.sort();

    let len = data.len();
    let sum: usize = data.iter().sum();
    let average = sum as f64 / len as f64;

    let median = if len.is_multiple_of(2) {
        (data[len / 2 - 1] + data[len / 2]) as f64 / 2.0
    } else {
        data[len / 2] as f64
    };

    let p90_index = (0.90 * len as f64).ceil() as usize - 1;
    let p99_index = (0.99 * len as f64).ceil() as usize - 1;

    let min = data[0];
    let max = *data.last().unwrap();

    (median, average, data[p90_index], data[p99_index], min, max)
}

fn print_results_table(results: &TestResults) {
    let mut down_measurements = results.down_measurements.clone();
    let mut up_measurements = results.up_measurements.clone();

    let (download_median, download_avg, download_p90, _, _, _) =
        compute_statistics(&mut down_measurements);
    let (upload_median, upload_avg, upload_p90, _, _, _) = compute_statistics(&mut up_measurements);

    let mut rows = vec![vec![
        "".to_string(),
        "Median".to_string(),
        "Average".to_string(),
        "90th pctile".to_string(),
    ]];

    // Populate rows based on computed statistics
    if results.download_completed || !results.down_measurements.is_empty() {
        rows.push(vec![
            "DOWN".to_string(),
            get_appropriate_byte_unit_rate(download_median as u64).1,
            get_appropriate_byte_unit_rate(download_avg as u64).1,
            get_appropriate_byte_unit_rate(download_p90 as u64).1,
        ]);
    }

    if results.upload_completed || !results.up_measurements.is_empty() {
        rows.push(vec![
            "UP".to_string(),
            get_appropriate_byte_unit_rate(upload_median as u64).1,
            get_appropriate_byte_unit_rate(upload_avg as u64).1,
            get_appropriate_byte_unit_rate(upload_p90 as u64).1,
        ]);
    }

    let table = table::format_ascii_table(rows);
    print!("\n{}\n{}\n", get_current_timestamp(), table);
}

fn build_speedtest_result(preamble: &PreambleData, results: &TestResults) -> SpeedtestResult {
    let mut down = results.down_measurements.clone();
    let mut up = results.up_measurements.clone();

    let (down_median, down_avg, down_p90, _, _, _) = compute_statistics(&mut down);
    let (up_median, up_avg, up_p90, _, _, _) = compute_statistics(&mut up);

    SpeedtestResult {
        timestamp: preamble.timestamp.clone(),
        server_iata: preamble.server_iata.clone(),
        server_city: preamble.server_city.clone(),
        server_country: preamble.server_country.clone(),
        user_country: preamble.user_country_full.clone(),
        latency_ms: preamble.latency.as_secs_f64() * 1000.0,
        jitter_ms: preamble.jitter.as_secs_f64() * 1000.0,
        download_median_bps: down_median as u64,
        download_avg_bps: down_avg as u64,
        download_p90_bps: down_p90 as u64,
        upload_median_bps: up_median as u64,
        upload_avg_bps: up_avg as u64,
        upload_p90_bps: up_p90 as u64,
    }
}

fn print_json_results(r: &SpeedtestResult) {
    println!(
        r#"{{
  "version": "cf_speedtest {}",
  "timestamp": "{}",
  "server_iata": "{}",
  "server_city": "{}",
  "server_country": "{}",
  "user_country": "{}",
  "latency_ms": {:.2},
  "jitter_ms": {:.2},
  "download_median_bps": {},
  "download_avg_bps": {},
  "download_p90_bps": {},
  "download_median_mbps": {:.2},
  "download_avg_mbps": {:.2},
  "download_p90_mbps": {:.2},
  "upload_median_bps": {},
  "upload_avg_bps": {},
  "upload_p90_bps": {},
  "upload_median_mbps": {:.2},
  "upload_avg_mbps": {:.2},
  "upload_p90_mbps": {:.2}
}}"#,
        env!("CARGO_PKG_VERSION"),
        r.timestamp,
        r.server_iata,
        r.server_city,
        r.server_country,
        r.user_country,
        r.latency_ms,
        r.jitter_ms,
        r.download_median_bps,
        r.download_avg_bps,
        r.download_p90_bps,
        SpeedtestResult::bps_to_mbps(r.download_median_bps),
        SpeedtestResult::bps_to_mbps(r.download_avg_bps),
        SpeedtestResult::bps_to_mbps(r.download_p90_bps),
        r.upload_median_bps,
        r.upload_avg_bps,
        r.upload_p90_bps,
        SpeedtestResult::bps_to_mbps(r.upload_median_bps),
        SpeedtestResult::bps_to_mbps(r.upload_avg_bps),
        SpeedtestResult::bps_to_mbps(r.upload_p90_bps),
    );
}

fn print_csv_results(r: &SpeedtestResult, no_header: bool) {
    if !no_header {
        println!("version,timestamp,server_iata,server_city,server_country,user_country,latency_ms,jitter_ms,download_median_bps,download_avg_bps,download_p90_bps,download_median_mbps,download_avg_mbps,download_p90_mbps,upload_median_bps,upload_avg_bps,upload_p90_bps,upload_median_mbps,upload_avg_mbps,upload_p90_mbps");
    }
    println!(
        "\"cf_speedtest {}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{:.2},{:.2},{},{},{},{:.2},{:.2},{:.2},{},{},{},{:.2},{:.2},{:.2}",
        env!("CARGO_PKG_VERSION"),
        r.timestamp,
        r.server_iata,
        r.server_city,
        r.server_country,
        r.user_country,
        r.latency_ms,
        r.jitter_ms,
        r.download_median_bps,
        r.download_avg_bps,
        r.download_p90_bps,
        SpeedtestResult::bps_to_mbps(r.download_median_bps),
        SpeedtestResult::bps_to_mbps(r.download_avg_bps),
        SpeedtestResult::bps_to_mbps(r.download_p90_bps),
        r.upload_median_bps,
        r.upload_avg_bps,
        r.upload_p90_bps,
        SpeedtestResult::bps_to_mbps(r.upload_median_bps),
        SpeedtestResult::bps_to_mbps(r.upload_avg_bps),
        SpeedtestResult::bps_to_mbps(r.upload_p90_bps),
    );
}

fn main() {
    let mut config: UserArgs = argh::from_env();
    config.validate().expect("Invalid arguments");

    let quiet = config.format.is_some();

    let results = Arc::new(Mutex::new(TestResults::default()));
    let results_clone = Arc::clone(&results);

    // Set up CTRL-C handler
    ctrlc::set_handler(move || {
        CTRL_C_PRESSED.store(true, Ordering::Relaxed);
        if !quiet {
            println!("\n\nReceived CTRL-C, printing current results...");
            if let Ok(current_results) = results_clone.lock() {
                print_results_table(&current_results);
            }
        }
        std::process::exit(0);
    })
    .expect("Error setting CTRL-C handler");

    // Collect preamble data (meta info, latency, jitter)
    let preamble = collect_preamble_data(&config.server, config.cipher());
    if !quiet {
        print_preamble(&preamble);
    }

    if !config.upload_only {
        run_download_test(&config, Arc::clone(&results), quiet);
    }

    if !config.download_only {
        if !quiet {
            println!("Starting upload tests...");
        }
        run_upload_test(&config, Arc::clone(&results), quiet);
    }

    // Output final results
    let final_results = results
        .lock()
        .expect("Results lock poisoned, please try re-running");

    match config.format.as_deref() {
        Some("json") => {
            let result = build_speedtest_result(&preamble, &final_results);
            print_json_results(&result);
        }
        Some("csv") => {
            let result = build_speedtest_result(&preamble, &final_results);
            print_csv_results(&result, config.no_header);
        }
        _ => {
            print_results_table(&final_results);
        }
    }
}
