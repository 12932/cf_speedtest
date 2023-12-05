use comfy_table::{presets::UTF8_FULL, Cell, Table};
use std::io::Read;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;
use ureq::Agent;
use ureq::AgentBuilder;

mod args;
use args::UserArgs;

mod locations;
#[cfg(test)]
mod tests;
mod tls;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

static CLOUDFLARE_SPEEDTEST_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down?measId=0";
static CLOUDFLARE_SPEEDTEST_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up?measId=0";
static CLOUDFLARE_SPEEDTEST_SERVER_URL: &str =
    "https://speed.cloudflare.com/__down?measId=0&bytes=0";
static CLOUDFLARE_SPEEDTEST_CGI_URL: &str = "https://speed.cloudflare.com/cdn-cgi/trace";
static OUR_USER_AGENT: &str = "cf_speedtest (0.4.6) https://github.com/12932/cf_speedtest";

static CONNECT_TIMEOUT_MILLIS: u64 = 9600;
static LATENCY_TEST_COUNT: u8 = 8;
static NEW_METAL_SLEEP_MILLIS: u32 = 250;

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

struct UploadHelper {
    bytes_to_send: usize,
    byte_ctr: Arc<AtomicUsize>,
    total_uploaded_counter: Arc<AtomicUsize>,
    exit_signal: Arc<AtomicBool>,
}

fn get_secs_since_unix_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
        format!("{:.2} {}B", bytes, byte_unit),
        format!("{:.2} {}b", bits, bit_unit),
    )
}

fn get_appropriate_byte_unit_rate(bytes: u64) -> (String, String) {
    let (a, b) = get_appropriate_byte_unit(bytes);
    (format!("{}/s", a), format!("{}it/s", b))
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

// Use cloudflare's cdn-cgi endpoint to get our ip address country
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

    for _ in 0..LATENCY_TEST_COUNT {
        // if vec length 2 or greater and we've spent a lot of time
        // calculating latency, exit early (we could be on satellite or sumthin)
        if latency_vec.len() >= 2 && start.elapsed() > std::time::Duration::from_secs(1) {
            break;
        }

        let now = Instant::now();
        let _response = my_agent
            .get(CLOUDFLARE_SPEEDTEST_CGI_URL)
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

fn get_current_timestamp() -> String {
    let now = chrono::Local::now();

    format!("{} {}", now.format("%Y-%m-%d %H:%M:%S"), now.format("%Z"))
}

//
fn upload_test(
    bytes: usize,
    total_up_bytes_counter: &Arc<AtomicUsize>,
    _current_speed: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let custom_connector = tls::InterceptingTlsConnector::new();

    let agent: Agent = AgentBuilder::new()
        .tls_connector(Arc::new(custom_connector))
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

        let resp = match agent
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
    bytes_to_request: usize,
    total_bytes_counter: &Arc<AtomicUsize>,
    current_down_speed: &Arc<AtomicUsize>,
    exit_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let custom_connector = tls::InterceptingTlsConnector::new();

    let agent: Agent = AgentBuilder::new()
        .tls_connector(Arc::new(custom_connector))
        .timeout_connect(std::time::Duration::from_millis(CONNECT_TIMEOUT_MILLIS))
        .redirects(0)
        .build();

    let resp = match agent
        .get(format!("{CLOUDFLARE_SPEEDTEST_DOWNLOAD_URL}&bytes={bytes_to_request}").as_str())
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
        let current_recv_buff =
            get_appropriate_buff_size(current_down_speed.load(Ordering::Relaxed));

        // copy bytes into the void
        let bytes_sank = std::io::copy(
            &mut resp_reader.by_ref().take(current_recv_buff),
            &mut std::io::sink(),
        )? as usize;

        //println!("Thread {:?} sank {} bytes", std::thread::current().id(), bytes_sank);

        if bytes_sank == 0 {
            if total_bytes_sank == 0 {
                eprintln!("Cloudflare sent an empty response?");
            }

            return Ok(());
        }

        total_bytes_sank += bytes_sank;
        total_bytes_counter.fetch_add(bytes_sank, Ordering::SeqCst);
    }
}

fn print_test_preamble() {
    println!("{:<32} {}", "Start:", get_current_timestamp());

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

    for i in 0..threads_to_spawn {
        let target_test_clone = Arc::clone(&target_test);
        let total_downloaded_bytes_counter = Arc::clone(&total_bytes_counter.clone());
        let current_down_clone = Arc::clone(&current_speed.clone());
        let exit_signal_clone = Arc::clone(&exit_signal.clone());
        let handle = std::thread::spawn(move || {
            if i > 0 {
                // sleep a little to hit a new cloudflare metal
                // (each metal will throttle to 1 gigabit)
                std::thread::sleep(std::time::Duration::from_millis(
                    (i * NEW_METAL_SLEEP_MILLIS).try_into().unwrap(),
                ));
            }

            loop {
                match target_test_clone(
                    bytes_to_request,
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
        thread_handles.push(handle);
    }

    thread_handles
}

fn run_download_test(config: &UserArgs) -> Vec<usize> {
    let total_downloaded_bytes_counter = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));

    exit_signal.store(false, Ordering::SeqCst);
    let current_down_speed = Arc::new(AtomicUsize::new(0));
    let down_deadline = get_secs_since_unix_epoch() + get_test_time(config.test_duration_seconds, config.download_threads);

    let target_test = Arc::new(download_test);
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
        let bytes_down = total_downloaded_bytes_counter.load(Ordering::Relaxed);
        let bytes_down_diff = bytes_down - last_bytes_down;

        // set current_down
        current_down_speed.store(bytes_down_diff, Ordering::SeqCst);
        down_measurements.push(bytes_down_diff);

        let speed_values = get_appropriate_byte_unit(bytes_down_diff as u64);
        // only print progress if we are before deadline
        if get_secs_since_unix_epoch() < down_deadline {
            println!(
                "Download: {bit_speed:>12.*}it/s       ({byte_speed:>10.*}/s)",
                16,
                16,
                byte_speed = speed_values.0,
                bit_speed = speed_values.1
            );
        }
        io::stdout().flush().unwrap();
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

    down_measurements
}

fn run_upload_test(config: &UserArgs) -> Vec<usize> {
    let exit_signal = Arc::new(AtomicBool::new(false));
    let total_uploaded_bytes_counter = Arc::new(AtomicUsize::new(0));
    let current_up_speed = Arc::new(AtomicUsize::new(0));
    // re-use exit_signal for upload tests
    exit_signal.store(false, Ordering::SeqCst);

    let up_deadline = get_secs_since_unix_epoch() + get_test_time(config.test_duration_seconds, config.upload_threads);

    let target_test = Arc::new(upload_test);
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
        let bytes_up = total_uploaded_bytes_counter.load(Ordering::Relaxed);

        let bytes_up_diff = bytes_up - last_bytes_up;
        up_measurements.push(bytes_up_diff);

        let speed_values = get_appropriate_byte_unit(bytes_up_diff as u64);

        println!(
            "Upload:   {bit_speed:>12.*}it/s       ({byte_speed:>10.*}/s)",
            16,
            16,
            byte_speed = speed_values.0,
            bit_speed = speed_values.1
        );

        io::stdout().flush().unwrap();
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

    up_measurements
}

fn compute_statistics(data: &mut Vec<usize>) -> (f64, f64, usize, usize, usize, usize) {
    if data.is_empty() {
        return (0f64, 0f64, 0, 0, 0, 0);
    }

    data.sort();

    let len = data.len();
    let sum: usize = data.iter().sum();
    let average = sum as f64 / len as f64;

    let median = if len % 2 == 0 {
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

fn main() {
    let config: UserArgs = argh::from_env();
    config.validate().expect("Invalid arguments");

    print_test_preamble();

    let mut down_measurements: Vec<usize> = Vec::new();
    let mut up_measurements: Vec<usize> = Vec::new();

    if !config.upload_only {
        down_measurements = run_download_test(&config);
    }

    if !config.download_only {
        println!("Starting upload tests...");
        up_measurements = run_upload_test(&config);
    }

    let (download_median, download_avg, download_p90, _, _, _) =
        compute_statistics(&mut down_measurements);
    let (upload_median, upload_avg, upload_p90, _, _, _) = compute_statistics(&mut up_measurements);

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(""),
            Cell::new("Median"),
            Cell::new("Average"),
            Cell::new("90th pctile"),
        ]);

    // Populate rows based on computed statistics
    table.add_row(vec![
        Cell::new("Download"),
        Cell::new(get_appropriate_byte_unit_rate(download_median as u64).1),
        Cell::new(get_appropriate_byte_unit_rate(download_avg as u64).1),
        Cell::new(get_appropriate_byte_unit_rate(download_p90 as u64).1),
    ]);

    table.add_row(vec![
        Cell::new("Upload"),
        Cell::new(get_appropriate_byte_unit_rate(upload_median as u64).1),
        Cell::new(get_appropriate_byte_unit_rate(upload_avg as u64).1),
        Cell::new(get_appropriate_byte_unit_rate(upload_p90 as u64).1),
    ]);

    print!("\n{}\n{}\n", get_current_timestamp(), table);
}
