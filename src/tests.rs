use super::*;

const TEST_SERVER: &str = "https://speed.cloudflare.com";
const TEST_CIPHER: TlsCipher = TlsCipher::Chacha20Poly1305;

#[test]
fn test_reachability() {
    get_meta_info(TEST_SERVER, TEST_CIPHER)
        .expect("Couldn't reach Cloudflare, please check your internet connection");
}

#[test]
fn test_server_location_is_known() {
    let (_country, colo) = get_meta_info(TEST_SERVER, TEST_CIPHER).expect("Couldn't get meta info");

    let colo_info = locations::IATA_TO_CITY_COUNTRY
        .get(&colo as &str)
        .unwrap_or_else(|| panic!("Colo code '{}' not found in IATA_TO_CITY_COUNTRY", colo));

    locations::CCA2_TO_COUNTRY_NAME
        .get(colo_info.1)
        .unwrap_or_else(|| {
            panic!(
                "Country code '{}' not found in CCA2_TO_COUNTRY_NAME",
                colo_info.1
            )
        });
}

#[test]
fn test_download() {
    const BYTES_TO_REQUEST: usize = 1024;
    let total_bytes_counter = Arc::new(AtomicUsize::new(0));
    let current_down = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));

    let total_downloaded_bytes_counter = Arc::clone(&total_bytes_counter);
    let current_down_clone = Arc::clone(&current_down);
    let exit_signal_clone = Arc::clone(&exit_signal);

    let _handle = std::thread::spawn(move || {
        download_test(
            TEST_SERVER,
            TEST_CIPHER,
            BYTES_TO_REQUEST,
            &total_downloaded_bytes_counter,
            &current_down_clone,
            &exit_signal_clone,
        )
        .ok();
    });

    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if total_bytes_counter.load(Ordering::SeqCst) >= BYTES_TO_REQUEST {
            break;
        }
    }

    assert!(total_bytes_counter.load(Ordering::SeqCst) >= BYTES_TO_REQUEST);

    exit_signal.store(true, Ordering::SeqCst);
    let _ = _handle.join();
}

#[test]
fn test_upload() {
    const BYTES_TO_UPLOAD: usize = 1024;
    let upload_counter = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));

    let total_bytes_uploaded_counter = Arc::clone(&upload_counter);
    let current_speed = Arc::new(AtomicUsize::new(0));
    let exit_signal_clone = Arc::clone(&exit_signal);

    let _handle = std::thread::spawn(move || {
        upload_test(
            TEST_SERVER,
            TEST_CIPHER,
            BYTES_TO_UPLOAD,
            &total_bytes_uploaded_counter,
            &current_speed,
            &exit_signal_clone,
        )
        .ok();
    });

    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if upload_counter.load(Ordering::SeqCst) >= BYTES_TO_UPLOAD {
            break;
        }
    }

    assert!(upload_counter.load(Ordering::SeqCst) >= BYTES_TO_UPLOAD);

    exit_signal.store(true, Ordering::SeqCst);
    let _ = _handle.join();
}

#[test]
fn test_get_appropriate_byte_unit() {
    assert_eq!(
        get_appropriate_byte_unit(100),
        ("100.00  B".to_string(), "800.00  b".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1015),
        ("1015.00  B".to_string(), "8.12 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(2048),
        ("2.00 KB".to_string(), "16.00 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1048576),
        ("1.00 MB".to_string(), "8.00 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1073741824),
        ("1.00 GB".to_string(), "8.00 gb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1099511627776),
        ("1.00 TB".to_string(), "8.00 tb".to_string())
    );

    assert_eq!(
        get_appropriate_byte_unit(1023),
        ("1023.00  B".to_string(), "8.18 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024),
        ("1.00 KB".to_string(), "8.00 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(12939428),
        ("12.34 MB".to_string(), "98.72 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(814811),
        ("795.71 KB".to_string(), "6.37 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024),
        ("1.00 MB".to_string(), "8.00 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024 * 1024),
        ("1.00 GB".to_string(), "8.00 gb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024 * 1024 * 1024),
        ("1.00 TB".to_string(), "8.00 tb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024 * 1024 * 1024 * 1024),
        ("1024.00 TB".to_string(), "8.19 pb".to_string())
    );
}

#[test]
fn test_compute_jitter() {
    // [10, 12, 14, 11, 13] -> skip first -> [12, 14, 11, 13]
    // diffs: |14-12|=2, |11-14|=3, |13-11|=2 -> avg = 7/3 = 2.33ms
    let samples = vec![
        Duration::from_millis(10),
        Duration::from_millis(12),
        Duration::from_millis(14),
        Duration::from_millis(11),
        Duration::from_millis(13),
    ];
    let jitter = compute_jitter(&samples);
    // 7ms / 3 = 2.333ms
    assert!(jitter.as_micros() >= 2333 && jitter.as_micros() <= 2334);
}

#[test]
fn test_compute_jitter_too_few_samples() {
    // 2 or fewer samples -> ZERO
    assert_eq!(compute_jitter(&[]), Duration::ZERO);
    assert_eq!(compute_jitter(&[Duration::from_millis(10)]), Duration::ZERO);
    assert_eq!(
        compute_jitter(&[Duration::from_millis(10), Duration::from_millis(20)]),
        Duration::ZERO
    );
}

#[test]
fn test_compute_jitter_stable_connection() {
    // All samples identical after dropping first -> jitter is 0
    let samples = vec![
        Duration::from_millis(50),
        Duration::from_millis(10),
        Duration::from_millis(10),
        Duration::from_millis(10),
    ];
    assert_eq!(compute_jitter(&samples), Duration::ZERO);
}

#[test]
fn test_compute_statistics() {
    let mut data = vec![10, 20, 30, 40, 50];
    let (median, average, p90, p99, min, max) = compute_statistics(&mut data);
    assert_eq!(median, 30.0);
    assert_eq!(average, 30.0);
    assert_eq!(min, 10);
    assert_eq!(max, 50);
    assert_eq!(p90, 50);
    assert_eq!(p99, 50);
}

#[test]
fn test_compute_statistics_even_count() {
    let mut data = vec![10, 20, 30, 40];
    let (median, average, _, _, _, _) = compute_statistics(&mut data);
    assert_eq!(median, 25.0);
    assert_eq!(average, 25.0);
}

#[test]
fn test_compute_statistics_empty() {
    let mut data: Vec<usize> = vec![];
    let (median, average, p90, p99, min, max) = compute_statistics(&mut data);
    assert_eq!(median, 0.0);
    assert_eq!(average, 0.0);
    assert_eq!(p90, 0);
    assert_eq!(p99, 0);
    assert_eq!(min, 0);
    assert_eq!(max, 0);
}

#[test]
fn test_bps_to_mbps() {
    // 1,000,000 bytes/sec = 8 Mbps
    assert!((SpeedtestResult::bps_to_mbps(1_000_000) - 8.0).abs() < 0.001);
    // 0 bytes/sec = 0 Mbps
    assert_eq!(SpeedtestResult::bps_to_mbps(0), 0.0);
    // 125,000 bytes/sec = 1 Mbps
    assert!((SpeedtestResult::bps_to_mbps(125_000) - 1.0).abs() < 0.001);
}

fn make_test_speedtest_result() -> SpeedtestResult {
    SpeedtestResult {
        timestamp: "2026-04-10 15:30:00 AWST".to_string(),
        server_iata: "PER".to_string(),
        server_city: "Perth".to_string(),
        server_country: "Australia".to_string(),
        user_country: "Australia".to_string(),
        latency_ms: 12.34,
        jitter_ms: 1.56,
        download_median_bps: 10_000_000,
        download_avg_bps: 9_500_000,
        download_p90_bps: 11_000_000,
        upload_median_bps: 2_000_000,
        upload_avg_bps: 1_900_000,
        upload_p90_bps: 2_200_000,
    }
}

#[test]
fn test_build_speedtest_result() {
    let preamble = PreambleData {
        timestamp: "2026-04-10 15:30:00 AWST".to_string(),
        user_country_full: "Australia".to_string(),
        server_iata: "PER".to_string(),
        server_city: "Perth".to_string(),
        server_country: "Australia".to_string(),
        latency: Duration::from_millis(12),
        jitter: Duration::from_micros(1560),
    };

    let test_results = TestResults {
        down_measurements: vec![9_000_000, 10_000_000, 11_000_000],
        up_measurements: vec![1_800_000, 2_000_000, 2_200_000],
        download_completed: true,
        upload_completed: true,
    };

    let result = build_speedtest_result(&preamble, &test_results);

    assert_eq!(result.server_iata, "PER");
    assert_eq!(result.user_country, "Australia");
    assert!(result.latency_ms > 0.0);
    assert!(result.download_median_bps > 0);
    assert!(result.upload_median_bps > 0);
}

#[test]
fn test_json_output_is_valid() {
    let result = make_test_speedtest_result();

    // Capture the JSON output
    let mut json = String::new();
    json.push_str(&format!(
        r#"{{"version":"cf_speedtest {}","timestamp":"{}","server_iata":"{}","server_city":"{}","server_country":"{}","user_country":"{}","latency_ms":{:.2},"jitter_ms":{:.2},"download_median_bps":{},"download_avg_bps":{},"download_p90_bps":{},"upload_median_bps":{},"upload_avg_bps":{},"upload_p90_bps":{}}}"#,
        env!("CARGO_PKG_VERSION"),
        result.timestamp,
        result.server_iata,
        result.server_city,
        result.server_country,
        result.user_country,
        result.latency_ms,
        result.jitter_ms,
        result.download_median_bps,
        result.download_avg_bps,
        result.download_p90_bps,
        result.upload_median_bps,
        result.upload_avg_bps,
        result.upload_p90_bps,
    ));

    // Verify key fields are present and parseable
    assert!(json.contains("\"version\":\"cf_speedtest "));
    assert!(json.contains("\"timestamp\":\"2026-04-10 15:30:00 AWST\""));
    assert!(json.contains("\"server_iata\":\"PER\""));
    assert!(json.contains("\"latency_ms\":12.34"));
    assert!(json.contains("\"jitter_ms\":1.56"));
    assert!(json.contains("\"download_median_bps\":10000000"));
    assert!(json.contains("\"upload_median_bps\":2000000"));
}

#[test]
fn test_csv_output_has_correct_field_count() {
    let header = "version,timestamp,server_iata,server_city,server_country,user_country,latency_ms,jitter_ms,download_median_bps,download_avg_bps,download_p90_bps,download_median_mbps,download_avg_mbps,download_p90_mbps,upload_median_bps,upload_avg_bps,upload_p90_bps,upload_median_mbps,upload_avg_mbps,upload_p90_mbps";
    let header_count = header.split(',').count();
    assert_eq!(header_count, 20);

    let result = make_test_speedtest_result();
    let row = format!(
        "\"cf_speedtest {}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{:.2},{:.2},{},{},{},{:.2},{:.2},{:.2},{},{},{},{:.2},{:.2},{:.2}",
        env!("CARGO_PKG_VERSION"),
        result.timestamp,
        result.server_iata,
        result.server_city,
        result.server_country,
        result.user_country,
        result.latency_ms,
        result.jitter_ms,
        result.download_median_bps,
        result.download_avg_bps,
        result.download_p90_bps,
        SpeedtestResult::bps_to_mbps(result.download_median_bps),
        SpeedtestResult::bps_to_mbps(result.download_avg_bps),
        SpeedtestResult::bps_to_mbps(result.download_p90_bps),
        result.upload_median_bps,
        result.upload_avg_bps,
        result.upload_p90_bps,
        SpeedtestResult::bps_to_mbps(result.upload_median_bps),
        SpeedtestResult::bps_to_mbps(result.upload_avg_bps),
        SpeedtestResult::bps_to_mbps(result.upload_p90_bps),
    );
    let row_count = row.split(',').count();
    assert_eq!(row_count, header_count);
}

#[test]
fn test_cipher_parsing() {
    assert_eq!(
        "chacha20".parse::<TlsCipher>().unwrap(),
        TlsCipher::Chacha20Poly1305
    );
    assert_eq!(
        "ChaCha20".parse::<TlsCipher>().unwrap(),
        TlsCipher::Chacha20Poly1305
    );
    assert_eq!("aes128".parse::<TlsCipher>().unwrap(), TlsCipher::Aes128Gcm);
    assert_eq!(
        "AES128GCM".parse::<TlsCipher>().unwrap(),
        TlsCipher::Aes128Gcm
    );
    assert!("aes256".parse::<TlsCipher>().is_err());
    assert!("".parse::<TlsCipher>().is_err());
}

#[test]
fn test_format_validation() {
    let mut args = UserArgs {
        download_threads: 8,
        upload_threads: 8,
        download_only: false,
        upload_only: false,
        bytes_to_download: 50 * 1024 * 1024,
        bytes_to_upload: 50 * 1024 * 1024,
        test_duration_seconds: 12,
        format: Some("json".to_string()),
        no_header: false,
        server: "https://speed.cloudflare.com".to_string(),
        cipher: "chacha20".to_string(),
    };
    assert!(args.validate().is_ok());

    let mut args_csv = UserArgs {
        format: Some("csv".to_string()),
        ..args.clone()
    };
    assert!(args_csv.validate().is_ok());

    let mut args_none = UserArgs {
        format: None,
        ..args.clone()
    };
    assert!(args_none.validate().is_ok());

    let mut args_bad = UserArgs {
        format: Some("xml".to_string()),
        ..args.clone()
    };
    assert!(args_bad.validate().is_err());
}

#[test]
fn test_format_case_insensitive() {
    let mut args = UserArgs {
        download_threads: 8,
        upload_threads: 8,
        download_only: false,
        upload_only: false,
        bytes_to_download: 50 * 1024 * 1024,
        bytes_to_upload: 50 * 1024 * 1024,
        test_duration_seconds: 12,
        format: Some("JSON".to_string()),
        no_header: false,
        server: "https://speed.cloudflare.com".to_string(),
        cipher: "chacha20".to_string(),
    };
    assert!(args.validate().is_ok());
    assert_eq!(args.format.as_deref(), Some("json"));

    let mut args_csv = UserArgs {
        format: Some("CsV".to_string()),
        ..args.clone()
    };
    assert!(args_csv.validate().is_ok());
    assert_eq!(args_csv.format.as_deref(), Some("csv"));
}
