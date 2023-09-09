use super::*;

#[test]
fn test_reachability() {
    get_our_ip_address_country()
        .expect("Couldn't reach Cloudflare, please check your internet connection");
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

    assert_eq!(total_bytes_counter.load(Ordering::SeqCst), BYTES_TO_REQUEST);

    exit_signal.store(true, Ordering::SeqCst);
    let _ = _handle.join();
}

#[test]
fn test_upload() {
	const BYTES_TO_UPLOAD: usize = 1024;
    let upload_counter = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));

    let total_bytes_uploaded_counter = Arc::clone(&upload_counter);
    let upload_bytes_clone = Arc::clone(&upload_counter);
    let exit_signal_clone = Arc::clone(&exit_signal);

    let _handle = std::thread::spawn(move || {
        upload_test(
            BYTES_TO_UPLOAD,
            &total_bytes_uploaded_counter,
            &upload_bytes_clone,
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
