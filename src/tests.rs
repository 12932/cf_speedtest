use super::*;

#[test]
fn test_reachability() {
    get_our_ip_address_country()
        .expect("Couldn't reach Cloudflare, please check your internet connection");
}

#[test]
fn test_download() {
    let total_bytes_counter = Arc::new(AtomicUsize::new(0));
    let current_down = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));

    let total_downloaded_bytes_counter = Arc::clone(&total_bytes_counter.clone());
    let current_down_clone = Arc::clone(&current_down.clone());
    let exit_signal_clone = Arc::clone(&exit_signal.clone());

    let handle = std::thread::spawn(move || {
        download_test(
            1,
            &total_downloaded_bytes_counter,
            &current_down_clone,
            &exit_signal_clone,
        )
        .unwrap();
    });

    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if total_bytes_counter.load(Ordering::SeqCst) >= 1 {
            break;
        }
    }

    assert!(total_bytes_counter.load(Ordering::SeqCst) >= 1);

    exit_signal.store(true, Ordering::SeqCst);
    let _ = handle.join();
}

#[test]
fn test_upload() {
    let upload_counter = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));

    let total_bytes_uploaded_counter = Arc::clone(&upload_counter);
    let exit_signal_clone = Arc::clone(&exit_signal);

    let handle = std::thread::spawn(move || {
        upload_test(1, &total_bytes_uploaded_counter, &exit_signal_clone).unwrap();
    });

    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if upload_counter.load(Ordering::SeqCst) >= 1 {
            break;
        }
    }

    assert!(upload_counter.load(Ordering::SeqCst) >= 1);

    exit_signal.store(true, Ordering::SeqCst);
    let _ = handle.join();
}

#[test]
fn test_get_appropriate_byte_unit() {
    assert_eq!(
        get_appropriate_byte_unit(100).unwrap(),
        ("100.00 B".to_string(), "800.00 b".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1015).unwrap(),
        ("1015.00 B".to_string(), "8.12 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(2048).unwrap(),
        ("2.00 KB".to_string(), "16.00 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1048576).unwrap(),
        ("1.00 MB".to_string(), "8.00 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1073741824).unwrap(),
        ("1.00 GB".to_string(), "8.00 gb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1099511627776).unwrap(),
        ("1.00 TB".to_string(), "8.00 tb".to_string())
    );

    assert_eq!(
        get_appropriate_byte_unit(1023).unwrap(),
        ("1023.00 B".to_string(), "8.18 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024).unwrap(),
        ("1.00 KB".to_string(), "8.00 kb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(12939428).unwrap(),
        ("12.34 MB".to_string(), "98.72 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(814811).unwrap(),
        ("795.71 KB".to_string(), "6.37 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024).unwrap(),
        ("1.00 MB".to_string(), "8.00 mb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024 * 1024).unwrap(),
        ("1.00 GB".to_string(), "8.00 gb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024 * 1024 * 1024).unwrap(),
        ("1.00 TB".to_string(), "8.00 tb".to_string())
    );
    assert_eq!(
        get_appropriate_byte_unit(1024 * 1024 * 1024 * 1024 * 1024).unwrap(),
        ("1024.00 TB".to_string(), "8.19 pb".to_string())
    );
}
