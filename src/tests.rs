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
    download_test(1, &total_bytes_counter, &current_down, &exit_signal).unwrap();
}

#[test]
fn test_upload() {
    let upload_counter = Arc::new(AtomicUsize::new(0));
    let exit_signal = Arc::new(AtomicBool::new(false));
    upload_test(1, &upload_counter, &exit_signal).unwrap();
}

#[test]
fn test_get_appropriate_byte_unit() {
	assert_eq!(get_appropriate_byte_unit(100).unwrap(), ("100.00 B".to_string(), "800.00 b".to_string()));
    assert_eq!(get_appropriate_byte_unit(1015).unwrap(), ("1015.00 B".to_string(), "8.12 kb".to_string()));
    assert_eq!(get_appropriate_byte_unit(2048).unwrap(), ("2.00 KB".to_string(), "16.00 kb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1048576).unwrap(), ("1.00 MB".to_string(), "8.00 mb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1073741824).unwrap(), ("1.00 GB".to_string(), "8.00 gb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1099511627776).unwrap(), ("1.00 TB".to_string(), "8.00 tb".to_string()));

	assert_eq!(get_appropriate_byte_unit(1023).unwrap(), ("1023.00 B".to_string(), "8.18 kb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1024).unwrap(), ("1.00 KB".to_string(), "8.00 kb".to_string()));
	assert_eq!(get_appropriate_byte_unit(12939428).unwrap(), ("12.34 MB".to_string(), "98.72 mb".to_string()));
    assert_eq!(get_appropriate_byte_unit(814811).unwrap(), ("795.71 KB".to_string(), "6.37 mb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1024 * 1024).unwrap(), ("1.00 MB".to_string(), "8.00 mb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1024 * 1024 * 1024).unwrap(), ("1.00 GB".to_string(), "8.00 gb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1024 * 1024 * 1024 * 1024).unwrap(), ("1.00 TB".to_string(), "8.00 tb".to_string()));
    assert_eq!(get_appropriate_byte_unit(1024 * 1024 * 1024 * 1024 * 1024).unwrap(), ("1024.00 TB".to_string(), "8.19 pb".to_string()));
}
