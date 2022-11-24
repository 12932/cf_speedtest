use super::*;

#[test]
fn test_reachability() {
	get_our_ip_address_country().expect(
		"Couldn't reach Cloudflare, please check your internet connection"
	);
}

#[test]
fn test_download() {
	let total_bytes_counter = Arc::new(AtomicU64::new(0));
	let current_down = Arc::new(AtomicU64::new(0));
	let exit_signal = Arc::new(AtomicBool::new(false));
	download_test(1, &total_bytes_counter, &current_down, &exit_signal).unwrap();
}

#[test]
fn test_upload() {
	let upload_counter = Arc::new(AtomicU64::new(0));
	let exit_signal = Arc::new(AtomicBool::new(false));
	upload_test(1, &upload_counter, &exit_signal).unwrap();
}
