#![no_main]
use libfuzzer_sys::fuzz_target;

use crypto::resolve::{get_cert_from_certchain, parse_extensions};
use crypto::x509::Certificate;
use der::Decodable;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let range = get_cert_from_certchain(data, 0);
        if range.is_ok() {
            let (start, end) = range.unwrap();
            let cert = Certificate::from_der(&data[start..end]);
            if cert.is_ok() {
                let cert = cert.unwrap();
                let extensions = cert
                    .tbs_certificate
                    .extensions
                    .as_ref();
                if extensions.is_some() {
                    let td_report = parse_extensions(&extensions.unwrap());
                }
            }
        }
});