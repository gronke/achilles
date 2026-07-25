//! Shared helpers for netmon integration tests. Compiled into each test binary,
//! so not every item is used by all of them.
#![allow(dead_code)]

use netmon::TargetProcess;

/// A synthetic capture target for engine-level tests.
pub fn target() -> TargetProcess {
    TargetProcess {
        pid: 1234,
        exe_path: Some("/Applications/Example.app/Contents/MacOS/Example".into()),
        display_name: Some("Example".into()),
        bundle_id: Some("com.example.app".into()),
    }
}

/// Build a minimal but valid TLS ClientHello record with:
/// cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F), SNI "example.com",
/// supported_groups [x25519 (0x001d)], signature_algorithms [0x0403].
pub fn client_hello_record() -> Vec<u8> {
    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }
    // SNI: server_name_list = [ host_name(0), len, "example.com" ]
    let host = b"example.com";
    let mut sni_entry = vec![0u8]; // host_name
    sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_entry.extend_from_slice(host);
    let mut sni_list = (sni_entry.len() as u16).to_be_bytes().to_vec();
    sni_list.extend_from_slice(&sni_entry);

    // supported_groups: list_len(2) + x25519
    let groups = {
        let mut b = 2u16.to_be_bytes().to_vec();
        b.extend_from_slice(&0x001du16.to_be_bytes());
        b
    };
    // signature_algorithms: list_len(2) + 0x0403
    let sigs = {
        let mut b = 2u16.to_be_bytes().to_vec();
        b.extend_from_slice(&0x0403u16.to_be_bytes());
        b
    };
    // supported_versions: u8 len + TLS 1.3, 1.2
    let sv = vec![4u8, 0x03, 0x04, 0x03, 0x03];

    let mut exts = Vec::new();
    exts.extend(ext(0x0000, &sni_list));
    exts.extend(ext(0x000a, &groups));
    exts.extend(ext(0x000d, &sigs));
    exts.extend(ext(0x002b, &sv));

    // ClientHello body
    let mut ch = Vec::new();
    ch.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version 1.2
    ch.extend_from_slice(&[0u8; 32]); // random
    ch.push(0); // session_id len
    ch.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
    ch.extend_from_slice(&0xC02Fu16.to_be_bytes());
    ch.push(1); // compression methods len
    ch.push(0); // null
    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    // Handshake header: type(1)=client_hello + u24 len
    let mut hs = vec![1u8];
    let l = ch.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&ch);

    // Record header: content_type(22), version 0x0301, u16 len
    let mut rec = vec![0x16u8, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
