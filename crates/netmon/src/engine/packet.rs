//! Decode a captured link-layer frame down to its TCP payload + endpoints, so
//! the engine can treat it like a per-flow byte slice. Pure `etherparse`, no
//! capture dependency — unit-testable with synthetic frames.

use std::net::{IpAddr, SocketAddr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::source::{L4Proto, LinkType};

pub struct Decoded {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub outbound: bool,
    pub proto: L4Proto,
    pub payload: Vec<u8>,
}

/// Ports that identify the *server* side of a connection, used to orient
/// local-vs-remote (and therefore capture direction) from a bare frame.
fn server_like(p: u16) -> bool {
    matches!(p, 443 | 80 | 8443 | 853 | 993 | 995 | 465 | 587) || p < 1024
}

/// Decide which endpoint is remote (server) and whether the frame is outbound.
fn classify(src: SocketAddr, dst: SocketAddr) -> (SocketAddr, SocketAddr, bool) {
    if server_like(dst.port()) && !server_like(src.port()) {
        (src, dst, true) // local → remote
    } else if server_like(src.port()) && !server_like(dst.port()) {
        (dst, src, false) // remote → local
    } else if dst.port() <= src.port() {
        (src, dst, true)
    } else {
        (dst, src, false)
    }
}

pub fn decode(link: LinkType, data: &[u8]) -> Option<Decoded> {
    let sliced = match link {
        LinkType::Ethernet => SlicedPacket::from_ethernet(data).ok()?,
        LinkType::RawIp => SlicedPacket::from_ip(data).ok()?,
        // BSD loopback: 4-byte address-family header, then the IP packet.
        LinkType::Null => SlicedPacket::from_ip(data.get(4..)?).ok()?,
        // Linux cooked / pktap are unwrapped by their backends before reaching here.
        LinkType::LinuxSll | LinkType::Pktap => return None,
    };
    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(v4) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        NetSlice::Ipv6(v6) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
    };
    // TCP carries the TLS streams we parse; UDP (QUIC/HTTP-3, DNS) can't be
    // stream-reassembled here, but we still surface its destinations and byte
    // counts — otherwise a QUIC-heavy app (e.g. a browser talking to Google
    // over HTTP/3) looks like it produced no traffic at all.
    let (proto, src_port, dst_port, payload) = match sliced.transport.as_ref()? {
        TransportSlice::Tcp(t) => (
            L4Proto::Tcp,
            t.source_port(),
            t.destination_port(),
            t.payload().to_vec(),
        ),
        TransportSlice::Udp(u) => (
            L4Proto::Udp,
            u.source_port(),
            u.destination_port(),
            u.payload().to_vec(),
        ),
        _ => return None,
    };
    if payload.is_empty() {
        return None;
    }
    let src = SocketAddr::new(src_ip, src_port);
    let dst = SocketAddr::new(dst_ip, dst_port);
    let (local, remote, outbound) = classify(src, dst);
    Some(Decoded {
        local,
        remote,
        outbound,
        proto,
        payload,
    })
}
