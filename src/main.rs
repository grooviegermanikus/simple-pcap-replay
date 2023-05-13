use std::fs::File;
use std::net::SocketAddr;

mod replay_udp_traffic;

use bytes::Buf;
use bytes::buf::Reader;

/// reads data from pcap dump produced by tcpdump
///
/// test it using this:
/// ```nc -u -l 7999```
fn main() {
    let target: SocketAddr = "127.0.0.1:7999".parse().expect("parse");
    let example = include_bytes!("shreds-mini.pcap");
    let mut reader: Reader<&[u8]> = example.reader();
    replay_udp_traffic::load_and_send_to_udp(&mut reader, target);
}
