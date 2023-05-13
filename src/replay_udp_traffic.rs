// Standalone binary to replay UDP traffic from a pcap file
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io;
use std::io::{Read, Stdin};
use std::net::{SocketAddr, UdpSocket};
use bytes::buf::Reader;
use etherparse::IpNumber::Udp;
use etherparse::{SlicedPacket, TransportSlice};

pub fn load_and_send_to_udp(reader: &mut Reader<&[u8]>, target: SocketAddr) {

    // TODO extract as parameters
    let sender_copy_udp = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().expect("parse")).expect("bind");

    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, reader).expect("LegacyPcapReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {

                match block {
                    PcapBlockOwned::Legacy(leg_block) => {
                        let data = leg_block.data;
                        // println!("got new block {:?}", leg_block);

                        let eth = SlicedPacket::from_ethernet(&data).expect("from_ethernet");
                        if let Some(TransportSlice::Udp(udp)) = eth.transport {
                            if udp.destination_port() == target.port() {
                                sender_copy_udp.send_to(eth.payload, target).expect("send_to");
                                num_blocks += 1;
                            }
                        }

                    }
                    PcapBlockOwned::LegacyHeader(_) => {}
                    PcapBlockOwned::NG(_) => {}
                }


                reader.consume(offset);
            },
            Err(PcapError::Eof) => {
                println!("EOF after {num_blocks}");
                return; // TODO return Result
            },
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

}