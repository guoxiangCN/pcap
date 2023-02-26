use pcap::{Device, PacketCodec};
use pcap::pkt::*;
use pktparse::ethernet::*;

struct TcpIpCodec;

impl PacketCodec for TcpIpCodec {
    type Item = Option<IpV4Packet>;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        parse_raw(packet.data)
    }
}

fn main() {
    let host = "192.168.3.8".to_owned();
    //  and tcp dst port $PORT
    let bpm_program_expr = "(ip dst host 192.168.3.8) and (tcp)";

    let devices = Device::list().expect("unable to find any devices");
    let dev = devices.into_iter().filter(|d| {
        let mut ret = false;
        for addr in &d.addresses {
            let addr = addr.addr;
            if addr.is_ipv4() && addr.to_string()==host {
                ret = true;
                break;
            }
        }
        ret
    }).nth(0).expect("unable to find the netcard device by the given host/ip");

    let mut cap = dev.open().expect("unable to capture the target device");
    // cap = cap.setnonblock().unwrap();
    cap.filter(bpm_program_expr, false).expect("cannot filter by bpm_program expr");
    for r in cap.iter(TcpIpCodec{}) {
        match r {
            Err(e) => {
                println!("error: {:?}", e);
                return;
            },
            Ok(maybe_pkt) => {
                if maybe_pkt.is_none() {
                    continue;
                }
                let ipv4_pkt = maybe_pkt.unwrap();
                println!("{:?}", ipv4_pkt);
            },
        }
    }
}

macro_rules! clone_data {
    ($slice: expr) => {
        if !$slice.is_empty() {
            Some($slice.to_vec())
        } else {
            None
        }
    };
}

/// Parse the raw packet.
///
/// ## Notes
///
/// 1. Every packet lives in an Ethernet frame.
/// 2. MTU may restrict the size of packet. UDP packet can be as big as 2^16-1 bytes (65535 bytes)
///    but the Ethernet frame can only contain 1500 bytes of data. Larger UDP packets will get
///    defragmented.
///
/// ## References:
/// - https://jvns.ca/blog/2017/02/07/mtu/
pub fn parse_raw(data: &[u8]) -> Option<IpV4Packet> {
    if let Ok((remaining, eth_frame)) = pktparse::ethernet::parse_ethernet_frame(data) {
        let etype = eth_frame.ethertype;
        if etype == EtherType::IPv4 {
            if let Ok((remaining, header)) = pktparse::ipv4::parse_ipv4_header(remaining) {
                let mut packet = IpV4Packet {
                    ether_hdr: eth_frame,
                    ip_hdr: header,
                    // assume it's tcp
                    app_prot: crate::ApplicationProtocol::TCP,
                    tcp: None,
                    udp: None,
                };
                match header.protocol {
                    pktparse::ip::IPProtocol::TCP => {
                        if let Ok((remaining, hdr)) = pktparse::tcp::parse_tcp_header(remaining) {
                            #[cfg(feature = "http-parse")]
                            let mut headers_buffer = vec![http_bytes::EMPTY_HEADER; 20];

                            let mut pack = TCPPacket {
                                hdr,
                                data: crate::TCPApps::Generic(None),
                            };
                            #[cfg(feature = "http-parse")]
                            {
                                if let Ok((http_header)) = http_bytes::parse_request_header(
                                    remaining,
                                    &mut headers_buffer,
                                    Some(http_bytes::http::uri::Scheme::HTTP),
                                ) {
                                    if let Some((req, remain)) = http_header {
                                        pack.data = crate::TCPApps::HTTP(req);
                                    }
                                } else {
                                    let data = clone_data!(remaining);
                                    pack.data = crate::TCPApps::Generic(data);
                                }
                            }
                            #[cfg(not(feature = "http-parse"))]
                            {
                                let data = clone_data!(remaining);
                                pack.data = crate::TCPApps::Generic(data);
                            }
                            packet.tcp = Some(pack);
                        }
                    }
                    pktparse::ip::IPProtocol::UDP => {
                        if let Ok((remaining, hdr)) = pktparse::udp::parse_udp_header(remaining) {
                            let data = if !remaining.is_empty() {
                                #[cfg(feature = "dns-parse")]
                                {
                                    if let Ok(dns) = dns_parser::Packet::parse(remaining) {
                                        crate::UDPApp::DNS(crate::dns::from_packet(&dns))
                                    } else {
                                        crate::UDPApp::Generic(Some(remaining.to_vec()))
                                    }
                                }
                                #[cfg(not(feature = "dns-parse"))]
                                {
                                    // might be expensive `.to_vec` call
                                    crate::UDPApp::Generic(Some(remaining.to_vec()))
                                }
                            } else {
                                crate::UDPApp::Generic(None)
                            };

                            let pack = crate::UDPPacket { hdr, data };
                            packet.app_prot = ApplicationProtocol::UDP;
                            packet.udp = Some(pack);
                        }
                    }
                    _ => {
                        return None;
                        //unimplemented!()
                    }
                }
                return Some(packet);
            }
        } else {
            eprintln!(" - Unsupported Ethernet frame type: {:?}", etype);
        }
        return None;
    }
    None
}