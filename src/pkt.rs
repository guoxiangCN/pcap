use pktparse::{ethernet, ipv4, ipv6, tcp, udp};

#[derive(Debug)]
pub enum HeaderType {
    Tcp(tcp::TcpHeader),
    Udp(udp::UdpHeader),
    IPv4(ipv4::IPv4Header),
    IPv6(ipv6::IPv6Header),
}

#[derive(Debug)]
pub enum ApplicationProtocol {
    TCP,
    UDP,
}

#[derive(Debug)]
pub enum TCPApps {
    #[cfg(feature = "http-parse")]
    HTTP(http_bytes::Request),
    Generic(Option<Vec<u8>>),
}

#[derive(Debug)]
pub enum UDPApp {
    #[cfg(feature = "dns-parse")]
    DNS(dns::DNSInfo),
    Generic(Option<Vec<u8>>),
}

#[derive(Debug)]
pub struct TCPPacket {
    pub hdr: tcp::TcpHeader,
    pub data: TCPApps,
}

#[derive(Debug)]
pub struct UDPPacket {
    pub hdr: udp::UdpHeader,
    pub data: UDPApp,
}

#[derive(Debug)]
pub struct IpV4Packet {
    pub ether_hdr: ethernet::EthernetFrame,
    pub ip_hdr: ipv4::IPv4Header,
    pub app_prot: ApplicationProtocol,
    pub tcp: Option<TCPPacket>,
    pub udp: Option<UDPPacket>,
}