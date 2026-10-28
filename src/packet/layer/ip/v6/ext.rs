//! IPv6 extension header chain.
//!
//! The extension headers of IPv6 are ordinary protocol layers: each one records
//! itself and names the protocol behind it in its own next-header octet. The
//! base header and every extension header reach the next-header table in
//! [`dispatch`](super::dispatch).
//!
//! ```text
//! IPv6 -> Hop-by-Hop -> Destination Options -> Routing -> Fragment -> AH -> ESP -> upper layer
//! ```
//!
//! Recommended order: every header appears only when the packet needs it
//! ([RFC 8200 section 4.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.1)).

pub mod frag;
pub mod header;
pub mod hip;
pub mod mobility;
pub mod option;
pub mod options;
pub mod route;
pub mod shim6;

pub use frag::{Ipv6Frag, Ipv6FragViewer};
pub use header::{Ipv6ExtHeaderViewer, parse_ext_header};
pub use hip::{HipPacketType, Ipv6Hip};
pub use mobility::{Ipv6Mobility, MobilityType};
pub use option::{Ipv6Option, Ipv6OptionKind, Ipv6Options};
pub use options::{Ipv6DestOpts, Ipv6Hopopt};
pub use route::{Ipv6Route, Ipv6RouteType, Ipv6RouteViewer};
pub use shim6::{Ipv6Shim6, Shim6MessageType};

#[cfg(test)]
pub(crate) mod test_util {
    //! Fixtures shared by the extension header layer tests.

    use crate::packet::{Packet, layer::Protocol};

    /// Ethernet + IPv6 + `payload`, where `next_header` selects what the base
    /// header points at.
    pub fn eth_ipv6_frame(next_header: u8, payload: &[u8]) -> Vec<u8> {
        eth_ipv6_frame_with_plen(next_header, payload.len() as u16, payload)
    }

    /// Ethernet + IPv6 + `payload`, with an explicit `Payload Length` so a test
    /// can declare a bound that differs from the captured bytes.
    pub fn eth_ipv6_frame_with_plen(
        next_header: u8,
        payload_length: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut data = vec![
            0x33, 0x33, 0x00, 0x00, 0x00, 0x02, // destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source MAC
            0x86, 0xdd, // EtherType: IPv6
            0x60, 0x00, 0x00, 0x00, // version, traffic class, flow label
        ];
        data.extend_from_slice(&payload_length.to_be_bytes());
        data.push(next_header);
        data.push(0x40); // hop limit
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        data.extend_from_slice(payload);

        data
    }

    /// A UDP header with source port 0x3039 and destination port 0x0050.
    pub fn udp_header() -> Vec<u8> {
        vec![0x30, 0x39, 0x00, 0x50, 0, 0, 0, 0]
    }

    /// A minimal TCP header.
    pub fn tcp_header() -> Vec<u8> {
        vec![
            0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0,
        ]
    }

    /// An options header (8 octets, no options) that points at `next_header`.
    pub fn options_header(next_header: u8) -> Vec<u8> {
        vec![next_header, 0x00, 0, 0, 0, 0, 0, 0]
    }

    /// Return the protocol of every layer of `packet`, outermost first.
    pub fn layers<T: AsRef<[u8]>>(packet: &Packet<T>) -> Vec<&'static dyn Protocol> {
        packet.layers().iter().map(|layer| layer.protocol).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::ip::{protocol::IpProtocol, v4::Ipv4, v6::Ipv6};
    use crate::packet::{
        Packet,
        layer::{Protocol, eth::Eth, tcp::Tcp, udp::Udp},
    };

    use super::test_util::{eth_ipv6_frame, layers, options_header, tcp_header, udp_header};

    use super::*;

    /// An inner IPv6 header (protocol `next_header`) as a tunnel payload.
    fn inner_ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![0x60, 0x00, 0x00, 0x00];
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        header.push(next_header);
        header.push(0x40); // hop limit
        header.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        header.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
        header.extend_from_slice(payload);

        header
    }

    /// An inner IPv4 header (protocol `protocol`) as a tunnel payload.
    fn inner_ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![0x45, 0x00];
        header.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        header.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        header.extend_from_slice(&[64, protocol, 0x00, 0x00]);
        header.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        header.extend_from_slice(payload);

        header
    }

    #[test]
    fn ipv6_in_ipv6_tunnel_is_parsed() {
        let inner = inner_ipv6(6, &tcp_header());
        let data = eth_ipv6_frame(41, &inner);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Ipv6, &Tcp]);
    }

    #[test]
    fn ipv4_in_ipv6_is_parsed() {
        let inner = inner_ipv4(17, &udp_header());
        let data = eth_ipv6_frame(4, &inner);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Ipv4, &Udp]);
    }

    #[test]
    fn chain_records_both_options_headers() {
        let mut payload = options_header(60); // Hop-by-Hop -> Destination Options
        payload.extend_from_slice(&options_header(17)); // -> UDP
        payload.extend_from_slice(&udp_header());

        let data = eth_ipv6_frame(0, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(
            layers(&packet),
            [
                &Eth as &dyn Protocol,
                &Ipv6,
                &Ipv6Hopopt,
                &Ipv6DestOpts,
                &Udp
            ]
        );

        // Both options headers record their own length and dispatch the next one.
        let hopopt = packet.layer_viewer(Ipv6Hopopt).expect("hopopt layer");
        assert_eq!(hopopt.next_header().get(), IpProtocol::Ipv6Opts);
        assert_eq!(packet.layer(Ipv6Hopopt).unwrap().range(), 54..62);

        let dstopts = packet.layer_viewer(Ipv6DestOpts).expect("dstopts layer");
        assert_eq!(dstopts.next_header().get(), IpProtocol::Udp);
        assert_eq!(packet.layer(Ipv6DestOpts).unwrap().range(), 62..70);

        assert!(packet.layer_viewer(Udp).is_some());
    }
}
