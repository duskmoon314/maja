//! # maja: Yet Another Network Packet Processing Crate
//!
//! `maja` is a Rust packet processing crate for protocol viewing,
//! capture file I/O, packet crafting, and small network-analysis tools.
//!
//! ## Quick Start
//!
//! ### Packet Parsing and Viewing
//!
//! ```rust
//! use maja::prelude::*;
//!
//! # fn main() -> Result<(), ParseError> {
//! let bytes: [u8; 34] = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
//!     0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
//!     0x08, 0x00, // eth type ipv4
//!     0x45, // version 4, ihl 5
//!     0x00, // dscp 0, ecn 0
//!     0x00, 0x20, // total length 20 + 8 + 4 = 32 (Assume a UDP with 4 bytes data)
//!     0x00, 0x00, // identification 0
//!     0x00, 0x00, // flags 0, fragment offset 0
//!     0x80, // ttl 128
//!     0x06, // protocol tcp
//!     0x00, 0x00, // checksum 0 (TODO: check this)
//!     0x7f, 0x00, 0x00, 0x01, // src ip
//!     0x7f, 0x00, 0x00, 0x02, // dst ip
//! ];
//!
//! let mut packet = Packet::new(bytes);
//! let res = packet.try_parse_with_link_type(LinkType::Ethernet, Default::default());
//! assert!(res.is_err()); // The packet is invalid due to truncated data
//!
//! // But we can still view the layers that were successfully parsed:
//! let ipv4 = packet.layer_viewer(Ipv4).unwrap();
//! assert_eq!(ipv4.src(), std::net::Ipv4Addr::new(127, 0, 0, 1));
//! # Ok(())
//! # }
//! ```
//!
//! ### Capture File I/O
//!
//! ```rust
//! use maja::prelude::*;
//!
//! # fn main() -> anyhow::Result<()> {
//! let pcap_bytes: [u8; _] = [
//!     0xA1, 0xB2, 0xC3, 0xD4, // magic number
//!     0x00, 0x02, 0x00, 0x04, // version major/minor
//!     0x00, 0x00, 0x00, 0x00, // reserved 1
//!     0x00, 0x00, 0x00, 0x00, // reserved 2
//!     0x00, 0x00, 0xFF, 0xFF, // snap_len
//!     0x00, 0x00, 0x00, 0x01, // link_type (Ethernet)
//!     // Packet 1
//!     0x43, 0xb8, 0x27, 0xa5, // ts_sec
//!     0x00, 0x01, 0xe2, 0x40, // ts_usec
//!     0x00, 0x00, 0x00, 0x04, // incl_len
//!     0x00, 0x00, 0x00, 0x04, // orig_len
//!     // Packet data
//!     1, 2, 3, 4,
//! ];
//!
//! let mut reader = SniffedReader::new(std::io::Cursor::new(pcap_bytes))?;
//!
//! assert_eq!(reader.interfaces(), vec![
//!     maja::capture::interface::Interface {
//!         link_type: LinkType::Ethernet,
//!         snap_len: 65535,
//!         resolution: maja::capture::interface::Resolution::PowerOfTen(6)
//!     }
//! ]);
//!
//! let record = reader.next_packet()?.unwrap();
//! assert_eq!(record.timestamp, 1136142245123456000);
//! assert_eq!(record.original_length, 4);
//! assert_eq!(record.link_type, LinkType::Ethernet);
//! assert_eq!(record.data, std::borrow::Cow::Borrowed(&[1, 2, 3, 4]));
//! # Ok(())
//! # }
//! ```
//!
//! ### Packet Crafting
//!
//! ```rust
//! use maja::prelude::*;
//! # fn main() -> Result<(), CraftError> {
//! let packet = (
//!     eth!(src: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], dst: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb])
//!     / ipv4!(src: [10, 0, 0, 1], dst: [10, 0, 0, 2])
//!     / udp!(src_port: 1234, dst_port: 5678)
//!     / raw!(b"hello")
//! ).build()?;
//!
//! assert_eq!(packet.as_bytes(), &[
//!     0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // dst mac
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
//!     0x08, 0x00, // eth type ipv4
//!     0x45, // version 4, ihl 5
//!     0x00, // dscp 0, ecn 0
//!     0x00, 0x21, // total length 20 + 8 + 5 = 33
//!     0x00, 0x00, // identification 0
//!     0x00, 0x00, // flags 0, fragment offset 0
//!     0x40, // ttl 64
//!     0x11, // protocol udp
//!     0x66, 0xca, // checksum
//!     0x0a, 0x00, 0x00, 0x01, // src ip
//!     0x0a, 0x00, 0x00, 0x02, // dst ip
//!     0x04, 0xd2, // src port 1234
//!     0x16, 0x2e, // dst port 5678
//!     0x00, 0x0d, // length 8 + 5 = 13
//!     0x8c, 0xff, // checksum
//!     0x68, 0x65, 0x6c, 0x6c, 0x6f, // payload "hello"
//! ]);
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

/// Capture file readers, writers, link types, and timestamped packet records.
pub mod capture;
/// Packet parsing, protocol viewers, flow identifiers, and packet crafting.
pub mod packet;

/// Common imports for capture reading, packet parsing, and packet crafting.
pub mod prelude {
    pub use crate::{
        capture::{CaptureReader, SniffedReader, link_type::LinkType, packet::PacketRecord},
        eth, eth_addr, field_spec, icmp_echo, impl_craft_layer_div, ipv4,
        packet::{
            CustomProtocolRegistry, Packet, ParseOptions,
            craft::{
                CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftLayerExt,
                CraftPlan, CraftedPacket, PacketStack,
            },
            error::ParseError,
            flow::{FlowId, FlowIdAsymmetric, FlowIdSymmetric},
            layer::{
                Layer, Protocol, ProtocolExt,
                eth::{Eth, EthAddr, EthBuilder, EthType},
                icmp::{Icmp, IcmpEchoBuilder, IcmpType},
                ip::{
                    protocol::IpProtocol,
                    v4::{Ipv4, Ipv4Builder},
                },
                raw::{Raw, RawBuilder},
                tcp::{Tcp, TcpBuilder, TcpFlags},
                udp::{Udp, UdpBuilder},
                vxlan::{Vxlan, VxlanFlags, VxlanVni},
            },
            utils::field::{FieldMut, FieldRef},
        },
        raw, tcp, udp,
    };
}
