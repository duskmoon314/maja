//! # Custom Protocol Example
//!
//! This example demonstrates how to implement a custom protocol and use maja to
//! parse it from binary data.
//!
//! Say we have a custom protocol named `Time` that consists of timestamp encoded for in-network analysis. The protocol is defined as follows:
//!
//! ```text
//! ETH  0                   1                   2                   3
//!      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                    Destination MAC Address                    
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!                                     |                               
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!                             Source MAC Address                      |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |      EtherType = 0xEEEE       |       EtherType (Time)        |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                      Timestamp (Seconds)                      |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                    Timestamp (Microseconds)                   |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                   Next Protocol (e.g., IPv4)                  |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use maja::{
    eth, field_spec, icmp_echo, ipv4,
    packet::{
        CustomProtocolRegistry, Packet, ParseOptions,
        craft::{CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan},
        layer::{
            Protocol, ProtocolExt,
            eth::{Eth, EthType},
            icmp::Icmp,
            ip::v4::Ipv4,
        },
        utils::field::{FieldMut, FieldRef},
    },
    raw,
};

/// LayerKind for the custom protocol `Time`.
#[derive(Debug, Clone, Copy)]
struct Time;

// Implement `Protocol` and `ProtocolExt` for the custom protocol `Time`.

impl Protocol for Time {}

impl ProtocolExt for Time {
    type Viewer<'a> = TimeViewer<&'a [u8]>;
    type ViewerMut<'a> = TimeViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut maja::packet::ParseContext,
        offset: usize,
    ) -> Result<(), maja::packet::error::ParseError> {
        ctx.require(&Time, offset, 10)?;

        ctx.push_layer(&Time, offset, 10);

        let time = TimeViewer {
            data: &ctx.bytes[offset..offset + 10],
        };
        match time.eth_type().get() {
            EthType::Ipv4 => ctx.parse_child::<Ipv4>(offset + 10),
            _ => Ok(()),
        }
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        TimeViewer { data: bytes }
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        TimeViewer { data: bytes }
    }
}

struct TimeViewer<T> {
    data: T,
}

field_spec!(EthTypeSpec, EthType, u16);
field_spec!(TimeSecondSpec, u32, u32);
field_spec!(TimeMicrosecondSpec, u32, u32);

impl<T> TimeViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_ETH_TYPE: core::ops::Range<usize> = 0..2;
    const FIELD_TIMESTAMP_SECONDS: core::ops::Range<usize> = 2..6;
    const FIELD_TIMESTAMP_MICROSECONDS: core::ops::Range<usize> = 6..10;

    pub fn eth_type(&self) -> FieldRef<'_, EthTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ETH_TYPE])
    }

    pub fn timestamp_seconds(&self) -> FieldRef<'_, TimeSecondSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TIMESTAMP_SECONDS])
    }

    pub fn timestamp_microseconds(&self) -> FieldRef<'_, TimeMicrosecondSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TIMESTAMP_MICROSECONDS])
    }
}

impl<T> TimeViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    pub fn eth_type_mut(&mut self) -> FieldMut<'_, EthTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ETH_TYPE])
    }

    pub fn timestamp_seconds_mut(&mut self) -> FieldMut<'_, TimeSecondSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TIMESTAMP_SECONDS])
    }

    pub fn timestamp_microseconds_mut(&mut self) -> FieldMut<'_, TimeMicrosecondSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TIMESTAMP_MICROSECONDS])
    }
}

/// Builder for the custom `Time` protocol.
///
/// This implements maja's `CraftLayer` trait directly. The builder writes the
/// ten-byte Time header into the shared packet buffer, infers IPv4 as the next
/// protocol when the child is `Ipv4`, and then lets the normal built-in IPv4
/// and ICMP builders continue the stack.
#[derive(Debug, Clone, Default)]
struct TimeBuilder {
    eth_type: Option<EthType>,
    timestamp_seconds: Option<u32>,
    timestamp_microseconds: Option<u32>,
}

impl TimeBuilder {
    /// Create an empty Time builder.
    fn new() -> Self {
        Self::default()
    }

    /// Set the next-protocol EtherType-like field.
    ///
    /// If omitted, an IPv4 child infers `EthType::Ipv4`; otherwise the field
    /// defaults to `0`.
    fn eth_type(mut self, eth_type: impl Into<EthType>) -> Self {
        self.eth_type = Some(eth_type.into());
        self
    }

    /// Set both timestamp fields.
    fn timestamp(mut self, seconds: u32, microseconds: u32) -> Self {
        self.timestamp_seconds = Some(seconds);
        self.timestamp_microseconds = Some(microseconds);
        self
    }
}

impl CraftLayer for TimeBuilder {
    fn protocol(&self) -> &'static dyn Protocol {
        &Time
    }

    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        let child_len = child.map_or(0, |child| child.len());
        Ok(CraftPlan::new(10, 10 + child_len))
    }

    fn write(
        &self,
        _context: CraftContext,
        _plan: CraftPlan,
        child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        let eth_type = self.eth_type.unwrap_or(match child {
            Some(child) if child.is(Ipv4) => EthType::Ipv4,
            _ => EthType::Reserverd(0),
        });

        let mut time = TimeViewer {
            data: &mut bytes[..10],
        };
        time.eth_type_mut().set(eth_type);
        time.timestamp_seconds_mut()
            .set(self.timestamp_seconds.unwrap_or_default());
        time.timestamp_microseconds_mut()
            .set(self.timestamp_microseconds.unwrap_or_default());

        Ok(())
    }
}

fn main() {
    // Add the custom protocol to the registry so that it can be parsed when encountered in a packet.
    let mut custom_protocol_registry = CustomProtocolRegistry::new();
    custom_protocol_registry.register::<_, Time>(Eth, 0xEEEE);

    let parse_options = ParseOptions {
        registry: custom_protocol_registry,
        ..Default::default()
    };

    let data: [u8; _] = [
        /* Eth */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Destination MAC Address
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, // Source MAC Address
        0xEE, 0xEE, // EtherType = 0xEEEE (custom protocol)
        /* Time starts here */
        0x08, 0x00, // Next Protocol (e.g., IPv4)
        0x00, 0x00, 0x00, 0x5F, // Timestamp (Seconds)
        0x00, 0x00, 0x03, 0xE8, // Timestamp (Microseconds)
        /* Ipv4 */
        0x45, // version 4, ihl 5
        0x00, // dscp 0, ecn 0
        0x00, 0x20, // total length 20 + 8 + 4 = 32 (Assume a UDP with 4 bytes data)
        0x00, 0x00, // identification 0
        0x00, 0x00, // flags 0, fragment offset 0
        0x40, // ttl 64
        0x11, // protocol udp
        0x00, 0x00, // checksum 0 (TODO: check this)
        0x7f, 0x00, 0x00, 0x01, // src ip
        0x7f, 0x00, 0x00, 0x02, // dst ip
        /* UDP */
        0x00, 0x50, // src port 80
        0x00, 0x51, // dst port 81
        0x00, 0x0c, // length 12
        0x00, 0x00, // checksum
        /* UDP data */
        0x01, 0x02, 0x03, 0x04,
    ];

    let mut packet = Packet::new(&data);
    packet.parse::<Eth>(parse_options.clone());

    // Now we can access the custom protocol layer and its fields.
    if let Some(time) = packet.layer_viewer(Time) {
        assert_eq!(time.eth_type().get(), EthType::Ipv4);
        assert_eq!(time.timestamp_seconds().get(), 95);
        assert_eq!(time.timestamp_microseconds().get(), 1000);
    }

    // The same custom protocol can also participate in packet crafting. The
    // stack below is:
    //
    // Ethernet / Time(custom) / IPv4 / ICMP Echo / Raw echo payload
    //
    // `TimeBuilder` is not known to maja internally; implementing `CraftLayer`
    // is enough for it to be composed with built-in protocol builders.
    let crafted = (eth!(eth_type: EthType::Reserverd(0xEEEE))
        / TimeBuilder::new()
            .eth_type(EthType::Ipv4)
            .timestamp(95, 1000)
        / ipv4!(
            src: core::net::Ipv4Addr::new(127, 0, 0, 1),
            dst: core::net::Ipv4Addr::new(127, 0, 0, 2),
        )
        / icmp_echo!(request, id: 0x1234, seq: 1)
        / raw!(b"custom-time"))
    .build()
    .expect("custom protocol can be crafted");

    let crafted_time = crafted.layer_viewer(Time).expect("crafted Time layer");
    assert_eq!(crafted_time.eth_type().get(), EthType::Ipv4);
    assert_eq!(crafted_time.timestamp_seconds().get(), 95);
    assert_eq!(crafted_time.timestamp_microseconds().get(), 1000);
    assert_eq!(
        crafted
            .layer_viewer(Icmp)
            .expect("crafted ICMP layer")
            .identifier(),
        0x1234
    );

    // We can also parse the crafted packet back to verify that the custom protocol is correctly handled.
    let mut parsed_crafted = Packet::new(crafted.as_bytes());
    parsed_crafted.parse::<Eth>(parse_options);

    let parsed_time = parsed_crafted
        .layer_viewer(Time)
        .expect("parsed crafted Time layer");
    assert_eq!(parsed_time.eth_type().get(), EthType::Ipv4);
    assert_eq!(parsed_time.timestamp_seconds().get(), 95);
    assert_eq!(parsed_time.timestamp_microseconds().get(), 1000);
}
