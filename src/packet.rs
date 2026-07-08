//! Packet parsing, layer metadata, flow identifiers, and packet crafting.
//!
//! [`Packet`](crate::packet::Packet) stores packet bytes together with a layer table
//! produced by parsers or crafting builders. Protocol-specific viewers are
//! lightweight borrowed views over slices in that byte buffer.

/// Packet crafting support and builder composition.
pub mod craft;
/// Structured parse errors.
pub mod error;
/// Flow identifier types for 5-tuple style grouping.
pub mod flow;
/// Protocol layer marker types and protocol viewers.
pub mod layer;
/// Shared packet utilities such as checksum and field accessors.
pub mod utils;

use std::{
    any::TypeId,
    collections::HashMap,
    fmt::Display,
    ops::{Deref, Range},
};

use layer::Layer;

pub use craft::{CraftError, CraftedPacket, PacketStack};

use crate::{
    capture::link_type::LinkType,
    packet::{
        error::ParseError,
        layer::{
            ParseFn, Protocol, ProtocolExt,
            eth::Eth,
            ip::{v4::Ipv4, v6::Ipv6},
            raw::Raw,
            sll::Sll,
        },
    },
};

/// Packet bytes plus parsed or crafted layer metadata.
///
/// `T` is the byte storage, commonly `&[u8]`, `&mut [u8]`, or `Vec<u8>`.
/// Parsing fills the layer table without copying packet bytes.
#[derive(Debug, Clone)]
pub struct Packet<T> {
    bytes: T,
    layers: Vec<Layer>,
}

impl<T> Packet<T>
where
    T: AsRef<[u8]>,
{
    /// Constructs a new `Packet` with the given bytes.
    ///
    /// The packet starts with an empty layer table. Call `parse`,
    /// `try_parse`, or a crafting API to populate layer metadata.
    pub fn new(bytes: T) -> Self {
        Self {
            bytes,
            layers: Vec::new(),
        }
    }

    /// Return the packet bytes.
    ///
    /// For parsed packets this returns the original input bytes. For crafted
    /// packets this returns the generated wire-format packet.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Return the packet length in octets.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.as_ref().len()
    }

    /// Return whether the packet has no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.as_ref().is_empty()
    }

    /// Return the parsed or crafted protocol layers.
    ///
    /// Each layer entry stores the protocol marker, byte offset, and layer
    /// length inside `as_bytes()`.
    #[inline]
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// Parse the packet from a concrete root protocol and update layer metadata.
    ///
    /// Errors are logged unless [`panic`](ParseOptions::panic) is set, in which case
    /// parsing errors panic. Use [`try_parse`](Packet::try_parse) when callers need the
    /// structured [`ParseError`].
    pub fn parse<P: ProtocolExt>(&mut self, options: ParseOptions) {
        if let Err(err) = self.try_parse::<P>(options.clone()) {
            if options.panic {
                panic!("{err}");
            }
            log::error!("{err}");
        }
    }

    /// Parses the packet using the root protocol implied by a capture link type.
    ///
    /// This is a convenience wrapper for capture readers, where the packet's
    /// first protocol is usually known as a [`LinkType`] value rather than a
    /// concrete `ProtocolExt` type.
    pub fn parse_with_link_type(&mut self, link_type: LinkType, options: ParseOptions) {
        if let Err(err) = self.try_parse_with_link_type(link_type, options.clone()) {
            if options.panic {
                panic!("{err}");
            }
            log::error!("{err}");
        }
    }

    /// Parses the packet and returns a structured error on malformed input.
    pub fn try_parse<P: ProtocolExt>(&mut self, options: ParseOptions) -> Result<(), ParseError> {
        let mut context = ParseContext::new(self.bytes.as_ref(), options, self.layers.clone());

        // Start parsing from the 0th byte. The ParseContext will check if there are any existing layers.
        // TODO: Implement link-layer detection. Now assume Ethernet.
        let result = context.parse::<P>(0);

        // Update the packet's layers with the parsed layers from the context.
        self.layers = context.layers;

        result
    }

    /// Parses the packet using the root protocol implied by a capture link type.
    pub fn try_parse_with_link_type(
        &mut self,
        link_type: LinkType,
        options: ParseOptions,
    ) -> Result<(), ParseError> {
        let mut context = ParseContext::new(self.bytes.as_ref(), options, self.layers.clone());

        let result = match link_type {
            LinkType::Ethernet => context.parse::<Eth>(0),
            LinkType::LinuxSll => context.parse::<Sll>(0),
            LinkType::Ipv4 => context.parse::<Ipv4>(0),
            LinkType::Ipv6 => context.parse::<Ipv6>(0),
            LinkType::Raw => match self.bytes.as_ref().first().map(|byte| byte >> 4) {
                Some(4) => context.parse::<Ipv4>(0),
                Some(6) => context.parse::<Ipv6>(0),
                _ => {
                    context.parse_raw(0);
                    Ok(())
                }
            },
            link_type => Err(ParseError::UnsupportedLinkType { link_type }),
        };

        self.layers = context.layers;

        result
    }

    /// Return metadata for the latest layer that matches the given protocol.
    ///
    /// This returns the parsed layer entry, including protocol marker, byte
    /// offset, and length. Use [`layer_viewer`](Packet::layer_viewer) when you want a typed
    /// protocol viewer over the layer bytes.
    pub fn layer<P: Protocol>(&self, protocol: P) -> Option<&Layer> {
        self.nth_layer(protocol, 0)
    }

    /// Return metadata for the nth latest layer that matches the protocol.
    ///
    /// Index `0` is the same layer returned by [`layer`](Packet::layer). Larger
    /// indexes walk outward through earlier matching layers, so in a tunneled
    /// packet `nth_layer(Eth, 0)` returns the innermost Ethernet layer and
    /// `nth_layer(Eth, 1)` returns the next outer Ethernet layer.
    pub fn nth_layer<P: Protocol>(&self, protocol: P, index: usize) -> Option<&Layer> {
        let protocol_id = protocol.id();
        self.layers
            .iter()
            .rev()
            .filter(|layer| layer.protocol.id() == protocol_id)
            .nth(index)
    }

    /// Return the byte range for the latest matching layer.
    pub fn layer_range<P: Protocol>(&self, protocol: P) -> Option<Range<usize>> {
        self.nth_layer_range(protocol, 0)
    }

    /// Return the byte range for the nth latest matching layer.
    pub fn nth_layer_range<P: Protocol>(&self, protocol: P, index: usize) -> Option<Range<usize>> {
        self.nth_layer(protocol, index).map(Layer::range)
    }

    /// Return the bytes for the latest matching layer.
    pub fn layer_bytes<P: Protocol>(&self, protocol: P) -> Option<&[u8]> {
        self.nth_layer_bytes(protocol, 0)
    }

    /// Return the bytes for the nth latest matching layer.
    pub fn nth_layer_bytes<P: Protocol>(&self, protocol: P, index: usize) -> Option<&[u8]> {
        self.nth_layer(protocol, index)
            .map(|layer| layer.bytes(self.bytes.as_ref()))
    }

    /// Return a typed viewer for the latest matching layer.
    pub fn layer_viewer<P: ProtocolExt>(&self, protocol: P) -> Option<P::Viewer<'_>> {
        self.nth_layer_viewer(protocol, 0)
    }

    /// Return a typed viewer for the nth latest matching layer.
    pub fn nth_layer_viewer<P: ProtocolExt>(
        &self,
        protocol: P,
        index: usize,
    ) -> Option<P::Viewer<'_>> {
        self.nth_layer(protocol, index)
            .map(|layer| P::view(layer.bytes(self.bytes.as_ref())))
    }
}

impl<T> Packet<T> {
    /// Consume the packet and return its underlying byte storage.
    ///
    /// This is useful when a caller constructed `Packet<T>` with a custom byte
    /// container and wants that exact container back.
    #[inline]
    pub fn into_inner(self) -> T {
        self.bytes
    }
}

impl Packet<Vec<u8>> {
    /// Consume the packet and return the crafted or owned byte buffer.
    ///
    /// This is the common escape hatch for handing crafted bytes to a socket,
    /// capture writer, or another byte-oriented API.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<T> Packet<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Return mutable bytes for the latest matching layer.
    pub fn layer_bytes_mut<P: Protocol>(&mut self, protocol: P) -> Option<&mut [u8]> {
        self.nth_layer_bytes_mut(protocol, 0)
    }

    /// Return mutable bytes for the nth latest matching layer.
    pub fn nth_layer_bytes_mut<P: Protocol>(
        &mut self,
        protocol: P,
        index: usize,
    ) -> Option<&mut [u8]> {
        let range = self.nth_layer(protocol, index)?.range();
        Some(&mut self.bytes.as_mut()[range])
    }

    /// Return a mutable typed viewer for the latest matching layer.
    pub fn layer_viewer_mut<P: ProtocolExt>(&mut self, protocol: P) -> Option<P::ViewerMut<'_>> {
        self.nth_layer_viewer_mut(protocol, 0)
    }

    /// Return a mutable typed viewer for the nth latest matching layer.
    pub fn nth_layer_viewer_mut<P: ProtocolExt>(
        &mut self,
        protocol: P,
        index: usize,
    ) -> Option<P::ViewerMut<'_>> {
        self.nth_layer_bytes_mut(protocol, index).map(P::view_mut)
    }
}

impl<T> Display for Packet<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, layer) in self.layers.iter().enumerate() {
            if i > 0 {
                write!(f, " | ")?;
            }

            layer.protocol.display(
                &self.bytes.as_ref()[layer.offset..layer.offset + layer.len],
                f,
            )?;
        }
        Ok(())
    }
}

/// Options controlling packet parsing behavior.
#[derive(Debug, Default, Clone)]
pub struct ParseOptions {
    /// Whether to panic on parsing errors.
    ///
    /// If `false` (default), only a `log::error!` will be emitted on parsing errors
    pub panic: bool,

    /// Custom protocol registry for parsing non-standard protocols.
    pub registry: CustomProtocolRegistry,

    /// Maximum number of structured protocol layers to parse.
    ///
    /// If `None` (default), all layers will be parsed.
    ///
    /// If `Some(n)`, structured parsing stops after `n` decoded protocol
    /// layers. When bytes remain at a stopped child boundary, a terminal
    /// `Raw` layer records the unparsed remainder.
    pub max_depth: Option<usize>,
}

/// Mutable parser state shared by protocol parser implementations.
///
/// Protocol parsers use this context to require byte ranges, push parsed layer
/// metadata, dispatch child protocols, and record raw trailing bytes.
#[derive(Debug)]
pub struct ParseContext<'a> {
    /// Full packet bytes being parsed.
    pub bytes: &'a [u8],
    /// Parse options selected by the caller.
    pub options: ParseOptions,
    /// Layer metadata accumulated so far.
    pub layers: Vec<Layer>,
}

impl<'a> ParseContext<'a> {
    /// Create a parser context for a packet byte slice and existing layers.
    pub fn new(bytes: &'a [u8], options: ParseOptions, layers: Vec<Layer>) -> Self {
        Self {
            bytes,
            options,
            layers,
        }
    }

    /// Parse a protocol at `offset` if structured parsing is still allowed.
    pub fn parse<P: Protocol + ProtocolExt>(&mut self, offset: usize) -> Result<(), ParseError> {
        if self.can_push_layer() {
            P::parse(self, offset)
        } else {
            Ok(())
        }
    }

    /// Parse a child protocol or record the child bytes as raw when depth stops.
    pub fn parse_child<P: Protocol + ProtocolExt>(
        &mut self,
        offset: usize,
    ) -> Result<(), ParseError> {
        if self.can_push_layer() {
            P::parse(self, offset)
        } else {
            self.parse_raw(offset);
            Ok(())
        }
    }

    pub(crate) fn parse_child_with(
        &mut self,
        parse_fn: ParseFn,
        offset: usize,
    ) -> Result<(), ParseError> {
        if self.can_push_layer() {
            parse_fn(self, offset)
        } else {
            self.parse_raw(offset);
            Ok(())
        }
    }

    /// Add a parsed protocol layer to the layer table when depth allows it.
    pub fn push_layer(&mut self, protocol: &'static dyn Protocol, offset: usize, len: usize) {
        if self.can_push_layer() {
            self.layers.push(Layer {
                protocol,
                offset,
                len,
            });
        }
    }

    /// Record the remaining bytes as a terminal raw layer.
    ///
    /// Raw is used for unsupported payloads and when `max_depth` prevents
    /// decoding the next structured protocol layer. It is intentionally allowed
    /// beyond `max_depth` so the unparsed remainder is still visible.
    pub fn parse_raw(&mut self, offset: usize) {
        if let Some(len) = self.bytes.len().checked_sub(offset)
            && len > 0
        {
            // If the last layer is already a Raw layer with the same offset and length, do not add another Raw layer.
            if self
                .layers
                .last()
                .is_some_and(|layer| layer.is(Raw) && layer.offset == offset && layer.len == len)
            {
                return;
            }

            self.layers.push(Layer {
                protocol: &Raw,
                offset,
                len,
            });
        }
    }

    /// Require a byte range for a protocol header or body.
    ///
    /// Returns [`Truncated`](ParseError::Truncated) when `offset..offset + len` is not
    /// fully present in the packet.
    pub fn require(
        &self,
        protocol: &'static dyn Protocol,
        offset: usize,
        len: usize,
    ) -> Result<&'a [u8], ParseError> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| ParseError::truncated(protocol, offset, len, self.bytes.len()))?;

        self.bytes
            .get(offset..end)
            .ok_or_else(|| ParseError::truncated(protocol, offset, len, self.bytes.len()))
    }

    fn can_push_layer(&self) -> bool {
        self.options
            .max_depth
            .is_none_or(|max_depth| self.layers.len() < max_depth)
    }
}

/// Registry mapping parent protocol discriminator values to custom parsers.
///
/// The key is `(parent protocol TypeId, discriminator code)`. Built-in
/// parsers consult this registry after their built-in well-known dispatches so
/// callers can attach private protocols to EtherTypes, IP protocol numbers, or
/// transport ports.
#[derive(Debug, Default, Clone)]
pub struct CustomProtocolRegistry {
    parsers: HashMap<(TypeId, u64), ParseFn>,
}

impl CustomProtocolRegistry {
    /// Create an empty custom protocol registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `Child` as a parser for `code` under `Parent`.
    ///
    /// The meaning of `code` is parent-specific: EtherType for Ethernet, IP
    /// protocol number for IPv4/IPv6, or service port for TCP/UDP.
    pub fn register<Parent: ProtocolExt, Child: ProtocolExt>(
        &mut self,
        parent: Parent,
        code: u64,
    ) -> &mut Self {
        self.parsers.insert((parent.id(), code), Child::parse);
        self
    }
}

impl Deref for CustomProtocolRegistry {
    type Target = HashMap<(TypeId, u64), ParseFn>;

    fn deref(&self) -> &Self::Target {
        &self.parsers
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        capture::link_type::LinkType,
        packet::{error::ParseError, layer::eth::Eth, layer::raw::Raw},
    };

    use super::*;

    #[test]
    fn parse_eth_packet() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source MAC
            0x08, 0x00, // EtherType: IPv4
            // Payload (IPv4 header + data)
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x20, // Total Length (20 + 8 + 4 = 32)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL (64)
            0x11, // Protocol (UDP)
            0x00, 0x00, // Header Checksum (TODO: Calculate this)
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
            0x04, 0xd2, 0x04, 0xd3, // Source Port (1234), Destination Port (1235)
            0x00, 0x0c, // Length (8 + 4 = 12)
            0x00, 0x00, // Checksum (TODO: Calculate this)
            0x01, 0x02, 0x03, 0x04, // Payload
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        assert_eq!(packet.layers.len(), 4);
        assert_eq!(
            packet.layer_viewer(Raw).expect("raw payload").bytes(),
            &[1, 2, 3, 4]
        );

        let s = format!("{}", packet);
        assert_eq!(
            s,
            "[Eth] 01:02:03:04:05:06 -> 0B:0C:0D:0E:0F:10 | [Ipv4] 10.0.1.1        -> 10.0.1.2        32   | [Udp] 1234  -> 1235  | [Raw] 4 bytes"
        );
    }

    #[test]
    fn parse_with_link_type_dispatches_ethernet() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x14, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL
            0xff, // Protocol: unknown
            0x00, 0x00, // Header Checksum
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
        ];

        let mut packet = Packet::new(&data);
        packet
            .try_parse_with_link_type(LinkType::Ethernet, Default::default())
            .expect("Ethernet link type should dispatch to Ethernet parser");

        assert!(packet.layer(Eth).is_some());
        assert!(packet.layer(layer::ip::v4::Ipv4).is_some());
    }

    #[test]
    fn layer_lookup_returns_metadata_and_bytes() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x14, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL
            0xff, // Protocol: unknown
            0x00, 0x00, // Header Checksum
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
        ];

        let mut packet = Packet::new(&data);
        packet
            .try_parse_with_link_type(LinkType::Ethernet, Default::default())
            .expect("Ethernet link type should dispatch to Ethernet parser");

        let eth = packet.layer(Eth).expect("eth metadata");
        assert_eq!(eth.offset, 0);
        assert_eq!(eth.len, 14);
        assert_eq!(eth.range(), 0..14);

        assert_eq!(packet.layer_range(layer::ip::v4::Ipv4), Some(14..34));
        assert_eq!(
            packet.layer_bytes(layer::ip::v4::Ipv4).expect("ipv4 bytes"),
            &data[14..34]
        );
        assert_eq!(
            packet
                .layer_viewer(layer::ip::v4::Ipv4)
                .expect("ipv4 viewer")
                .src()
                .get(),
            core::net::Ipv4Addr::new(10, 0, 1, 1)
        );
    }

    #[test]
    fn layer_bytes_mut_updates_packet_bytes() {
        let mut data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source MAC
            0x88, 0xb5, // EtherType: experimental
        ];

        let mut packet = Packet::new(&mut data[..]);
        packet
            .try_parse_with_link_type(LinkType::Ethernet, Default::default())
            .expect("Ethernet link type should dispatch to Ethernet parser");

        packet.layer_bytes_mut(Eth).expect("eth bytes")[0] = 0xaa;

        assert_eq!(packet.as_bytes()[0], 0xaa);
    }

    #[test]
    fn parse_with_link_type_dispatches_raw_ipv4() {
        let data = [
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x14, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL
            0xff, // Protocol: unknown
            0x00, 0x00, // Header Checksum
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
        ];

        let mut packet = Packet::new(&data);
        packet
            .try_parse_with_link_type(LinkType::Raw, Default::default())
            .expect("raw IPv4 link type should dispatch to IPv4 parser");

        assert!(packet.layer(layer::ip::v4::Ipv4).is_some());
    }

    #[test]
    fn parse_with_link_type_reports_unsupported_link_type() {
        let data = [0; 8];
        let mut packet = Packet::new(&data);

        let err = packet
            .try_parse_with_link_type(LinkType::Ppp, Default::default())
            .expect_err("PPP is not supported by the link-type dispatcher yet");

        match err {
            ParseError::UnsupportedLinkType { link_type } => {
                assert_eq!(link_type, LinkType::Ppp);
            }
            err => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn try_parse_returns_structured_truncation_error() {
        let data = [0xff, 0xff, 0xff, 0xff];
        let mut packet = Packet::new(&data);

        let err = packet
            .try_parse::<Eth>(Default::default())
            .expect_err("short Ethernet frame should fail");

        match err {
            ParseError::Truncated {
                protocol,
                offset,
                needed,
                available,
            } => {
                assert_eq!(protocol.id(), Eth.id());
                assert_eq!(offset, 0);
                assert_eq!(needed, 14);
                assert_eq!(available, 4);
            }
            err => panic!("unexpected error: {err}"),
        }

        assert_eq!(packet.layers.len(), 0);
    }

    #[test]
    fn ipv4_header_len_below_minimum_is_malformed() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source MAC
            0x08, 0x00, // EtherType: IPv4
            0x44, // Version + invalid IHL: 4 * 4 = 16 bytes
            0x00, // DSCP + ECN
            0x00, 0x14, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL
            0x11, // Protocol: UDP
            0x00, 0x00, // Header Checksum
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
        ];

        let mut packet = Packet::new(&data);
        let err = packet
            .try_parse::<Eth>(Default::default())
            .expect_err("invalid IHL should be malformed");

        match err {
            ParseError::Malformed {
                protocol,
                field,
                reason,
            } => {
                assert_eq!(protocol.id(), layer::ip::v4::Ipv4.id());
                assert_eq!(field, "ihl");
                assert_eq!(
                    reason,
                    "header length is smaller than the minimum IPv4 header length"
                );
            }
            err => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn tcp_data_offset_below_minimum_is_malformed() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x28, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL
            0x06, // Protocol: TCP
            0x00, 0x00, // Header Checksum
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
            0x04, 0xd2, 0x00, 0x50, // TCP ports
            0x00, 0x00, 0x00, 0x00, // Sequence number
            0x00, 0x00, 0x00, 0x00, // Acknowledgment number
            0x40, // Invalid data offset: 4 * 4 = 16 bytes
            0x02, // Flags
            0x20, 0x00, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let mut packet = Packet::new(&data);
        let err = packet
            .try_parse::<Eth>(Default::default())
            .expect_err("invalid TCP data offset should be malformed");

        match err {
            ParseError::Malformed {
                protocol,
                field,
                reason,
            } => {
                assert_eq!(protocol.id(), layer::tcp::Tcp.id());
                assert_eq!(field, "data_offset");
                assert_eq!(
                    reason,
                    "header length is smaller than the minimum TCP header length"
                );
            }
            err => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn max_depth_limits_layer_parsing() {
        let data = [
            01, 02, 03, 04, 05, 06, // Destination MAC
            11, 12, 13, 14, 15, 16, // Source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x20, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL
            0x11, // Protocol: UDP
            0x00, 0x00, // Header Checksum
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
            0x04, 0xd2, 0x04, 0xd3, // UDP ports
            0x00, 0x0c, // Length
            0x00, 0x00, // Checksum
            0x01, 0x02, 0x03, 0x04, // Payload
        ];

        let mut packet = Packet::new(&data);
        packet
            .try_parse::<Eth>(ParseOptions {
                max_depth: Some(2),
                ..Default::default()
            })
            .expect("parse should stop cleanly at max_depth");

        assert_eq!(packet.layers.len(), 3);
        assert!(packet.layer(Eth).is_some());
        assert!(packet.layer(layer::ip::v4::Ipv4).is_some());
        assert!(packet.layer(layer::udp::Udp).is_none());
        assert_eq!(
            packet.layer_viewer(Raw).expect("raw remainder").bytes(),
            &[0x04, 0xd2, 0x04, 0xd3, 0x00, 0x0c, 0x00, 0x00, 1, 2, 3, 4]
        );
    }

    #[test]
    fn max_depth_zero_parses_no_layers() {
        let data = [
            01, 02, 03, 04, 05, 06, // Destination MAC
            11, 12, 13, 14, 15, 16, // Source MAC
            0x08, 0x00, // EtherType: IPv4
        ];

        let mut packet = Packet::new(&data);
        packet
            .try_parse::<Eth>(ParseOptions {
                max_depth: Some(0),
                ..Default::default()
            })
            .expect("max_depth zero should stop before root parser");

        assert_eq!(packet.layers.len(), 0);
    }
}
