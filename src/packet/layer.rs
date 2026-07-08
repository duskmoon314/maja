//! Protocol layer registry and shared protocol traits.
//!
//! Each protocol has a zero-sized marker type implementing [`Protocol`]. A
//! parser-capable protocol also implements [`ProtocolExt`] to define immutable
//! and mutable viewer types plus its parse entry point.

use std::{any::TypeId, fmt::Debug, ops::Range};

use crate::packet::{ParseContext, error::ParseError};

/// Address Resolution Protocol.
pub mod arp;
/// Dynamic Host Configuration Protocol.
pub mod dhcp;
/// Domain Name System.
pub mod dns;
/// Ethernet II framing.
pub mod eth;
/// Generic Routing Encapsulation.
pub mod gre;
/// Internet Control Message Protocol for IPv4.
pub mod icmp;
/// Internet Control Message Protocol for IPv6.
pub mod icmpv6;
/// Internet Group Management Protocol.
pub mod igmp;
/// Internet Protocol versions and protocol-number registry.
pub mod ip;
/// IEEE 802.2 Logical Link Control.
pub mod llc;
/// Multiprotocol Label Switching.
pub mod mpls;
/// Network Time Protocol.
pub mod ntp;
/// Raw unparsed payload bytes.
pub mod raw;
/// Stream Control Transmission Protocol.
pub mod sctp;
/// Linux cooked capture header.
pub mod sll;
/// Transmission Control Protocol.
pub mod tcp;
/// Transport Layer Security record header.
pub mod tls;
/// User Datagram Protocol.
pub mod udp;
/// IEEE 802.1Q VLAN tag.
pub mod vlan;
/// Virtual eXtensible Local Area Network.
pub mod vxlan;

/// Metadata for one parsed or crafted protocol layer.
///
/// The range `offset..offset + len` points into the packet byte buffer. For
/// protocols that have children, `len` is the layer's own header/body range as
/// recorded by that protocol, not necessarily the full subtree length.
#[derive(Debug, Clone)]
pub struct Layer {
    /// Protocol marker for this layer.
    pub protocol: &'static dyn Protocol,
    /// Byte offset of this layer within the packet.
    pub offset: usize,
    /// Number of bytes recorded for this layer.
    pub len: usize,
}

impl Layer {
    /// Return whether this layer uses the given protocol marker.
    #[inline]
    pub fn is<P: Protocol>(&self, protocol: P) -> bool {
        self.protocol.id() == protocol.id()
    }

    /// Return the byte range covered by this layer inside the packet bytes.
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.len
    }

    /// Return this layer's bytes from the packet byte slice.
    ///
    /// The `packet_bytes` argument must be the full packet buffer that this
    /// layer metadata was produced from.
    #[inline]
    pub fn bytes<'a>(&self, packet_bytes: &'a [u8]) -> &'a [u8] {
        &packet_bytes[self.range()]
    }

    /// Return mutable bytes for this layer from the packet byte slice.
    ///
    /// The `packet_bytes` argument must be the full packet buffer that this
    /// layer metadata was produced from.
    #[inline]
    pub fn bytes_mut<'a>(&self, packet_bytes: &'a mut [u8]) -> &'a mut [u8] {
        &mut packet_bytes[self.range()]
    }
}

/// Protocol identity and display behavior.
///
/// Implement this for zero-sized marker types that identify a protocol in
/// layer metadata. Parsing protocols should also implement [`ProtocolExt`].
pub trait Protocol: 'static + Debug {
    /// Return a stable type-based identifier for this protocol marker.
    #[inline]
    fn id(&self) -> TypeId {
        TypeId::of::<Self>()
    }

    /// Format this protocol's layer bytes for packet display output.
    fn display(&self, _bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "[{:?}]", self)?;
        Ok(())
    }
}

/// Protocol parser and viewer contract.
///
/// Implementors provide borrowed immutable and mutable viewers plus a parser
/// that records a layer in [`ParseContext`] and optionally dispatches children.
pub trait ProtocolExt: Protocol + Copy {
    /// Immutable viewer type returned by [`layer_viewer`](crate::packet::Packet::layer_viewer).
    type Viewer<'a>;
    /// Mutable viewer type returned by [`layer_viewer_mut`](crate::packet::Packet::layer_viewer_mut).
    type ViewerMut<'a>;

    /// Parse this protocol at `offset` in the packet.
    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError>;

    /// Create an immutable viewer over this protocol's recorded layer bytes.
    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a>;
    /// Create a mutable viewer over this protocol's recorded layer bytes.
    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a>;
}

pub(crate) type ParseFn = fn(&mut ParseContext, usize) -> Result<(), ParseError>;
