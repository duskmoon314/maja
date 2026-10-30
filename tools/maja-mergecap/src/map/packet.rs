//! The outermost IP envelope of a packet: addresses, ports, protocol and the
//! fragment identity used for aliasing.

use std::{net::IpAddr, ops::Range};

use super::pool::Family;
use maja::packet::{
    Packet,
    layer::{
        Layer, ProtocolExt,
        icmpv6::Icmpv6,
        ip::{
            ah::Ah,
            protocol::IpProtocol,
            v4::{Ipv4, Ipv4Viewer},
            v6::{
                Ipv6, Ipv6Frag, Ipv6Hopopt, Ipv6Route, Ipv6Viewer,
                ext::{Ipv6DestOpts, Ipv6FragViewer, Ipv6Hip, Ipv6Mobility, Ipv6Shim6},
            },
        },
        tcp::Tcp,
        udp::Udp,
    },
};

/// The family of the outermost IP header of a packet.
///
/// `layer_viewer` returns the innermost layer, which is the payload of a tunnel
/// (`Eth -> IPv4 -> GRE -> IPv4 -> TCP` or `IPv6 -> SRH -> IPv6 -> TCP`).
/// Rewriting is about the packet as a whole, so this tool always works on the
/// outermost IP header and leaves an encapsulated packet alone; the family with
/// the smaller offset is the outer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

pub fn outer_ip_family<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<IpFamily> {
    match (packet.nth_layer(Ipv4, -1), packet.nth_layer(Ipv6, -1)) {
        (Some(ipv4), Some(ipv6)) if ipv4.offset < ipv6.offset => Some(IpFamily::V4),
        (Some(_), Some(_)) => Some(IpFamily::V6),
        (Some(_), None) => Some(IpFamily::V4),
        (None, Some(_)) => Some(IpFamily::V6),
        (None, None) => None,
    }
}

/// The outermost IPv4 header, i.e. the one this tool rewrites.
pub fn outer_ipv4<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<Ipv4Viewer<&[u8]>> {
    packet.nth_layer_viewer(Ipv4, -1)
}

/// The outermost IPv6 header, i.e. the one this tool rewrites.
pub fn outer_ipv6<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<Ipv6Viewer<&[u8]>> {
    packet.nth_layer_viewer(Ipv6, -1)
}

/// The outermost IPv4 header, mutable.
pub fn outer_ipv4_mut<T: AsRef<[u8]> + AsMut<[u8]>>(
    packet: &mut Packet<T>,
) -> Option<Ipv4Viewer<&mut [u8]>> {
    packet.nth_layer_viewer_mut(Ipv4, -1)
}

/// The outermost IPv6 header, mutable.
pub fn outer_ipv6_mut<T: AsRef<[u8]> + AsMut<[u8]>>(
    packet: &mut Packet<T>,
) -> Option<Ipv6Viewer<&mut [u8]>> {
    packet.nth_layer_viewer_mut(Ipv6, -1)
}

/// Whether the layer is an extension header of an IPv6 chain.
fn is_chain_layer(layer: &Layer) -> bool {
    layer.is(Ipv6Hopopt)
        || layer.is(Ipv6DestOpts)
        || layer.is(Ipv6Route)
        || layer.is(Ipv6Frag)
        || layer.is(Ah)
        || layer.is(Ipv6Mobility)
        || layer.is(Ipv6Hip)
        || layer.is(Ipv6Shim6)
}

/// Layer indices of the extension header chain of the outermost IPv6 packet.
///
/// The chain starts behind that `Ipv6` layer and stops at the first layer that is
/// not an extension header, so an inner packet's headers (IPv6 in IPv6, a tunnel
/// payload, the invoking packet of an ICMPv6 error) never answer for the outer
/// one.
fn chain_range<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<Range<usize>> {
    let layers = packet.layers();
    let start = layers.iter().position(|layer| layer.is(Ipv6))?;
    let end = layers[start + 1..]
        .iter()
        .position(|layer| !is_chain_layer(layer))
        .map_or(layers.len(), |offset| start + 1 + offset);

    Some(start + 1..end)
}

/// The protocol behind the extension header chain of the outermost IPv6 packet.
pub fn next_header<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<u8> {
    let bytes = packet.as_bytes();
    let layers = packet.layers();
    let ipv6 = layers.iter().find(|layer| layer.is(Ipv6))?;
    let mut next_header = u8::from(Ipv6Viewer::new(ipv6.bytes(bytes)).next_header().get());

    for layer in &layers[chain_range(packet)?] {
        next_header = layer.bytes(bytes)[0];
    }

    Some(next_header)
}

/// A viewer for one extension header of the outermost IPv6 packet.
pub fn chain_viewer<T: AsRef<[u8]>, P: ProtocolExt>(
    packet: &Packet<T>,
    protocol: P,
) -> Option<P::Viewer<'_>> {
    let bytes = packet.as_bytes();
    let layers = packet.layers();
    let layer = layers[chain_range(packet)?]
        .iter()
        .find(|layer| layer.is(protocol))?;

    Some(P::view(layer.bytes(bytes)))
}

/// Fragment header of the outermost IPv6 packet, if it has one.
pub fn outer_fragment<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<Ipv6FragViewer<&[u8]>> {
    chain_viewer(packet, Ipv6Frag)
}

/// The transport protocol of the outermost IP packet, if it has one.
///
/// A tunnelled packet carries another IP packet, whose transport header belongs
/// to the inner addresses. This tool rewrites the outer header only, so the ports
/// and the transport checksum of an inner packet have to be left alone.
/// `None` means the outermost IP packet carries no transport protocol this tool
/// knows about (a tunnel, ESP, or an unknown protocol number).
pub fn outer_transport<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<IpProtocol> {
    if outer_ip_family(packet) == Some(IpFamily::V4) {
        return outer_ipv4(packet).map(|ipv4| ipv4.protocol().get());
    }

    next_header(packet).map(IpProtocol::from)
}

/// Canonical (direction independent) session key.
///
/// Endpoints are stored as integers plus a family tag; a packet is either IPv4
/// or IPv6, so a session never mixes families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    family: Family,
    a: (u128, u16),
    b: (u128, u16),
    proto: u8,
}

impl SessionId {
    pub fn new(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16, proto: u8) -> Self {
        let family = Family::of_addr(src);
        let src = (addr_to_u128(src), src_port);
        let dst = (addr_to_u128(dst), dst_port);
        let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };

        SessionId {
            family,
            a,
            b,
            proto,
        }
    }

    /// First endpoint in canonical order.
    pub fn a(&self) -> (u128, u16) {
        self.a
    }

    /// Second endpoint in canonical order.
    pub fn b(&self) -> (u128, u16) {
        self.b
    }

    pub fn proto(&self) -> u8 {
        self.proto
    }
}

/// Address as an integer; callers must know the family already.
pub fn addr_to_u128(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(addr) => u128::from(u32::from(addr)),
        IpAddr::V6(addr) => u128::from(addr),
    }
}

/// Fragment datagram key: fragments after the first carry no ports, so the
/// identification groups them instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub id: u32,
}

/// The addresses of one datagram or packet, `None` for an unchanged endpoint.
#[derive(Debug, Clone, Copy, Default)]
pub struct Targets {
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
}

/// Everything the mapping needs to know about the outermost IP packet.
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub has_ports: bool,
    pub fragment: Option<FragKey>,
}

impl PacketInfo {
    pub fn read<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<Self> {
        match outer_ip_family(packet)? {
            IpFamily::V4 => Some(Self::from_ipv4(packet, outer_ipv4(packet)?)),
            IpFamily::V6 => Some(Self::from_ipv6(packet, outer_ipv6(packet)?)),
        }
    }

    fn from_ipv4<T: AsRef<[u8]>>(packet: &Packet<T>, ipv4: Ipv4Viewer<&[u8]>) -> Self {
        let (src_port, dst_port, has_ports) = ports(packet);
        let flags = ipv4.flags().get();
        let fragment_offset = ipv4.fragment_offset().get();
        let src = IpAddr::V4(ipv4.src().get());
        let dst = IpAddr::V4(ipv4.dst().get());
        let proto = u8::from(ipv4.protocol().get());

        PacketInfo {
            src,
            dst,
            proto,
            src_port,
            dst_port,
            has_ports,
            fragment: (fragment_offset != 0 || flags & FRAG_MORE != 0).then_some(FragKey {
                src,
                dst,
                proto,
                id: u32::from(ipv4.identification().get()),
            }),
        }
    }

    fn from_ipv6<T: AsRef<[u8]>>(packet: &Packet<T>, ipv6: Ipv6Viewer<&[u8]>) -> Self {
        let (src_port, dst_port, has_ports) = ports(packet);
        let src = IpAddr::V6(ipv6.src().get());
        let dst = IpAddr::V6(ipv6.dst().get());

        // The protocol is the `next header` behind the extension header chain,
        // so a transport behind an extension header (Hop-by-Hop -> SCTP, for
        // example) is reported with its own protocol number.
        let proto = next_header(packet).unwrap_or_else(|| u8::from(ipv6.next_header().get()));

        // The fragment header, when present, is what groups the fragments of one
        // datagram; every fragment names the header that follows the fragment
        // header, so the key is the same for all of them.
        let fragment = outer_fragment(packet).map(|frag| FragKey {
            src,
            dst,
            proto: u8::from(frag.next_header().get()),
            id: frag.identification().get(),
        });

        PacketInfo {
            src,
            dst,
            proto,
            src_port,
            dst_port,
            has_ports,
            fragment,
        }
    }

    /// Session of this packet, when it carries ports.
    pub fn session(&self) -> Option<SessionId> {
        self.has_ports
            .then(|| SessionId::new(self.src, self.src_port, self.dst, self.dst_port, self.proto))
    }
}

/// More fragments flag of the IPv4 header (the low bit of the flag field).
const FRAG_MORE: u8 = 0x1;

/// Source and destination ports of the packet, when it has a transport header.
fn ports<T: AsRef<[u8]>>(packet: &Packet<T>) -> (u16, u16, bool) {
    // Only the transport of the outermost IP packet has ports: a tunnelled
    // packet carries the ports of its inner packet, which belongs to the inner
    // addresses.
    match outer_transport(packet) {
        Some(IpProtocol::Tcp) => packet
            .nth_layer_viewer(Tcp, -1)
            .map_or((0, 0, false), |tcp| {
                (tcp.src_port().get(), tcp.dst_port().get(), true)
            }),
        Some(IpProtocol::Udp) => packet
            .nth_layer_viewer(Udp, -1)
            .map_or((0, 0, false), |udp| {
                (udp.src_port().get(), udp.dst_port().get(), true)
            }),
        _ => (0, 0, false),
    }
}

/// Write the targets into the packet, one family at a time.
///
/// A target of the other family is skipped; validation makes that impossible
/// for a configured entry.
pub fn apply_targets<T: AsRef<[u8]> + AsMut<[u8]>>(packet: &mut Packet<T>, targets: Targets) {
    match outer_ip_family(packet) {
        Some(IpFamily::V4) => {
            let Some(mut ipv4) = outer_ipv4_mut(packet) else {
                return;
            };

            if let Some(IpAddr::V4(src)) = targets.src {
                ipv4.src_mut().set(src);
            }
            if let Some(IpAddr::V4(dst)) = targets.dst {
                ipv4.dst_mut().set(dst);
            }
        }
        Some(IpFamily::V6) => {
            let Some(mut ipv6) = outer_ipv6_mut(packet) else {
                return;
            };

            if let Some(IpAddr::V6(src)) = targets.src {
                ipv6.src_mut().set(src);
            }
            if let Some(IpAddr::V6(dst)) = targets.dst {
                ipv6.dst_mut().set(dst);
            }
        }
        None => {}
    }
}

/// The transport segment of the outermost IP packet, i.e. exactly the bytes its
/// transport checksum covers.
///
/// The transport header does not start right after the IP header when there are
/// extension headers (IPv6), and `Layer::len` records the header only, so the end
/// is taken from the length the IP header declares.
pub fn transport_segment<T: AsRef<[u8]>>(packet: &Packet<T>) -> Option<&[u8]> {
    let bytes = packet.as_bytes();
    let (ip_offset, header_len, payload_len) = match outer_ip_family(packet)? {
        IpFamily::V4 => {
            let ipv4 = outer_ipv4(packet)?;
            let header_len = ipv4.header_len();
            let total_length = usize::from(ipv4.total_length().get());

            // A total length below the header length is malformed; only a zero
            // one means offload (or a jumbogram), where the captured bytes are
            // the segment.
            if total_length != 0 && total_length < header_len {
                return None;
            }

            (
                packet.nth_layer_range(Ipv4, -1)?.start,
                header_len,
                total_length.saturating_sub(header_len),
            )
        }
        IpFamily::V6 => (
            packet.nth_layer_range(Ipv6, -1)?.start,
            Ipv6::MIN_LEN,
            usize::from(outer_ipv6(packet)?.payload_length().get()),
        ),
    };

    let l4_offset = match outer_transport(packet)? {
        IpProtocol::Tcp => packet.nth_layer_range(Tcp, -1),
        IpProtocol::Udp => packet.nth_layer_range(Udp, -1),
        IpProtocol::Ipv6Icmp => packet.nth_layer_range(Icmpv6, -1),
        _ => None,
    }?
    .start;

    if l4_offset < ip_offset + header_len {
        return None;
    }

    // A zero payload length means the sender used offload (or a jumbogram); fall
    // back to everything that is captured.
    let end = if payload_len == 0 {
        bytes.len()
    } else {
        ip_offset + header_len + payload_len
    };

    bytes.get(l4_offset..end)
}
