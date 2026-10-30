//! Address rewriting for `maja-mergecap`.
//!
//! Two paths:
//!
//! * [`DirectMaps`] rewrites the source and/or destination field of every
//!   packet, without any notion of a key. This is the legacy behaviour of
//!   `ip_map` / `src_ip_map` / `dst_ip_map` and always draws per packet.
//! * [`FlowState`] implements the keyed `flow_map`: the role of an address is
//!   decided by the `from` network it belongs to, and the pool policy decides
//!   how a key gets its target.

mod entry;
mod flow;
mod packet;
mod pool;

use std::{cell::RefCell, collections::HashMap, path::Path, rc::Rc, sync::Once};

use anyhow::bail;
use log::warn;
use maja::packet::{
    Packet,
    layer::{
        icmpv6::{Icmpv6, Icmpv6Viewer},
        ip::{protocol::IpProtocol, v6::Ipv6Route},
        tcp::{Tcp, TcpViewer},
        udp::{Udp, UdpViewer},
    },
};
use rand::{SeedableRng, rngs::StdRng};

use crate::{
    config::{AllocScope, FlowMap, InputFile},
    map::{
        entry::DirectMaps,
        flow::{Allocation, FlowCfg, FlowState},
        packet::{
            IpFamily, PacketInfo, chain_viewer, outer_fragment, outer_ip_family, outer_ipv4,
            outer_ipv4_mut, outer_ipv6, outer_transport, transport_segment,
        },
    },
};

/// Salt used to derive the mapping rng from the seed.
///
/// The value is the first word of SHA-512's initial hash value (`frac(sqrt 2)`),
/// a well known "nothing up my sleeve" constant rather than a tuned magic
/// number. Its only job is to give the address mapping its own rng stream, so
/// that jitter or the parallel arrangement cannot shift the mapping of a given
/// `--seed`.
const MAP_RNG_SALT: u64 = 0x6a09_e667_f3bc_c908;

/// rng derived from a seed and a salt.
pub fn derived_rng(seed: u64, salt: u64) -> StdRng {
    StdRng::seed_from_u64(splitmix64(seed ^ salt))
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ============================= global allocation ===========================

/// State that outlives one input file: the allocation tables of
/// `alloc_scope = global`.
///
/// Files that carry the same `flow_map` share one table, so the mapping only
/// depends on the merged packet stream and the global seed, not on how the
/// packets were split into files.
#[derive(Default)]
pub struct MapRuntime {
    globals: HashMap<String, GlobalAllocation>,
}

struct GlobalAllocation {
    allocation: Rc<RefCell<Allocation>>,
    groups: usize,
}

impl MapRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    fn global_allocation(
        &mut self,
        flow: &FlowMap,
        cfg: &FlowCfg,
        seed: u64,
        groups: usize,
    ) -> anyhow::Result<Rc<RefCell<Allocation>>> {
        let key = format!("{flow:?}");

        if let Some(global) = self.globals.get(&key) {
            if global.groups != groups {
                bail!(
                    "`alloc_scope = global` needs the same `parallel` in every input file \
                     that shares this flow_map"
                );
            }
            return Ok(Rc::clone(&global.allocation));
        }

        let allocation = Rc::new(RefCell::new(Allocation::new(
            cfg,
            seed,
            flow.sharing(),
            groups,
        )));
        self.globals.insert(
            key,
            GlobalAllocation {
                allocation: Rc::clone(&allocation),
                groups,
            },
        );

        Ok(allocation)
    }
}

// ================================ rewriter =================================

/// Address rewriter of one input file.
pub struct Rewriter {
    direct: Option<DirectMaps>,
    flow: Option<FlowState>,
    fix_checksum: bool,
}

impl Rewriter {
    /// Build the rewriter for one input file.
    ///
    /// `file_seed` drives everything that is per file (the `random` groups and a
    /// `file` scoped allocation table); `global_seed` drives the stateless `hash`
    /// policy and a `global` scoped table, so neither depends on the file order.
    pub fn new<P: AsRef<Path>>(
        file: &InputFile<P>,
        runtime: &mut MapRuntime,
        file_seed: u64,
        global_seed: u64,
        groups: usize,
        fix_checksum: bool,
    ) -> anyhow::Result<Self> {
        let has_direct = !file.ip_map().is_empty()
            || !file.src_ip_map().is_empty()
            || !file.dst_ip_map().is_empty();

        let flow = match &file.flow_map {
            Some(flow) => {
                let cfg = FlowCfg::compile(flow)?;
                let allocation = match flow.alloc_scope {
                    AllocScope::File => None,
                    AllocScope::Global => {
                        Some(runtime.global_allocation(flow, &cfg, global_seed, groups)?)
                    }
                };

                if groups > 1 && cfg.uses_hash() {
                    warn!(
                        "{}: `hash` derives every target from the key, so the parallel groups \
                         are identical",
                        file.path.as_ref().display()
                    );
                }

                Some(FlowState::new(
                    cfg,
                    global_seed,
                    file_seed,
                    groups,
                    flow.sharing(),
                    allocation,
                ))
            }
            None => None,
        };

        Ok(Rewriter {
            direct: if has_direct {
                Some(DirectMaps::new(
                    file.src_ip_map(),
                    file.ip_map(),
                    file.dst_ip_map(),
                    derived_rng(file_seed, MAP_RNG_SALT),
                )?)
            } else {
                None
            },
            flow,
            fix_checksum,
        })
    }

    /// Whether any mapping is configured.
    pub fn is_active(&self) -> bool {
        self.direct.is_some() || self.flow.is_some()
    }

    /// Rewrite one packet of parallel group `group`.
    ///
    /// Returns whether any address was rewritten; checksums are only touched
    /// when something actually changed.
    pub fn rewrite<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        packet: &mut Packet<T>,
        group: usize,
    ) -> bool {
        let mut changed = false;

        if let Some(direct) = &mut self.direct {
            changed |= direct.rewrite(packet);
        }

        if let Some(flow) = &mut self.flow {
            changed |= flow.rewrite(packet, group);
        }

        if changed && self.fix_checksum {
            fix_checksums(packet);
        }

        changed
    }
}

/// Recompute the checksums an address change invalidated.
///
/// IPv4 has a header checksum of its own; IPv6 has none. The transport checksum
/// covers the whole segment plus a pseudo header with the addresses, so it is
/// recomputed for TCP, UDP and (on IPv6) ICMPv6. Fragmented datagrams are left
/// alone: their checksum covers all fragments, which this tool does not
/// reassemble, so any value computed from one fragment would be wrong.
fn fix_checksums<T: AsRef<[u8]> + AsMut<[u8]>>(packet: &mut Packet<T>) {
    match outer_ip_family(packet) {
        Some(IpFamily::V4) => {
            if let Some(mut ipv4) = outer_ipv4_mut(packet) {
                let checksum = ipv4.calculate_checksum();
                ipv4.checksum_mut().set(checksum);
            }

            if PacketInfo::read(packet).is_some_and(|info| info.fragment.is_some()) {
                return;
            }

            // Only the transport of the outermost packet is fixed: a tunnel keeps
            // its own transport header, and the checksum of an inner packet covers
            // the inner addresses. `outer_transport` names that transport, so it
            // also selects the layer to fix (`VXLAN` has an outer UDP and an inner
            // TCP).
            let Some(protocol) = outer_transport(packet) else {
                return;
            };
            let Some(ipv4) = outer_ipv4(packet) else {
                return;
            };
            let (src, dst) = (ipv4.src().get(), ipv4.dst().get());

            match protocol {
                IpProtocol::Tcp => {
                    let Some(segment) = transport_segment(packet) else {
                        return;
                    };
                    let checksum = TcpViewer::new(segment).calculate_checksum_ipv4(src, dst);
                    if let Some(mut tcp) = packet.nth_layer_viewer_mut(Tcp, -1) {
                        tcp.checksum_mut().set(checksum);
                    }
                }
                IpProtocol::Udp => {
                    // A stored zero means the checksum is disabled on IPv4.
                    if packet
                        .nth_layer_viewer(Udp, -1)
                        .is_some_and(|udp| udp.checksum().get() == 0)
                    {
                        return;
                    }
                    let Some(segment) = transport_segment(packet) else {
                        return;
                    };
                    let checksum = UdpViewer::new(segment).calculate_checksum_ipv4(src, dst);
                    if let Some(mut udp) = packet.nth_layer_viewer_mut(Udp, -1) {
                        udp.checksum_mut().set(checksum);
                    }
                }
                _ => {}
            }
        }
        Some(IpFamily::V6) => {
            if outer_fragment(packet).is_some() {
                return;
            }

            let Some(protocol) = outer_transport(packet) else {
                return;
            };
            let Some(ipv6) = outer_ipv6(packet) else {
                return;
            };
            let (src, dst) = (ipv6.src().get(), ipv6.dst().get());
            // The pseudo header does not always use the destination of the IPv6
            // header; see `pseudo_header_dst`.
            let Some(dst) = pseudo_header_dst(packet, dst) else {
                return;
            };

            let Some(segment) = transport_segment(packet) else {
                return;
            };

            match protocol {
                IpProtocol::Tcp => {
                    let checksum = TcpViewer::new(segment).calculate_checksum_ipv6(src, dst);
                    if let Some(mut tcp) = packet.nth_layer_viewer_mut(Tcp, -1) {
                        tcp.checksum_mut().set(checksum);
                    }
                }
                IpProtocol::Udp => {
                    // The checksum is mandatory on IPv6, so it is always
                    // recomputed.
                    let checksum = UdpViewer::new(segment).calculate_checksum_ipv6(src, dst);
                    if let Some(mut udp) = packet.nth_layer_viewer_mut(Udp, -1) {
                        udp.checksum_mut().set(checksum);
                    }
                }
                IpProtocol::Ipv6Icmp => {
                    let checksum = Icmpv6Viewer::new(segment).calculate_checksum_ipv6(src, dst);
                    if let Some(mut icmpv6) = packet.nth_layer_viewer_mut(Icmpv6, -1) {
                        icmpv6.checksum_mut().set(checksum);
                    }
                }
                _ => {}
            }
        }
        None => {}
    }
}

/// Return the destination address of the transport pseudo header.
///
/// [RFC 8200 section 8.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1):
/// a packet that still has to visit Routing header segments uses the final
/// destination of the route in its pseudo header, not the destination of the IPv6
/// header. The final destination is the last address of a source route list and
/// the first address of a Segment Routing segment list, because that list is
/// encoded starting from the last segment.
///
/// `None` means the final destination cannot be determined, because the routing
/// type is one this tool does not decode; the transport checksum is then left as
/// it is instead of being computed from the wrong address.
fn pseudo_header_dst<T: AsRef<[u8]>>(
    packet: &Packet<T>,
    dst: std::net::Ipv6Addr,
) -> Option<std::net::Ipv6Addr> {
    // Only a routing header of the outermost packet changes the pseudo header:
    // one inside an encapsulated packet belongs to the inner addresses.
    let Some(route) = chain_viewer(packet, Ipv6Route) else {
        return Some(dst);
    };

    if route.segments_left().get() == 0 {
        return Some(dst);
    }

    let final_dst = route
        .type0()
        .and_then(|type0| type0.addrs().last())
        .or_else(|| route.srh().and_then(|srh| srh.segments().next()));

    if final_dst.is_none() {
        WARN_UNKNOWN_ROUTE.call_once(|| {
            warn!(
                "routing header type {} has segments left but no address this tool can read; \
                 leaving the transport checksum unchanged",
                route.routing_type().get()
            );
        });
    }

    final_dst
}

/// Guards the warning about a routing header whose final destination cannot be
/// read, so a capture full of such packets logs it once.
static WARN_UNKNOWN_ROUTE: Once = Once::new();

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, net::Ipv6Addr, path::PathBuf};

    use maja::prelude::*;

    use super::*;
    use crate::config::{InputFile, MapEntry, Target};

    fn entry(from: Option<&str>, to: &str) -> MapEntry {
        MapEntry {
            from: from.map(|from| from.parse().unwrap()),
            to: Target::try_from(to.to_string()).unwrap(),
            shape: None,
            policy: None,
        }
    }

    fn make_rewriter(entries: Vec<MapEntry>, fix_checksum: bool) -> Rewriter {
        let flow = FlowMap {
            entries,
            ..Default::default()
        };
        let file = InputFile {
            path: PathBuf::from("test.pcap"),
            flow_map: Some(flow),
            ..Default::default()
        };

        Rewriter::new(&file, &mut MapRuntime::new(), 1, 7, 1, fix_checksum).unwrap()
    }

    fn addrs4(packet: &CraftedPacket) -> (Ipv4Addr, Ipv4Addr) {
        let ipv4 = packet.nth_layer_viewer(Ipv4, -1).expect("ipv4 layer");
        (ipv4.src().get(), ipv4.dst().get())
    }

    fn tcp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> CraftedPacket {
        (eth!() / ipv4!(src: src, dst: dst) / tcp!(src: 1234, dst: 80) / raw!(b"payload"))
            .build()
            .unwrap()
    }

    /// Ethernet + IPv6 (`next_header`) + `payload`.
    fn ipv6_frame(next_header: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x33, 0x33, 0x00, 0x00, 0x00, 0x02, // destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source MAC
            0x86, 0xdd, // EtherType: IPv6
            0x60, 0x00, 0x00, 0x00, // version, traffic class, flow label
        ];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.push(next_header);
        frame.push(0x40); // hop limit
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        frame.extend_from_slice(payload);

        frame
    }

    fn tcp_segment(sport: u16, dport: u16) -> Vec<u8> {
        let mut segment = vec![];
        segment.extend_from_slice(&sport.to_be_bytes());
        segment.extend_from_slice(&dport.to_be_bytes());
        segment.extend_from_slice(&1u32.to_be_bytes()); // sequence
        segment.extend_from_slice(&0u32.to_be_bytes()); // acknowledgement
        segment.extend_from_slice(&(5u16 << 12).to_be_bytes()); // data offset
        segment.extend_from_slice(&[0x10, 0x00]); // flags, window
        segment.extend_from_slice(&[0x00, 0x00]); // checksum
        segment.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        segment.extend_from_slice(b"payload");

        segment
    }

    #[test]
    fn checksums_are_recomputed() {
        let mut rewriter = make_rewriter(
            vec![
                entry(Some("192.168.0.0/16"), "10.0.0.0/24"),
                entry(Some("203.0.113.0/24"), "10.1.0.0/24"),
            ],
            true,
        );

        let mut packet = tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(203, 0, 113, 80),
        );
        rewriter.rewrite(&mut packet, 0);

        let (src, dst) = {
            let ipv4 = packet.nth_layer_viewer(Ipv4, -1).unwrap();
            (ipv4.src().get(), ipv4.dst().get())
        };
        assert!(
            packet
                .nth_layer_viewer(Ipv4, -1)
                .unwrap()
                .validate_checksum()
        );
        assert!(
            TcpViewer::new(transport_segment(&packet).unwrap()).validate_checksum_ipv4(src, dst)
        );
    }

    #[test]
    fn checksum_fix_can_be_disabled() {
        let mut rewriter = make_rewriter(vec![entry(Some("192.168.0.0/16"), "10.0.0.0/24")], false);

        let mut packet = tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(203, 0, 113, 80),
        );
        let before = packet.nth_layer_viewer(Tcp, -1).unwrap().checksum().get();
        rewriter.rewrite(&mut packet, 0);

        assert_eq!(
            packet.nth_layer_viewer(Tcp, -1).unwrap().checksum().get(),
            before
        );
        assert_ne!(addrs4(&packet).0, Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn v6_transport_checksums_are_recomputed() {
        let src = Ipv6Addr::new(0x3ffe, 0x507, 0, 1, 0x200, 0x86ff, 0xfe05, 0x80da);
        let dst = Ipv6Addr::new(0x3ffe, 0x501, 0, 0x1001, 0, 0, 0, 2);

        // Start from a segment whose checksum is correct for the original
        // addresses, so the rewrite has something to invalidate.
        let mut segment = tcp_segment(40000, 80);
        let base = ipv6_frame(6, src, dst, &segment);
        let checksum = {
            let mut packet = Packet::new(base.as_slice());
            packet.parse::<Eth>(Default::default());
            TcpViewer::new(transport_segment(&packet).unwrap()).calculate_checksum_ipv6(src, dst)
        };
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        let frame = ipv6_frame(6, src, dst, &segment);
        let mut packet = Packet::new(frame);
        packet.parse::<Eth>(Default::default());
        assert!(
            TcpViewer::new(transport_segment(&packet).unwrap()).validate_checksum_ipv6(src, dst)
        );

        let mut rewriter = make_rewriter(
            vec![entry(Some("3ffe:507:0:1::/64"), "2001:db8:1::/64")],
            true,
        );
        rewriter.rewrite(&mut packet, 0);

        let (new_src, new_dst) = {
            let ipv6 = packet.nth_layer_viewer(Ipv6, -1).unwrap();
            (ipv6.src().get(), ipv6.dst().get())
        };
        assert!(
            "2001:db8:1::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap()
                .contains(&new_src),
            "{new_src}"
        );
        assert!(
            TcpViewer::new(transport_segment(&packet).unwrap())
                .validate_checksum_ipv6(new_src, new_dst)
        );
    }

    /// Ethernet + IPv6 + Segment Routing header (type 4) + TCP segment.
    ///
    /// `segments_left` is 1, so the transport pseudo header has to use the first
    /// segment as the final destination, not the destination of the IPv6 header.
    fn srh_frame() -> Vec<u8> {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0xaa, 0, 0, 0, 0, 2);
        let final_dst = Ipv6Addr::new(0x2001, 0xdb8, 0xbb, 0, 0, 0, 0, 2);

        let mut srh = vec![
            6, // next header: TCP
            4, // header extension length: (4 + 1) * 8 = 40 octets
            4, // routing type: segment routing
            1, // segments left
            1, // last entry
            0, // flags
            0, 0, // tag
        ];
        srh.extend_from_slice(&final_dst.octets());
        srh.extend_from_slice(&dst.octets());
        srh.extend_from_slice(&tcp_segment(40000, 80));

        ipv6_frame(43, src, dst, &srh)
    }

    #[test]
    fn a_routing_header_moves_the_pseudo_header_destination() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let final_dst = Ipv6Addr::new(0x2001, 0xdb8, 0xbb, 0, 0, 0, 0, 2);

        // Checksum the segment for the final destination of the route.
        let mut packet = Packet::new(srh_frame());
        packet.parse::<Eth>(Default::default());
        let checksum = TcpViewer::new(transport_segment(&packet).unwrap())
            .calculate_checksum_ipv6(src, final_dst);
        packet
            .nth_layer_viewer_mut(Tcp, -1)
            .unwrap()
            .checksum_mut()
            .set(checksum);

        let mut rewriter =
            make_rewriter(vec![entry(Some("2001:db8::/32"), "2001:db8:99::/48")], true);
        rewriter.rewrite(&mut packet, 0);

        let new_src = packet.nth_layer_viewer(Ipv6, -1).unwrap().src().get();
        let new_dst = packet.nth_layer_viewer(Ipv6, -1).unwrap().dst().get();
        let tcp = TcpViewer::new(transport_segment(&packet).unwrap());

        assert_ne!(new_src, src);
        assert!(
            tcp.validate_checksum_ipv6(new_src, final_dst),
            "the pseudo header keeps the final destination of the route"
        );
        assert!(
            !tcp.validate_checksum_ipv6(new_src, new_dst),
            "the destination of the IPv6 header is not the pseudo header one"
        );
    }

    #[test]
    fn a_fragmented_datagram_keeps_its_transport_checksum() {
        let mut rewriter = make_rewriter(vec![entry(Some("192.168.0.0/16"), "10.0.0.0/24")], true);

        let mut first = (eth!()
            / ipv4!(
                src: Ipv4Addr::new(192, 168, 1, 10),
                dst: Ipv4Addr::new(203, 0, 113, 80),
                identification: 3,
                flags: 1,
                protocol: IpProtocol::Tcp
            )
            / tcp!(src: 1234, dst: 80)
            / raw!(b"fragment"))
        .build()
        .unwrap();
        let before = first.nth_layer_viewer(Tcp, -1).unwrap().checksum().get();
        rewriter.rewrite(&mut first, 0);

        // The IPv4 header is fixed, the transport checksum is not: it covers all
        // fragments, which this tool does not reassemble.
        assert!(
            first
                .nth_layer_viewer(Ipv4, -1)
                .unwrap()
                .validate_checksum()
        );
        assert_eq!(
            first.nth_layer_viewer(Tcp, -1).unwrap().checksum().get(),
            before
        );
    }
}
