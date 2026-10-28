//! The IPv6 next-header dispatcher.
//!
//! The base header and every extension header name the next protocol in their
//! next-header octet, and hand that value to the same [`dispatch`] function.

use crate::packet::{
    ParseContext,
    error::ParseError,
    layer::{
        Protocol,
        ip::{ah::Ah, esp::Esp, protocol::IpProtocol},
    },
};

use super::{
    Ipv6,
    ext::{Ipv6DestOpts, Ipv6Frag, Ipv6Hip, Ipv6Hopopt, Ipv6Mobility, Ipv6Route, Ipv6Shim6},
};

/// Parse the protocol that follows an IPv6 header or an extension header.
#[inline]
pub fn dispatch(
    ctx: &mut ParseContext,
    offset: usize,
    next_header: IpProtocol,
) -> Result<(), ParseError> {
    match next_header {
        IpProtocol::Hopopt => ctx.parse_child::<Ipv6Hopopt>(offset),
        IpProtocol::Ipv6Opts => ctx.parse_child::<Ipv6DestOpts>(offset),
        IpProtocol::Ipv6Route => ctx.parse_child::<Ipv6Route>(offset),
        IpProtocol::Ipv6Frag => ctx.parse_child::<Ipv6Frag>(offset),
        IpProtocol::Ah => ctx.parse_child::<Ah>(offset),
        IpProtocol::MobilityHeader => ctx.parse_child::<Ipv6Mobility>(offset),
        IpProtocol::Hip => ctx.parse_child::<Ipv6Hip>(offset),
        IpProtocol::Shim6 => ctx.parse_child::<Ipv6Shim6>(offset),
        // ESP and `no next header` end the chain.
        IpProtocol::Esp => ctx.parse_child::<Esp>(offset),
        IpProtocol::Ipv6NoNxt => {
            ctx.parse_raw(offset);
            Ok(())
        }
        IpProtocol::Tcp => ctx.parse_child::<crate::packet::layer::tcp::Tcp>(offset),
        IpProtocol::Udp => ctx.parse_child::<crate::packet::layer::udp::Udp>(offset),
        IpProtocol::Gre => ctx.parse_child::<crate::packet::layer::gre::Gre>(offset),
        IpProtocol::Sctp => ctx.parse_child::<crate::packet::layer::sctp::Sctp>(offset),
        IpProtocol::Ipv6Icmp => ctx.parse_child::<crate::packet::layer::icmpv6::Icmpv6>(offset),
        IpProtocol::Ipv4 => ctx.parse_child::<crate::packet::layer::ip::v4::Ipv4>(offset),
        IpProtocol::Ipv6 => ctx.parse_child::<Ipv6>(offset),
        protocol
            if ctx
                .options
                .registry
                .contains_key(&(Ipv6.id(), protocol.into())) =>
        {
            let parse_fn = ctx.options.registry[&(Ipv6.id(), protocol.into())];
            ctx.parse_child_with(parse_fn, offset)
        }
        _ => {
            ctx.parse_raw(offset);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use crate::packet::layer::ip::v6::ext::test_util::{eth_ipv6_frame, layers, udp_header};
    use crate::packet::layer::{Protocol, eth::Eth, ip::v6::Ipv6, raw::Raw, udp::Udp};

    /// Every extension header of the IANA list records its own layer, and the
    /// protocol behind it is parsed — or, when it ends the chain, recorded raw.
    #[test]
    fn every_extension_header_layer_is_parsed() {
        // An eight-octet header whose next header is UDP, a Fragment header with
        // offset 0, a twelve-octet AH, and ESP (no readable next header).
        let udp_next = [17, 0, 0, 0, 0, 0, 0, 0];
        let frag_next = [17, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        let ah_next = [17, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2];
        let esp_header = [0, 0, 0, 1, 0, 0, 0, 2];
        // Mobility: payload proto UDP, Header Len 0; HIP: the 40-octet fixed
        // part (Header Length 4); Shim6: a control message of type I1.
        let mobility_next = [17, 0, 5, 0, 0x12, 0x34, 0, 0];
        let mut hip_next = vec![17, 4, 1, 0, 0x12, 0x34, 0, 1];
        hip_next.extend_from_slice(&[0x11; 32]);
        let shim6_next = [17, 0, 1, 0, 0x12, 0x34, 0, 0];

        let cases: &[(u8, &[&dyn Protocol], &[u8])] = &[
            (0, &[&Eth, &Ipv6, &Ipv6Hopopt, &Udp], &udp_next),
            (43, &[&Eth, &Ipv6, &Ipv6Route, &Udp], &udp_next),
            (44, &[&Eth, &Ipv6, &Ipv6Frag, &Udp], &frag_next),
            (60, &[&Eth, &Ipv6, &Ipv6DestOpts, &Udp], &udp_next),
            (135, &[&Eth, &Ipv6, &Ipv6Mobility, &Udp], &mobility_next),
            (139, &[&Eth, &Ipv6, &Ipv6Hip, &Udp], &hip_next),
            (140, &[&Eth, &Ipv6, &Ipv6Shim6, &Udp], &shim6_next),
            (51, &[&Eth, &Ipv6, &Ah, &Udp], &ah_next),
            // ESP ends the chain, and nothing follows "no next header".
            (50, &[&Eth, &Ipv6, &Esp, &Raw], &esp_header),
            (59, &[&Eth, &Ipv6, &Raw], &[]),
            // An experimental value has no layout of its own: raw until a parser
            // is registered for it.
            (253, &[&Eth, &Ipv6, &Raw], &udp_next),
        ];

        for (protocol, expected, header) in cases {
            let mut payload = header.to_vec();
            payload.extend_from_slice(&udp_header());

            let data = eth_ipv6_frame(*protocol, &payload);
            let mut packet = Packet::new(data.as_slice());
            packet.parse::<Eth>(Default::default());

            assert_eq!(layers(&packet), *expected, "next header {protocol}");
        }
    }
}
