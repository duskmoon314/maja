//! The two options extension headers: Hop-by-Hop and Destination Options.
//!
//! [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html) gives both headers the
//! same layout ([section 4.3](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.3)
//! and [section 4.6](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.6)), which
//! lives in [`header`]: a `Next Header` octet, a `Hdr Ext Len` octet and
//! an option area.
//!
//! - [`Ipv6Hopopt`] follows the IPv6 base header directly
//!   ([RFC 8200 section 4.3](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.3)).
//! - [`Ipv6DestOpts`] is processed by the destination
//!   ([section 4.6](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.6)).
//!
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                                                               |
//! .                                                               .
//! .                            Options                            .
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::packet::{
    ParseContext,
    error::ParseError,
    layer::{Protocol, ProtocolExt},
};

use super::header::{self, Ipv6ExtHeaderViewer};

/// Internet Protocol version 6 Hop-by-Hop Options header.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Hopopt;

impl Protocol for Ipv6Hopopt {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = Ipv6ExtHeaderViewer::new(bytes);

        write!(
            fmt,
            "[Ipv6Hopopt] next={} len={}",
            header.next_header().get(),
            header.header_len(),
        )
    }
}

impl ProtocolExt for Ipv6Hopopt {
    type Viewer<'a> = Ipv6ExtHeaderViewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6ExtHeaderViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        header::parse_ext_header(ctx, offset, &Ipv6Hopopt, header::MIN_LEN)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6ExtHeaderViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6ExtHeaderViewer::new(bytes)
    }
}

/// Internet Protocol version 6 Destination Options header.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6DestOpts;

impl Protocol for Ipv6DestOpts {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = Ipv6ExtHeaderViewer::new(bytes);

        write!(
            fmt,
            "[Ipv6DestOpts] next={} len={}",
            header.next_header().get(),
            header.header_len(),
        )
    }
}

impl ProtocolExt for Ipv6DestOpts {
    type Viewer<'a> = Ipv6ExtHeaderViewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6ExtHeaderViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        header::parse_ext_header(ctx, offset, &Ipv6DestOpts, header::MIN_LEN)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6ExtHeaderViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6ExtHeaderViewer::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::Protocol;
    use crate::packet::{
        Packet,
        layer::{
            eth::Eth,
            ip::{
                protocol::IpProtocol,
                v6::{
                    Ipv6,
                    ext::{
                        Ipv6DestOpts, Ipv6ExtHeaderViewer, Ipv6Hopopt,
                        option::{Ipv6Option, Ipv6OptionKind, Ipv6Options},
                    },
                },
            },
            udp::Udp,
        },
    };

    use super::*;

    /// Ethernet + IPv6 + an options header (protocol `protocol`) + `payload`.
    fn options_frame(protocol: u8, options: &[u8], next_header: u8, payload: &[u8]) -> Vec<u8> {
        let header_len = (header::MIN_LEN + options.len()).next_multiple_of(8);
        let mut header = vec![next_header, (header_len / 8 - 1) as u8];
        header.extend_from_slice(options);
        header.resize(header_len, 0);
        header.extend_from_slice(payload);

        super::super::test_util::eth_ipv6_frame(protocol, &header)
    }

    /// The five fields both options headers share, plus the header behind them.
    fn assert_shared_shape(
        header: &Ipv6ExtHeaderViewer<&[u8]>,
        body: &[u8],
        packet: &Packet<&[u8]>,
    ) {
        // The header length follows the `Hdr Ext Len` value: 8-octet units after
        // the first eight octets, so the option area is padded to the next one.
        let header_len = (header::MIN_LEN + body.len()).next_multiple_of(8);

        assert_eq!(header.next_header().get(), IpProtocol::Udp);
        assert_eq!(header.hdr_ext_len().get(), (header_len / 8 - 1) as u8);
        assert_eq!(header.header_len(), header_len);
        assert_eq!(header.data(), body);
        assert!(packet.layer_viewer(Ipv6).is_some());

        let udp = packet.layer_viewer(Udp).expect("udp layer");
        assert_eq!(udp.src_port().get(), 0x3039);
    }

    #[test]
    fn ipv6_hopopt_viewer() {
        // Pad1, PadN (2 octets), Router Alert, PadN (3 octets). The four options
        // fill the header exactly, so nothing here is implicit padding.
        let options = [
            0x00, // Pad1
            0x01, 0x02, 0x00, 0x00, // PadN
            0x05, 0x02, 0x00, 0x00, // Router Alert
            0x01, 0x03, 0x00, 0x00, 0x00, // PadN
        ];
        let data = options_frame(0, &options, 17, &super::super::test_util::udp_header());

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(
            super::super::test_util::layers(&packet),
            [&Eth as &dyn Protocol, &Ipv6, &Ipv6Hopopt, &Udp]
        );

        let hopopts = packet.layer_viewer(Ipv6Hopopt).expect("hopopts layer");
        assert_shared_shape(&hopopts, &options, &packet);

        assert_eq!(
            Ipv6Options::new(hopopts.data()).collect::<Vec<_>>(),
            vec![
                Ipv6Option::Pad1,
                Ipv6Option::Option {
                    kind: Ipv6OptionKind::PadN,
                    data: &[0x00, 0x00],
                },
                Ipv6Option::Option {
                    kind: Ipv6OptionKind::RouterAlert,
                    data: &[0x00, 0x00],
                },
                Ipv6Option::Option {
                    kind: Ipv6OptionKind::PadN,
                    data: &[0x00, 0x00, 0x00],
                },
            ]
        );
    }

    #[test]
    fn ipv6_dest_opts_viewer() {
        // Home Address (18 octets) and a PadN that fills the header exactly.
        let mut options = vec![0xc9, 0x10];
        options.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        options.extend_from_slice(&[0x01, 0x02, 0x00, 0x00]);
        let data = options_frame(60, &options, 17, &super::super::test_util::udp_header());

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(
            super::super::test_util::layers(&packet),
            [&Eth as &dyn Protocol, &Ipv6, &Ipv6DestOpts, &Udp]
        );

        let dstopts = packet.layer_viewer(Ipv6DestOpts).expect("dstopts layer");
        assert_shared_shape(&dstopts, &options, &packet);

        // The option area is the TLV stream the option iterator walks.
        let options: Vec<_> = Ipv6Options::new(dstopts.data()).collect();
        assert_eq!(options[0].kind(), Ipv6OptionKind::HomeAddress);
        assert_eq!(options[1].kind(), Ipv6OptionKind::PadN);
        assert_eq!(options[1].data().map(<[u8]>::len), Some(2));
    }
}
