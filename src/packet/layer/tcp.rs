//! Transmission Control Protocol (TCP) parsing.
//!
//! TCP has a 20-byte fixed header followed by optional 32-bit-aligned option
//! bytes. The data offset field gives the total TCP header length in 32-bit
//! words. This parser records only the TCP header as the TCP layer; recognized
//! application payloads dispatch to child layers, and unknown payload bytes are
//! recorded as `Raw`.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Offset| Rsvd  |C|E|U|A|P|R|S|F|            Window             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |         Urgent Pointer        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Options (if Offset > 5)    |    Padding    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
//! ~                              ...                              ~
//! ```

use std::net::Ipv4Addr;

use crate::{
    field_spec,
    packet::{
        layer::{Protocol, ProtocolExt},
        utils::{
            checksum::ipv4_transport_checksum_zeroing,
            field::{FieldMut, FieldRef},
        },
    },
};

pub mod craft;
pub mod flags;
pub mod option;
pub use craft::TcpBuilder;
pub use flags::TcpFlags;
pub use option::{TcpOption, TcpOptionKind, TcpOptions};

/// Transmission Control Protocol (TCP) LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Tcp;

impl Tcp {
    /// Minimum TCP header length.
    const MIN_LEN: usize = 20;

    /// HTTPS TCP service port.
    pub const HTTPS_PORT: u16 = 443;

    /// SMTPS TCP service port.
    pub const SMTPS_PORT: u16 = 465;

    /// LDAPS TCP service port.
    pub const LDAPS_PORT: u16 = 636;

    /// DNS-over-TLS TCP service port.
    pub const DNS_OVER_TLS_PORT: u16 = 853;

    /// FTPS TCP service port.
    pub const FTPS_PORT: u16 = 990;

    /// IMAPS TCP service port.
    pub const IMAPS_PORT: u16 = 993;

    /// POP3S TCP service port.
    pub const POP3S_PORT: u16 = 995;

    /// Alternate HTTPS TCP service port commonly used by web services.
    pub const HTTPS_ALT_PORT: u16 = 8443;

    /// TCP service ports whose payloads may carry TLS records.
    pub const TLS_SERVICE_PORTS: [u16; 8] = [
        Self::HTTPS_PORT,
        Self::SMTPS_PORT,
        Self::LDAPS_PORT,
        Self::DNS_OVER_TLS_PORT,
        Self::FTPS_PORT,
        Self::IMAPS_PORT,
        Self::POP3S_PORT,
        Self::HTTPS_ALT_PORT,
    ];
}

impl Protocol for Tcp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tcp = TcpViewer::new(bytes);

        write!(
            fmt,
            "[Tcp] {:<5} -> {:<5} {}",
            tcp.src_port().get(),
            tcp.dst_port().get(),
            tcp.flags().get()
        )
    }
}

impl ProtocolExt for Tcp {
    type Viewer<'a> = TcpViewer<&'a [u8]>;
    type ViewerMut<'a> = TcpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut crate::packet::ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let min_header = ctx.require(&Tcp, offset, Tcp::MIN_LEN)?;

        let tcp = TcpViewer::new(min_header);
        let header_len = tcp.header_len();
        if header_len < Tcp::MIN_LEN {
            return Err(crate::packet::error::ParseError::Malformed {
                protocol: &Tcp,
                field: "data_offset",
                reason: "header length is smaller than the minimum TCP header length",
            });
        }

        let header = ctx.require(&Tcp, offset, header_len)?;

        ctx.push_layer(&Tcp, offset, header_len);

        let tcp = TcpViewer::new(header);
        let src_port = tcp.src_port().get();
        let dst_port = tcp.dst_port().get();
        let payload_offset = offset + header_len;
        let payload = ctx.bytes.get(payload_offset..).unwrap_or_default();

        match (src_port, dst_port) {
            (src, dst)
                if (is_tls_service_port(src) || is_tls_service_port(dst))
                    && crate::packet::layer::tls::looks_like_record(payload) =>
            {
                ctx.parse_child::<crate::packet::layer::tls::Tls>(payload_offset)?;
            }
            (_, port) if ctx.options.registry.contains_key(&(Tcp.id(), port.into())) => {
                let parse_fn = ctx.options.registry[&(Tcp.id(), port.into())];
                ctx.parse_child_with(parse_fn, payload_offset)?;
            }
            (port, _)
                if src_port != dst_port
                    && ctx.options.registry.contains_key(&(Tcp.id(), port.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Tcp.id(), port.into())];
                ctx.parse_child_with(parse_fn, payload_offset)?;
            }
            _ => ctx.parse_raw(payload_offset),
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        TcpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        TcpViewer::new(bytes)
    }
}

#[inline]
fn is_tls_service_port(port: u16) -> bool {
    Tcp::TLS_SERVICE_PORTS.contains(&port)
}

field_spec!(PortSpec, u16, u16);
field_spec!(SeqNumSpec, u32, u32);
field_spec!(AckNumSpec, u32, u32);
field_spec!(DataOffsetSpec, u8, u8, 0xF0, 4);
field_spec!(FlagsSpec, TcpFlags, u8);
field_spec!(WindowSizeSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(UrgentPointerSpec, u16, u16);

/// Transmission Control Protocol (TCP)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Acknowledgment Number                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Offset| Rsvd  |C|E|U|A|P|R|S|F|            Window             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |         Urgent Pointer        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options (if Offset > 5)    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Data                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct TcpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> TcpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field ranges of the source port: 0..2
    const FIELD_SRC_PORT: core::ops::Range<usize> = 0..2;
    /// Field ranges of the destination port: 2..4
    const FIELD_DST_PORT: core::ops::Range<usize> = 2..4;
    /// Field ranges of the sequence number: 4..8
    const FIELD_SEQ_NUM: core::ops::Range<usize> = 4..8;
    /// Field ranges of the acknowledgment number: 8..12
    const FIELD_ACK_NUM: core::ops::Range<usize> = 8..12;
    /// Field ranges of the data offset: 12..13
    const FIELD_DATA_OFFSET: core::ops::Range<usize> = 12..13;
    /// Field ranges of the flags: 13..14
    const FIELD_FLAGS: core::ops::Range<usize> = 13..14;
    /// Field ranges of the window size: 14..16
    const FIELD_WINDOW_SIZE: core::ops::Range<usize> = 14..16;
    /// Field ranges of the checksum: 16..18
    const FIELD_CHECKSUM: core::ops::Range<usize> = 16..18;
    /// Field ranges of the urgent pointer: 18..20
    const FIELD_URGENT_POINTER: core::ops::Range<usize> = 18..20;

    /// Create a new TcpViewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Return the TCP header length in octets.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.data_offset().get() as usize * 4
    }

    /// Get the raw TCP options bytes.
    #[inline]
    pub fn options(&self) -> &[u8] {
        let len = self.header_len().min(self.data.as_ref().len());
        if len <= Tcp::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Tcp::MIN_LEN..len]
        }
    }

    /// Iterate over TCP options.
    #[inline]
    pub fn option_iter(&self) -> TcpOptions<'_> {
        TcpOptions::new(self.options())
    }

    /// Calculate the TCP checksum using an IPv4 pseudo header.
    ///
    /// The checksum field is treated as zero during calculation. The viewer
    /// must contain the complete TCP segment, including payload bytes; TCP has
    /// no length field of its own, so this helper uses the full byte slice
    /// passed to [`new`](TcpViewer::new).
    #[inline]
    pub fn calculate_checksum_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        ipv4_transport_checksum_zeroing(src, dst, 6, self.data.as_ref(), Self::FIELD_CHECKSUM)
    }

    /// Return whether the TCP checksum is valid for the given IPv4 endpoints.
    ///
    /// The viewer must contain the complete TCP segment, including payload
    /// bytes, because the IPv4 pseudo-header checksum covers the whole segment.
    #[inline]
    pub fn validate_checksum_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        self.checksum().get() == self.calculate_checksum_ipv4(src, dst)
    }

    /// Get the accessor of the source port.
    #[inline]
    pub fn src_port(&self) -> FieldRef<'_, PortSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SRC_PORT])
    }

    /// Get the accessor of the destination port.
    #[inline]
    pub fn dst_port(&self) -> FieldRef<'_, PortSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DST_PORT])
    }

    /// Get the accessor of the sequence number.
    #[inline]
    pub fn seq_num(&self) -> FieldRef<'_, SeqNumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SEQ_NUM])
    }

    /// Get the accessor of the acknowledgment number.
    #[inline]
    pub fn ack_num(&self) -> FieldRef<'_, AckNumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ACK_NUM])
    }

    /// Get the accessor of the data offset.
    #[inline]
    pub fn data_offset(&self) -> FieldRef<'_, DataOffsetSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DATA_OFFSET])
    }

    /// Get the accessor of the flags.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of the window size.
    #[inline]
    pub fn window_size(&self) -> FieldRef<'_, WindowSizeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_WINDOW_SIZE])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the accessor of the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> FieldRef<'_, UrgentPointerSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_URGENT_POINTER])
    }
}

impl<T> TcpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable raw TCP options bytes.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let len = self.header_len().min(self.data.as_ref().len());
        let data = self.data.as_mut();
        if len <= Tcp::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Tcp::MIN_LEN..len]
        }
    }

    /// Get the mutable accessor of the source port.
    #[inline]
    pub fn src_port_mut(&mut self) -> FieldMut<'_, PortSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SRC_PORT])
    }

    /// Get the mutable accessor of the destination port.
    #[inline]
    pub fn dst_port_mut(&mut self) -> FieldMut<'_, PortSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DST_PORT])
    }

    /// Get the mutable accessor of the sequence number.
    #[inline]
    pub fn seq_num_mut(&mut self) -> FieldMut<'_, SeqNumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SEQ_NUM])
    }

    /// Get the mutable accessor of the acknowledgment number.
    #[inline]
    pub fn ack_num_mut(&mut self) -> FieldMut<'_, AckNumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ACK_NUM])
    }

    /// Get the mutable accessor of the data offset.
    #[inline]
    pub fn data_offset_mut(&mut self) -> FieldMut<'_, DataOffsetSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DATA_OFFSET])
    }

    /// Get the mutable accessor of the flags.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of the window size.
    #[inline]
    pub fn window_size_mut(&mut self) -> FieldMut<'_, WindowSizeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_WINDOW_SIZE])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable accessor of the urgent pointer.
    #[inline]
    pub fn urgent_pointer_mut(&mut self) -> FieldMut<'_, UrgentPointerSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_URGENT_POINTER])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_viewer() {
        let data: [u8; 20] = [
            0x00, 0x50, // src_port = 80
            0x00, 0x60, // dst_port = 96
            0x00, 0x00, 0x00, 0x00, // seq_num = 0
            0x00, 0x00, 0x00, 0x00, // ack_num = 0
            0x50, // data_offset = 5, reserved = 0
            0x02, // flags = 2, SYN
            0x20, 0x00, // window_size = 8192
            0x00, 0x00, // checksum = 0
            0x00, 0x00, // urgent_pointer = 0
        ];

        let tcp = TcpViewer::new(&data);

        assert_eq!(tcp.src_port(), 80);
        assert_eq!(tcp.dst_port(), 96);
        assert_eq!(tcp.seq_num(), 0);
        assert_eq!(tcp.ack_num(), 0);
        assert_eq!(tcp.data_offset(), 5);
        assert_eq!(tcp.flags(), TcpFlags::SYN);
        assert_eq!(tcp.window_size(), 8192);
        assert_eq!(tcp.checksum(), 0);
        assert_eq!(tcp.urgent_pointer(), 0);
    }

    #[test]
    fn tcp_options() {
        let data: [u8; 32] = [
            0x00, 0x50, // src_port = 80
            0x00, 0x60, // dst_port = 96
            0x00, 0x00, 0x00, 0x00, // seq_num = 0
            0x00, 0x00, 0x00, 0x00, // ack_num = 0
            0x80, // data_offset = 8, reserved = 0
            0x02, // flags = 2, SYN
            0x20, 0x00, // window_size = 8192
            0x00, 0x00, // checksum = 0
            0x00, 0x00, // urgent_pointer = 0
            0x02, 0x04, 0x05, 0xb4, // MSS
            0x01, // NOP
            0x03, 0x03, 0x07, // window scale
            0x04, 0x02, // SACK permitted
            0x00, 0x00, // EOL + padding
        ];

        let tcp = TcpViewer::new(&data);
        let options: Vec<_> = tcp.option_iter().collect();

        assert_eq!(tcp.header_len(), 32);
        assert_eq!(tcp.options().len(), 12);
        assert_eq!(
            options[0],
            TcpOption::Option {
                kind: TcpOptionKind::MaximumSegmentSize,
                len: 4,
                data: &[0x05, 0xb4],
            }
        );
        assert_eq!(options[0].maximum_segment_size(), Some(1460));
        assert_eq!(options[1], TcpOption::NoOperation);
        assert_eq!(
            options[2],
            TcpOption::Option {
                kind: TcpOptionKind::WindowScale,
                len: 3,
                data: &[0x07],
            }
        );
        assert_eq!(options[2].window_scale(), Some(7));
        assert_eq!(
            options[3],
            TcpOption::Option {
                kind: TcpOptionKind::SackPermitted,
                len: 2,
                data: &[],
            }
        );
        assert!(options[3].sack_permitted());
        assert_eq!(options[4], TcpOption::EndOfOptions);
    }

    #[test]
    fn tcp_checksum_helpers() {
        let src = Ipv4Addr::new(198, 51, 100, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let mut data = [
            0x30, 0x39, // src_port
            0x00, 0x50, // dst_port
            0x00, 0x00, 0x00, 0x01, // seq_num
            0x00, 0x00, 0x00, 0x00, // ack_num
            0x50, // data_offset = 5
            0x02, // flags = SYN
            0x20, 0x00, // window_size
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent_pointer
            b'h', b'i',
        ];

        {
            let mut tcp = TcpViewer::new(&mut data);
            let checksum = tcp.calculate_checksum_ipv4(src, dst);
            tcp.checksum_mut().set(checksum);
        }

        assert!(TcpViewer::new(&data).validate_checksum_ipv4(src, dst));

        data[21] = b'o';
        assert!(!TcpViewer::new(&data).validate_checksum_ipv4(src, dst));
    }
}
