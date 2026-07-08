//! TCP packet crafting.
//!
//! The TCP builder writes a TCP segment into the final packet buffer. It
//! calculates the TCP checksum when an IPv4 parent supplies pseudo-header
//! context; standalone TCP segments default to checksum zero unless set.

use super::{Tcp, TcpFlags, TcpViewer};
use crate::packet::craft::{
    CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan, checked_add_len,
    checked_u16_len,
};

/// Builder for TCP segments.
///
/// If not explicitly set, data offset is derived from option length, flags are
/// empty, sequence/acknowledgment numbers are zero, and window size defaults
/// to 64.
#[derive(Debug, Clone, Default)]
pub struct TcpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    seq_num: Option<u32>,
    ack_num: Option<u32>,
    data_offset: Option<u8>,
    flags: Option<TcpFlags>,
    window_size: Option<u16>,
    checksum: Option<u16>,
    urgent_pointer: Option<u16>,
    options: Vec<u8>,
}

impl TcpBuilder {
    /// Create an empty TCP builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source port.
    pub fn src_port(mut self, src_port: u16) -> Self {
        self.src_port = Some(src_port);
        self
    }

    /// Set the source port.
    ///
    /// This is a short alias for [`src_port`](TcpBuilder::src_port).
    pub fn src(self, src_port: u16) -> Self {
        self.src_port(src_port)
    }

    /// Set the destination port.
    pub fn dst_port(mut self, dst_port: u16) -> Self {
        self.dst_port = Some(dst_port);
        self
    }

    /// Set the destination port.
    ///
    /// This is a short alias for [`dst_port`](TcpBuilder::dst_port).
    pub fn dst(self, dst_port: u16) -> Self {
        self.dst_port(dst_port)
    }

    /// Set the sequence number.
    pub fn seq_num(mut self, seq_num: u32) -> Self {
        self.seq_num = Some(seq_num);
        self
    }

    /// Set the sequence number.
    ///
    /// This is a short alias for [`seq_num`](TcpBuilder::seq_num).
    pub fn seq(self, seq_num: u32) -> Self {
        self.seq_num(seq_num)
    }

    /// Set the acknowledgment number.
    pub fn ack_num(mut self, ack_num: u32) -> Self {
        self.ack_num = Some(ack_num);
        self
    }

    /// Set the acknowledgment number.
    ///
    /// This is a short alias for [`ack_num`](TcpBuilder::ack_num).
    pub fn ack(self, ack_num: u32) -> Self {
        self.ack_num(ack_num)
    }

    /// Set the data offset field in 32-bit words.
    ///
    /// Normally this should be omitted so the builder can derive it from the
    /// padded option length.
    pub fn data_offset(mut self, data_offset: u8) -> Self {
        self.data_offset = Some(data_offset);
        self
    }

    /// Set the flags field.
    pub fn flags(mut self, flags: impl Into<TcpFlags>) -> Self {
        self.flags = Some(flags.into());
        self
    }

    /// Set the window size field.
    pub fn window_size(mut self, window_size: u16) -> Self {
        self.window_size = Some(window_size);
        self
    }

    /// Set the window size field.
    ///
    /// This is a short alias for [`window_size`](TcpBuilder::window_size).
    pub fn window(self, window_size: u16) -> Self {
        self.window_size(window_size)
    }

    /// Set the checksum field.
    ///
    /// If unset and an IPv4 parent exists, the checksum is calculated from the
    /// IPv4 pseudo-header and final TCP bytes.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    /// Set the urgent pointer field.
    pub fn urgent_pointer(mut self, urgent_pointer: u16) -> Self {
        self.urgent_pointer = Some(urgent_pointer);
        self
    }

    /// Append raw TCP option bytes.
    ///
    /// The builder pads the option area to a 32-bit boundary when calculating
    /// and writing the data offset.
    pub fn options(mut self, options: impl AsRef<[u8]>) -> Self {
        self.options.extend_from_slice(options.as_ref());
        self
    }

    /// Calculate the final TCP header length and validate explicit data offset.
    ///
    /// Options are padded to a 32-bit boundary for data-offset calculation. If
    /// the user supplied a data offset, it must cover the padded options and be
    /// at most 15 words.
    fn measure_header_len(&self) -> Result<usize, CraftError> {
        let options_len = self.options.len().next_multiple_of(4);
        let min_header_len = checked_add_len("tcp", "data_offset", Tcp::MIN_LEN, options_len)?;
        let min_data_offset = min_header_len / 4;
        let data_offset = self.data_offset.unwrap_or(min_data_offset as u8);

        if data_offset < 5 {
            return Err(CraftError::InvalidField {
                protocol: "tcp",
                field: "data_offset",
                value: data_offset as usize,
                reason: "data offset must be at least 5",
            });
        }
        if data_offset > 15 {
            return Err(CraftError::LengthOverflow {
                protocol: "tcp",
                field: "data_offset",
                len: data_offset as usize,
                max: 15,
            });
        }

        let header_len = data_offset as usize * 4;
        if header_len < min_header_len {
            return Err(CraftError::InvalidLength {
                protocol: "tcp",
                field: "data_offset",
                len: header_len,
                min: min_header_len,
            });
        }

        Ok(header_len)
    }
}

impl CraftLayer for TcpBuilder {
    /// Return the TCP protocol marker used in crafted layer metadata.
    fn protocol(&self) -> &'static dyn crate::packet::layer::Protocol {
        &Tcp
    }

    /// Measure the TCP header, segment length, and child offset.
    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        let header_len = self.measure_header_len()?;
        let child_len = child.map_or(0, |child| child.len());
        let segment_len = checked_add_len("tcp", "segment_len", header_len, child_len)?;
        checked_u16_len("tcp", "ipv4_pseudo_length", segment_len)?;

        Ok(CraftPlan::new(header_len, segment_len))
    }

    /// Write the TCP header and checksum.
    ///
    /// Child bytes have already been written at the measured child offset.
    fn write(
        &self,
        context: CraftContext,
        plan: CraftPlan,
        _child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        let header_len = plan.layer_len();
        bytes[Tcp::MIN_LEN..Tcp::MIN_LEN + self.options.len()].copy_from_slice(&self.options);

        {
            let mut tcp = TcpViewer::new(&mut bytes[..header_len]);
            tcp.src_port_mut().set(self.src_port.unwrap_or_default());
            tcp.dst_port_mut().set(self.dst_port.unwrap_or_default());
            tcp.seq_num_mut().set(self.seq_num.unwrap_or_default());
            tcp.ack_num_mut().set(self.ack_num.unwrap_or_default());
            tcp.data_offset_mut().set((header_len / 4) as u8);
            tcp.flags_mut().set(self.flags.unwrap_or_default());
            tcp.window_size_mut().set(self.window_size.unwrap_or(64));
            tcp.checksum_mut().set(0);
            tcp.urgent_pointer_mut()
                .set(self.urgent_pointer.unwrap_or_default());
        }

        let checksum = self.checksum.unwrap_or_else(|| {
            context
                .ipv4
                .map(|ctx| TcpViewer::new(&bytes[..]).calculate_checksum_ipv4(ctx.src, ctx.dst))
                .unwrap_or_default()
        });
        TcpViewer::new(&mut bytes[..header_len])
            .checksum_mut()
            .set(checksum);

        Ok(())
    }
}

crate::impl_craft_layer_div!(TcpBuilder);

/// Create a TCP builder.
///
/// Fields map to [`TcpBuilder`] methods. A field without a value calls a
/// zero-argument method; a field with `: value` passes that value to the
/// method.
#[macro_export]
macro_rules! tcp {
    () => {
        $crate::packet::layer::tcp::TcpBuilder::new()
    };

    ($($field:ident $( : $value:expr )?),+ $(,)?) => {
        $crate::packet::layer::tcp::TcpBuilder::new()
            $(.$field($($value)?))+
    };
}
