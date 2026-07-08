//! IPv4 packet crafting.
//!
//! The IPv4 builder writes the IPv4 header into the final packet buffer and
//! calculates the IPv4 header checksum unless the caller supplies one. It also
//! passes IPv4 pseudo-header context to TCP and UDP children.

use std::net::Ipv4Addr;

use super::{Ipv4, Ipv4Viewer};
use crate::packet::{
    craft::{
        CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan,
        checked_add_len, checked_u16_len,
    },
    layer::{icmp::Icmp, ip::protocol::IpProtocol, tcp::Tcp, udp::Udp},
};

/// Builder for IPv4 packets.
///
/// If not explicitly set, IHL is derived from option length, total length is
/// derived from header + child length, TTL defaults to 64, and the protocol
/// field is inferred from TCP/UDP children.
#[derive(Debug, Clone, Default)]
pub struct Ipv4Builder {
    ihl: Option<u8>,
    dscp: Option<u8>,
    ecn: Option<u8>,
    total_length: Option<u16>,
    identification: Option<u16>,
    flags: Option<u8>,
    fragment_offset: Option<u16>,
    ttl: Option<u8>,
    protocol: Option<IpProtocol>,
    checksum: Option<u16>,
    src: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
    options: Vec<u8>,
}

impl Ipv4Builder {
    /// Create an empty IPv4 builder.
    ///
    /// Source and destination addresses default to `0.0.0.0`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IHL field in 32-bit words.
    ///
    /// Normally this should be omitted so the builder can derive it from the
    /// padded option length.
    pub fn ihl(mut self, ihl: u8) -> Self {
        self.ihl = Some(ihl);
        self
    }

    /// Set the DSCP field.
    pub fn dscp(mut self, dscp: u8) -> Self {
        self.dscp = Some(dscp);
        self
    }

    /// Set the ECN field.
    pub fn ecn(mut self, ecn: u8) -> Self {
        self.ecn = Some(ecn);
        self
    }

    /// Set the total length field.
    ///
    /// Normally this should be omitted so the builder can derive it from the
    /// measured packet length. If set, it must exactly match the generated
    /// header plus child length; use a `raw!(...)` child to add payload bytes.
    pub fn total_length(mut self, total_length: u16) -> Self {
        self.total_length = Some(total_length);
        self
    }

    /// Set the identification field.
    pub fn identification(mut self, identification: u16) -> Self {
        self.identification = Some(identification);
        self
    }

    /// Set the identification field.
    ///
    /// This is a short alias for [`identification`](Ipv4Builder::identification).
    pub fn id(self, identification: u16) -> Self {
        self.identification(identification)
    }

    /// Set the flags field.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Set the fragment offset field.
    pub fn fragment_offset(mut self, fragment_offset: u16) -> Self {
        self.fragment_offset = Some(fragment_offset);
        self
    }

    /// Set the TTL field.
    ///
    /// If unset, the builder writes `64`.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the protocol field.
    ///
    /// Use this for custom child protocols. If unset, TCP and UDP children
    /// infer `IpProtocol::Tcp` or `IpProtocol::Udp`.
    pub fn protocol(mut self, protocol: impl Into<IpProtocol>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Set the header checksum field.
    ///
    /// If unset, the checksum is calculated from the final header bytes.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    /// Set the source IPv4 address.
    pub fn src(mut self, src: impl Into<Ipv4Addr>) -> Self {
        self.src = Some(src.into());
        self
    }

    /// Set the destination IPv4 address.
    pub fn dst(mut self, dst: impl Into<Ipv4Addr>) -> Self {
        self.dst = Some(dst.into());
        self
    }

    /// Append raw IPv4 option bytes.
    ///
    /// The builder pads the option area to a 32-bit boundary when calculating
    /// and writing IHL.
    pub fn options(mut self, options: impl AsRef<[u8]>) -> Self {
        self.options.extend_from_slice(options.as_ref());
        self
    }

    /// Return the source address that will be written to the packet.
    ///
    /// This is used while building child checksum context before the packet
    /// buffer exists.
    pub(crate) fn effective_src(&self) -> Ipv4Addr {
        self.src.unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Return the destination address that will be written to the packet.
    ///
    /// This is used while building child checksum context before the packet
    /// buffer exists.
    pub(crate) fn effective_dst(&self) -> Ipv4Addr {
        self.dst.unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Calculate the final IPv4 header length and validate explicit IHL.
    ///
    /// Options are padded to a 32-bit boundary for IHL calculation. If the user
    /// supplied IHL, it must be at least the padded header size and at most 15
    /// words.
    fn measure_header_len(&self) -> Result<usize, CraftError> {
        let options_len = self.options.len().next_multiple_of(4);
        let min_header_len = checked_add_len("ipv4", "ihl", Ipv4::MIN_LEN, options_len)?;
        let min_ihl = min_header_len / 4;
        let ihl = self.ihl.unwrap_or(min_ihl as u8);

        if ihl < 5 {
            return Err(CraftError::InvalidField {
                protocol: "ipv4",
                field: "ihl",
                value: ihl as usize,
                reason: "IHL must be at least 5",
            });
        }
        if ihl > 15 {
            return Err(CraftError::LengthOverflow {
                protocol: "ipv4",
                field: "ihl",
                len: ihl as usize,
                max: 15,
            });
        }

        let header_len = ihl as usize * 4;
        if header_len < min_header_len {
            return Err(CraftError::InvalidLength {
                protocol: "ipv4",
                field: "ihl",
                len: header_len,
                min: min_header_len,
            });
        }

        Ok(header_len)
    }
}

impl CraftLayer for Ipv4Builder {
    /// Return the IPv4 protocol marker used in crafted layer metadata.
    fn protocol(&self) -> &'static dyn crate::packet::layer::Protocol {
        &Ipv4
    }

    /// Pass source/destination addresses to child TCP/UDP checksum builders.
    fn child_context(&self, context: CraftContext) -> CraftContext {
        context.with_ipv4(self.effective_src(), self.effective_dst())
    }

    /// Measure the IPv4 header, total length, and child offset.
    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        let header_len = self.measure_header_len()?;
        let child_len = child.map_or(0, |child| child.len());

        let generated_total_len = checked_add_len("ipv4", "total_length", header_len, child_len)?;
        let total_length = match self.total_length {
            Some(total_length) if total_length as usize == generated_total_len => total_length,
            Some(total_length) => {
                return Err(CraftError::InvalidField {
                    protocol: "ipv4",
                    field: "total_length",
                    value: total_length as usize,
                    reason: "must match generated header plus child length; use raw!(...) to add payload bytes",
                });
            }
            None => checked_u16_len("ipv4", "total_length", generated_total_len)?,
        };

        Ok(CraftPlan::new(header_len, total_length as usize))
    }

    /// Write the IPv4 header and header checksum.
    ///
    /// Child bytes have already been written at the measured child offset.
    fn write(
        &self,
        _context: CraftContext,
        plan: CraftPlan,
        child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        let header_len = plan.layer_len();
        let total_length = checked_u16_len("ipv4", "total_length", plan.total_len())?;
        let protocol = self.protocol.unwrap_or(match child {
            Some(child) if child.is(Icmp) => IpProtocol::Icmp,
            Some(child) if child.is(Tcp) => IpProtocol::Tcp,
            Some(child) if child.is(Udp) => IpProtocol::Udp,
            _ => IpProtocol::Reserved(255),
        });

        bytes[Ipv4::MIN_LEN..Ipv4::MIN_LEN + self.options.len()].copy_from_slice(&self.options);

        {
            let mut ipv4 = Ipv4Viewer::new(&mut bytes[..header_len]);
            ipv4.version_mut().set(4);
            ipv4.ihl_mut().set((header_len / 4) as u8);
            ipv4.dscp_mut().set(self.dscp.unwrap_or_default());
            ipv4.ecn_mut().set(self.ecn.unwrap_or_default());
            ipv4.total_length_mut().set(total_length);
            ipv4.identification_mut()
                .set(self.identification.unwrap_or_default());
            ipv4.flags_mut().set(self.flags.unwrap_or_default());
            ipv4.fragment_offset_mut()
                .set(self.fragment_offset.unwrap_or_default());
            ipv4.ttl_mut().set(self.ttl.unwrap_or(64));
            ipv4.protocol_mut().set(protocol);
            ipv4.checksum_mut().set(0);
            ipv4.src_mut().set(self.effective_src());
            ipv4.dst_mut().set(self.effective_dst());
        }

        let checksum = self
            .checksum
            .unwrap_or_else(|| Ipv4Viewer::new(&bytes[..header_len]).calculate_checksum());
        Ipv4Viewer::new(&mut bytes[..header_len])
            .checksum_mut()
            .set(checksum);

        Ok(())
    }
}

crate::impl_craft_layer_div!(Ipv4Builder);

/// Create an IPv4 builder.
///
/// Fields map to [`Ipv4Builder`] methods. A field without a value calls a
/// zero-argument method; a field with `: value` passes that value to the
/// method.
#[macro_export]
macro_rules! ipv4 {
    () => {
        $crate::packet::layer::ip::v4::Ipv4Builder::new()
    };

    ($($field:ident $( : $value:expr )?),+ $(,)?) => {
        $crate::packet::layer::ip::v4::Ipv4Builder::new()
            $(.$field($($value)?))+
    };
}
