//! ICMPv4 echo packet crafting.
//!
//! This builder writes the ICMP common header plus the echo identifier and
//! sequence fields. Echo payload bytes should be represented as a child layer,
//! usually `raw!(...)`, so the checksum can cover those bytes without each
//! protocol builder owning an extra payload buffer.

use crate::packet::{
    craft::{
        CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan,
        checked_add_len,
    },
    layer::icmp::{Icmp, IcmpType, IcmpViewer},
};

/// Builder for ICMPv4 echo request and echo reply messages.
///
/// The builder defaults to an echo request with code `0`, identifier `0`, and
/// sequence `0`. If a child layer is present, it starts after the eight-byte
/// echo header and is included in checksum calculation.
#[derive(Debug, Clone)]
pub struct IcmpEchoBuilder {
    message_type: IcmpType,
    code: Option<u8>,
    checksum: Option<u16>,
    identifier: Option<u16>,
    sequence: Option<u16>,
}

impl Default for IcmpEchoBuilder {
    fn default() -> Self {
        Self {
            message_type: IcmpType::EchoRequest,
            code: None,
            checksum: None,
            identifier: None,
            sequence: None,
        }
    }
}

impl IcmpEchoBuilder {
    /// Create an ICMP echo request builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Craft this message as an echo request.
    pub fn request(mut self) -> Self {
        self.message_type = IcmpType::EchoRequest;
        self
    }

    /// Craft this message as an echo reply.
    pub fn reply(mut self) -> Self {
        self.message_type = IcmpType::EchoReply;
        self
    }

    /// Set the ICMP type field.
    ///
    /// This builder accepts only [`EchoRequest`](IcmpType::EchoRequest) and
    /// [`EchoReply`](IcmpType::EchoReply). Other values are rejected during measurement.
    pub fn message_type(mut self, message_type: impl Into<IcmpType>) -> Self {
        self.message_type = message_type.into();
        self
    }

    /// Set the ICMP code field.
    ///
    /// Echo request and reply normally use code `0`, which is also the default.
    pub fn code(mut self, code: u8) -> Self {
        self.code = Some(code);
        self
    }

    /// Set the ICMP checksum field.
    ///
    /// If unset, the checksum is calculated from the final ICMP bytes,
    /// including any child payload bytes.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    /// Set the echo identifier field.
    pub fn identifier(mut self, identifier: u16) -> Self {
        self.identifier = Some(identifier);
        self
    }

    /// Set the echo identifier field.
    ///
    /// This is a short alias for [`identifier`](IcmpEchoBuilder::identifier).
    pub fn id(self, identifier: u16) -> Self {
        self.identifier(identifier)
    }

    /// Set the echo sequence number field.
    pub fn sequence(mut self, sequence: u16) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Set the echo sequence number field.
    ///
    /// This is a short alias for [`sequence`](IcmpEchoBuilder::sequence).
    pub fn seq(self, sequence: u16) -> Self {
        self.sequence(sequence)
    }

    /// Validate that the configured ICMP type is an echo message.
    fn validate_message_type(&self) -> Result<(), CraftError> {
        if matches!(
            self.message_type,
            IcmpType::EchoRequest | IcmpType::EchoReply
        ) {
            Ok(())
        } else {
            Err(CraftError::InvalidField {
                protocol: "icmp",
                field: "type",
                value: u8::from(self.message_type) as usize,
                reason: "IcmpEchoBuilder only supports echo request and echo reply messages",
            })
        }
    }
}

impl CraftLayer for IcmpEchoBuilder {
    /// Return the ICMP protocol marker used in crafted layer metadata.
    fn protocol(&self) -> &'static dyn crate::packet::layer::Protocol {
        &Icmp
    }

    /// Measure the eight-byte ICMP echo header plus child payload bytes.
    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        self.validate_message_type()?;

        let child_len = child.map_or(0, |child| child.len());
        Ok(CraftPlan::new(
            8,
            checked_add_len("icmp", "total_len", 8, child_len)?,
        ))
    }

    /// Write the ICMP echo header and checksum.
    ///
    /// Child bytes have already been written after the echo header, so the
    /// checksum can be calculated over the full ICMP message slice.
    fn write(
        &self,
        _context: CraftContext,
        _plan: CraftPlan,
        _child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        {
            let mut icmp = IcmpViewer::new(&mut bytes[..8]);
            icmp.message_type_mut().set(self.message_type);
            icmp.code_mut().set(self.code.unwrap_or_default());
            icmp.checksum_mut().set(0);
            icmp.identifier_mut()
                .set(self.identifier.unwrap_or_default());
            icmp.sequence_mut().set(self.sequence.unwrap_or_default());
        }

        let checksum = self
            .checksum
            .unwrap_or_else(|| IcmpViewer::new(&bytes[..]).calculate_checksum());
        IcmpViewer::new(&mut bytes[..8])
            .checksum_mut()
            .set(checksum);

        Ok(())
    }
}

crate::impl_craft_layer_div!(IcmpEchoBuilder);

/// Create an ICMPv4 echo builder.
///
/// Fields map to [`IcmpEchoBuilder`] methods. A field without a value calls a
/// zero-argument method, so `request` expands to `request()`; a field with
/// `: value` passes that value to the method.
///
/// ```
/// # use maja::prelude::*;
/// let _ = icmp_echo!(request, id: 0x1234, seq: 1);
/// ```
#[macro_export]
macro_rules! icmp_echo {
    () => {
        $crate::packet::layer::icmp::IcmpEchoBuilder::new()
    };

    ($($field:ident $( : $value:expr )?),+ $(,)?) => {
        $crate::packet::layer::icmp::IcmpEchoBuilder::new()
            $(.$field($($value)?))+
    };
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        ipv4,
        packet::layer::{
            icmp::{Icmp, IcmpType, IcmpViewer},
            ip::{protocol::IpProtocol, v4::Ipv4},
            raw::Raw,
        },
        raw,
    };

    #[test]
    fn crafts_ipv4_icmp_echo_raw_stack() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 2);
        let packet =
            (ipv4!(src: src, dst: dst) / icmp_echo!(request, id: 0x1234, seq: 7) / raw!(b"hello"))
                .build()
                .expect("craft icmp echo packet");

        assert_eq!(packet.len(), 20 + 8 + 5);
        assert_eq!(packet.layers().len(), 3);

        let ipv4 = packet.layer_viewer(Ipv4).expect("ipv4 layer");
        assert_eq!(ipv4.protocol(), IpProtocol::Icmp);
        assert!(ipv4.validate_checksum());

        let icmp = packet.layer_viewer(Icmp).expect("icmp layer");
        assert_eq!(icmp.message_type(), IcmpType::EchoRequest);
        assert_eq!(icmp.identifier(), 0x1234);
        assert_eq!(icmp.sequence(), 7);

        let icmp_message = IcmpViewer::new(&packet.as_bytes()[20..]);
        assert!(icmp_message.validate_checksum());
        assert_eq!(icmp_message.echo().expect("echo view").payload(), b"hello");

        let raw = packet.layer_viewer(Raw).expect("raw payload");
        assert_eq!(raw.bytes(), b"hello");
    }

    #[test]
    fn crafts_ipv4_icmp_echo_reply_stack() {
        let src = Ipv4Addr::new(192, 0, 2, 2);
        let dst = Ipv4Addr::new(192, 0, 2, 1);
        let packet = (ipv4!(src: src, dst: dst) / icmp_echo!(reply, id: 0x1234, seq: 7))
            .build()
            .expect("craft icmp echo packet");

        assert_eq!(packet.len(), 20 + 8);
        assert_eq!(packet.layers().len(), 2);

        let ipv4 = packet.layer_viewer(Ipv4).expect("ipv4 layer");
        assert_eq!(ipv4.protocol(), IpProtocol::Icmp);
        assert!(ipv4.validate_checksum());

        let icmp = packet.layer_viewer(Icmp).expect("icmp layer");
        assert_eq!(icmp.message_type(), IcmpType::EchoReply);
        assert_eq!(icmp.identifier(), 0x1234);
        assert_eq!(icmp.sequence(), 7);

        let icmp_message = IcmpViewer::new(&packet.as_bytes()[20..]);
        assert!(icmp_message.validate_checksum());
        assert_eq!(icmp_message.echo().expect("echo view").payload(), &[]);
    }
}
