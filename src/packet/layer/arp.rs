//! Address Resolution Protocol (ARP)
//!
//! ARP starts with fixed metadata describing the hardware and protocol address
//! families, followed by variable-length sender and target addresses. For the
//! common Ethernet/IPv4 layout this is a 28-byte message with 6-byte hardware
//! addresses and 4-byte protocol addresses.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Hardware Type           |       Protocol Type           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Hardware Len | Protocol Len  |          Operation            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sender Hardware Address                    |
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sender Protocol Address                    |
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Target Hardware Address                    |
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Target Protocol Address                    |
//! ~                              ...                              ~
//! ```
//!
//! A typical ARP with Ethernet + Ipv4 addresses looks like this:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Hardware Type           |       Protocol Type           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Hardware Len | Protocol Len  |          Operation            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sender Hardware Address                    |
//! |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |  Sender Protocol Address      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Sender Protocol Address cont. |  Target Hardware Address      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Target Hardware Address cont.              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Target Protocol Address                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use std::fmt::Debug;

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{
            Protocol, ProtocolExt,
            eth::{EthAddr, EthType},
        },
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod hardware_type;
pub mod operation;

pub use hardware_type::ArpHardwareType;
pub use operation::ArpOperation;

/// Address Resolution Protocol (ARP) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Arp;

impl Arp {
    /// Minimum ARP header length before variable-size addresses.
    const MIN_LEN: usize = 8;
    /// ARP length for Ethernet hardware addresses and IPv4 protocol addresses.
    const ETHERNET_IPV4_LEN: usize = 28;
}

impl Protocol for Arp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let arp = ArpViewer::new(bytes);

        if arp.is_ethernet_ipv4() {
            write!(
                fmt,
                "[Arp] {} {} -> {}",
                arp.operation().get(),
                arp.sender_protocol_addr().get(),
                arp.target_protocol_addr().get()
            )
        } else {
            write!(
                fmt,
                "[Arp] {} {:?} {:?}",
                arp.operation().get(),
                arp.hardware_type().get(),
                arp.protocol_type().get()
            )
        }
    }
}

impl ProtocolExt for Arp {
    type Viewer<'a> = ArpViewer<&'a [u8]>;
    type ViewerMut<'a> = ArpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Arp, offset, Arp::MIN_LEN)?;

        let arp = ArpViewer::new(header);
        let len = arp.header_len();

        ctx.require(&Arp, offset, len)?;

        ctx.push_layer(&Arp, offset, len);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        ArpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        ArpViewer::new(bytes)
    }
}

field_spec!(HardwareTypeSpec, ArpHardwareType, u16);
field_spec!(ProtocolTypeSpec, EthType, u16);
field_spec!(HardwareLenSpec, u8, u8);
field_spec!(ProtocolLenSpec, u8, u8);
field_spec!(OperationSpec, ArpOperation, u16);
field_spec!(HardwareAddrSpec, EthAddr, [u8; 6]);
field_spec!(ProtocolAddrSpec, core::net::Ipv4Addr, u32);

/// Address Resolution Protocol (ARP)
pub struct ArpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> ArpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the hardware type: 0..2
    const FIELD_HARDWARE_TYPE: core::ops::Range<usize> = 0..2;
    /// Field range of the protocol type: 2..4
    const FIELD_PROTOCOL_TYPE: core::ops::Range<usize> = 2..4;
    /// Field range of the hardware address length: 4..5
    const FIELD_HARDWARE_LEN: core::ops::Range<usize> = 4..5;
    /// Field range of the protocol address length: 5..6
    const FIELD_PROTOCOL_LEN: core::ops::Range<usize> = 5..6;
    /// Field range of the operation code: 6..8
    const FIELD_OPERATION: core::ops::Range<usize> = 6..8;
    /// Field range of the sender hardware address for Ethernet/IPv4 ARP: 8..14
    const FIELD_SENDER_HARDWARE_ADDR: core::ops::Range<usize> = 8..14;
    /// Field range of the sender protocol address for Ethernet/IPv4 ARP: 14..18
    const FIELD_SENDER_PROTOCOL_ADDR: core::ops::Range<usize> = 14..18;
    /// Field range of the target hardware address for Ethernet/IPv4 ARP: 18..24
    const FIELD_TARGET_HARDWARE_ADDR: core::ops::Range<usize> = 18..24;
    /// Field range of the target protocol address for Ethernet/IPv4 ARP: 24..28
    const FIELD_TARGET_PROTOCOL_ADDR: core::ops::Range<usize> = 24..28;

    /// Create a new ARP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Return the total ARP header length from the HLEN and PLEN fields.
    #[inline]
    pub fn header_len(&self) -> usize {
        Arp::MIN_LEN + 2 * (self.hardware_len().get() as usize + self.protocol_len().get() as usize)
    }

    /// Return whether this ARP payload uses the common Ethernet/IPv4 layout.
    #[inline]
    pub fn is_ethernet_ipv4(&self) -> bool {
        self.data.as_ref().len() >= Arp::ETHERNET_IPV4_LEN
            && self.hardware_type() == ArpHardwareType::Ethernet
            && self.protocol_type() == EthType::Ipv4
            && self.hardware_len() == 6
            && self.protocol_len() == 4
    }

    /// Get the accessor of the hardware type.
    #[inline]
    pub fn hardware_type(&self) -> FieldRef<'_, HardwareTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HARDWARE_TYPE])
    }

    /// Get the accessor of the protocol type.
    #[inline]
    pub fn protocol_type(&self) -> FieldRef<'_, ProtocolTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL_TYPE])
    }

    /// Get the accessor of the hardware address length.
    #[inline]
    pub fn hardware_len(&self) -> FieldRef<'_, HardwareLenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HARDWARE_LEN])
    }

    /// Get the accessor of the protocol address length.
    #[inline]
    pub fn protocol_len(&self) -> FieldRef<'_, ProtocolLenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL_LEN])
    }

    /// Get the accessor of the operation code.
    #[inline]
    pub fn operation(&self) -> FieldRef<'_, OperationSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_OPERATION])
    }

    /// Get the sender hardware address bytes using HLEN.
    #[inline]
    pub fn sender_hardware_addr_bytes(&self) -> &[u8] {
        &self.data.as_ref()[self.sender_hardware_addr_range()]
    }

    /// Get the sender protocol address bytes using PLEN.
    #[inline]
    pub fn sender_protocol_addr_bytes(&self) -> &[u8] {
        &self.data.as_ref()[self.sender_protocol_addr_range()]
    }

    /// Get the target hardware address bytes using HLEN.
    #[inline]
    pub fn target_hardware_addr_bytes(&self) -> &[u8] {
        &self.data.as_ref()[self.target_hardware_addr_range()]
    }

    /// Get the target protocol address bytes using PLEN.
    #[inline]
    pub fn target_protocol_addr_bytes(&self) -> &[u8] {
        &self.data.as_ref()[self.target_protocol_addr_range()]
    }

    /// Get the accessor of the sender hardware address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn sender_hardware_addr(&self) -> FieldRef<'_, HardwareAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SENDER_HARDWARE_ADDR])
    }

    /// Get the accessor of the sender protocol address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn sender_protocol_addr(&self) -> FieldRef<'_, ProtocolAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SENDER_PROTOCOL_ADDR])
    }

    /// Get the accessor of the target hardware address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn target_hardware_addr(&self) -> FieldRef<'_, HardwareAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TARGET_HARDWARE_ADDR])
    }

    /// Get the accessor of the target protocol address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn target_protocol_addr(&self) -> FieldRef<'_, ProtocolAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TARGET_PROTOCOL_ADDR])
    }

    fn sender_hardware_addr_range(&self) -> core::ops::Range<usize> {
        let start = Arp::MIN_LEN;
        start..start + self.hardware_len().get() as usize
    }

    fn sender_protocol_addr_range(&self) -> core::ops::Range<usize> {
        let start = self.sender_hardware_addr_range().end;
        start..start + self.protocol_len().get() as usize
    }

    fn target_hardware_addr_range(&self) -> core::ops::Range<usize> {
        let start = self.sender_protocol_addr_range().end;
        start..start + self.hardware_len().get() as usize
    }

    fn target_protocol_addr_range(&self) -> core::ops::Range<usize> {
        let start = self.target_hardware_addr_range().end;
        start..start + self.protocol_len().get() as usize
    }
}

impl<T> ArpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the hardware type.
    #[inline]
    pub fn hardware_type_mut(&mut self) -> FieldMut<'_, HardwareTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HARDWARE_TYPE])
    }

    /// Get the mutable accessor of the protocol type.
    #[inline]
    pub fn protocol_type_mut(&mut self) -> FieldMut<'_, ProtocolTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL_TYPE])
    }

    /// Get the mutable accessor of the hardware address length.
    #[inline]
    pub fn hardware_len_mut(&mut self) -> FieldMut<'_, HardwareLenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HARDWARE_LEN])
    }

    /// Get the mutable accessor of the protocol address length.
    #[inline]
    pub fn protocol_len_mut(&mut self) -> FieldMut<'_, ProtocolLenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL_LEN])
    }

    /// Get the mutable accessor of the operation code.
    #[inline]
    pub fn operation_mut(&mut self) -> FieldMut<'_, OperationSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_OPERATION])
    }

    /// Get the mutable sender hardware address bytes using HLEN.
    #[inline]
    pub fn sender_hardware_addr_bytes_mut(&mut self) -> &mut [u8] {
        let range = self.sender_hardware_addr_range();
        &mut self.data.as_mut()[range]
    }

    /// Get the mutable sender protocol address bytes using PLEN.
    #[inline]
    pub fn sender_protocol_addr_bytes_mut(&mut self) -> &mut [u8] {
        let range = self.sender_protocol_addr_range();
        &mut self.data.as_mut()[range]
    }

    /// Get the mutable target hardware address bytes using HLEN.
    #[inline]
    pub fn target_hardware_addr_bytes_mut(&mut self) -> &mut [u8] {
        let range = self.target_hardware_addr_range();
        &mut self.data.as_mut()[range]
    }

    /// Get the mutable target protocol address bytes using PLEN.
    #[inline]
    pub fn target_protocol_addr_bytes_mut(&mut self) -> &mut [u8] {
        let range = self.target_protocol_addr_range();
        &mut self.data.as_mut()[range]
    }

    /// Get the mutable accessor of the sender hardware address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn sender_hardware_addr_mut(&mut self) -> FieldMut<'_, HardwareAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SENDER_HARDWARE_ADDR])
    }

    /// Get the mutable accessor of the sender protocol address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn sender_protocol_addr_mut(&mut self) -> FieldMut<'_, ProtocolAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SENDER_PROTOCOL_ADDR])
    }

    /// Get the mutable accessor of the target hardware address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn target_hardware_addr_mut(&mut self) -> FieldMut<'_, HardwareAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TARGET_HARDWARE_ADDR])
    }

    /// Get the mutable accessor of the target protocol address for Ethernet/IPv4 ARP.
    #[inline]
    pub fn target_protocol_addr_mut(&mut self) -> FieldMut<'_, ProtocolAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TARGET_PROTOCOL_ADDR])
    }
}

impl<T> Debug for ArpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Arp");
        debug
            .field("hardware_type", &self.hardware_type().get())
            .field("protocol_type", &self.protocol_type().get())
            .field("hardware_len", &self.hardware_len().get())
            .field("protocol_len", &self.protocol_len().get())
            .field("operation", &self.operation().get());

        if self.is_ethernet_ipv4() {
            debug
                .field("sender_hardware_addr", &self.sender_hardware_addr().get())
                .field("sender_protocol_addr", &self.sender_protocol_addr().get())
                .field("target_hardware_addr", &self.target_hardware_addr().get())
                .field("target_protocol_addr", &self.target_protocol_addr().get());
        } else {
            debug
                .field("sender_hardware_addr", &self.sender_hardware_addr_bytes())
                .field("sender_protocol_addr", &self.sender_protocol_addr_bytes())
                .field("target_hardware_addr", &self.target_hardware_addr_bytes())
                .field("target_protocol_addr", &self.target_protocol_addr_bytes());
        }

        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use crate::{
        eth_addr,
        packet::{Packet, layer::eth::Eth},
    };

    use super::*;

    #[test]
    fn arp_viewer() {
        let data: [u8; 28] = [
            0x00, 0x01, // hardware type: Ethernet
            0x08, 0x00, // protocol type: IPv4
            0x06, // hardware len
            0x04, // protocol len
            0x00, 0x01, // operation: request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender hardware address
            192, 168, 1, 10, // sender protocol address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target hardware address
            192, 168, 1, 1, // target protocol address
        ];

        let arp = ArpViewer::new(&data);

        assert_eq!(arp.hardware_type(), ArpHardwareType::Ethernet);
        assert_eq!(arp.protocol_type(), EthType::Ipv4);
        assert_eq!(arp.hardware_len(), 6);
        assert_eq!(arp.protocol_len(), 4);
        assert_eq!(arp.operation(), ArpOperation::Request);
        assert_eq!(arp.header_len(), 28);
        assert!(arp.is_ethernet_ipv4());
        assert_eq!(
            arp.sender_hardware_addr(),
            eth_addr!(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        );
        assert_eq!(arp.sender_protocol_addr(), Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(
            arp.target_hardware_addr(),
            eth_addr!(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        );
        assert_eq!(arp.target_protocol_addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            arp.sender_hardware_addr_bytes(),
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(arp.sender_protocol_addr_bytes(), &[192, 168, 1, 10]);
        assert_eq!(
            arp.target_hardware_addr_bytes(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(arp.target_protocol_addr_bytes(), &[192, 168, 1, 1]);
    }

    #[test]
    fn arp_viewer_mut() {
        let mut data: [u8; 28] = [0; 28];

        let mut arp = ArpViewer::new(&mut data);

        arp.hardware_type_mut().set(ArpHardwareType::Ethernet);
        arp.protocol_type_mut().set(EthType::Ipv4);
        arp.hardware_len_mut().set(6);
        arp.protocol_len_mut().set(4);
        arp.operation_mut().set(ArpOperation::Reply);
        arp.sender_hardware_addr_mut()
            .set(eth_addr!(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
        arp.sender_protocol_addr_mut()
            .set(Ipv4Addr::new(192, 168, 1, 10));
        arp.target_hardware_addr_mut()
            .set(eth_addr!(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB));
        arp.target_protocol_addr_mut()
            .set(Ipv4Addr::new(192, 168, 1, 1));

        assert_eq!(
            data,
            [
                0x00, 0x01, // hardware type: Ethernet
                0x08, 0x00, // protocol type: IPv4
                0x06, // hardware len
                0x04, // protocol len
                0x00, 0x02, // operation: reply
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender hardware address
                192, 168, 1, 10, // sender protocol address
                0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // target hardware address
                192, 168, 1, 1, // target protocol address
            ]
        );
    }

    #[test]
    fn parse_ethernet_arp_packet() {
        let data: [u8; 42] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source MAC
            0x08, 0x06, // EtherType: ARP
            0x00, 0x01, // hardware type: Ethernet
            0x08, 0x00, // protocol type: IPv4
            0x06, // hardware len
            0x04, // protocol len
            0x00, 0x01, // operation: request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender hardware address
            192, 168, 1, 10, // sender protocol address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target hardware address
            192, 168, 1, 1, // target protocol address
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let arp = packet.layer_viewer(Arp).expect("ARP layer not found");
        assert_eq!(arp.operation(), ArpOperation::Request);
        assert_eq!(arp.sender_protocol_addr(), Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(arp.target_protocol_addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            format!("{}", packet),
            "[Eth] FF:FF:FF:FF:FF:FF -> 00:11:22:33:44:55 | [Arp] Request 192.168.1.10 -> 192.168.1.1"
        );
    }
}
