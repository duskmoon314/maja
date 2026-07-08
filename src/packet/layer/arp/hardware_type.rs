//! ARP hardware type registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// ARP hardware type values from the IANA ARP Parameters registry.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum traits
    FromPrimitive,
    IntoPrimitive,
    // strum traits
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
pub enum ArpHardwareType {
    /// Reserved.
    Reserved = 0,
    /// Ethernet (10Mb).
    Ethernet = 1,
    /// Experimental Ethernet (3Mb).
    ExperimentalEthernet = 2,
    /// Amateur Radio AX.25.
    AmateurRadioAx25 = 3,
    /// Proteon ProNET Token Ring.
    ProteonPronetTokenRing = 4,
    /// Chaos.
    Chaos = 5,
    /// IEEE 802 Networks.
    Ieee802Networks = 6,
    /// ARCNET.
    Arcnet = 7,
    /// Hyperchannel.
    Hyperchannel = 8,
    /// Lanstar.
    Lanstar = 9,
    /// Autonet Short Address.
    AutonetShortAddress = 10,
    /// LocalTalk.
    Localtalk = 11,
    /// LocalNet (IBM PCNet or SYTEK LocalNET).
    Localnet = 12,
    /// Ultra link.
    Ultralink = 13,
    /// SMDS.
    Smds = 14,
    /// Frame Relay.
    FrameRelay = 15,
    /// Asynchronous Transmission Mode (ATM).
    Atm16 = 16,
    /// HDLC.
    Hdlc = 17,
    /// Fibre Channel.
    FibreChannel = 18,
    /// Asynchronous Transmission Mode (ATM).
    Atm19 = 19,
    /// Serial Line.
    SerialLine = 20,
    /// Asynchronous Transmission Mode (ATM).
    Atm21 = 21,
    /// MIL-STD-188-220.
    MilStd188220 = 22,
    /// Metricom.
    Metricom = 23,
    /// IEEE 1394.1995.
    Ieee1394 = 24,
    /// MAPOS.
    Mapos = 25,
    /// Twinaxial.
    Twinaxial = 26,
    /// EUI-64.
    Eui64 = 27,
    /// HIPARP.
    Hiparp = 28,
    /// IP and ARP over ISO 7816-3.
    Iso7816_3 = 29,
    /// ARPSec.
    ArpSec = 30,
    /// IPsec tunnel.
    IpsecTunnel = 31,
    /// InfiniBand.
    InfiniBand = 32,
    /// TIA-102 Project 25 Common Air Interface.
    Tia102 = 33,
    /// Wiegand Interface.
    WiegandInterface = 34,
    /// Pure IP.
    PureIp = 35,
    /// Experimental hardware type 1.
    HwExp1 = 36,
    /// HFI.
    Hfi = 37,
    /// Unified Bus.
    UnifiedBus = 38,
    /// Experimental hardware type 2.
    HwExp2 = 256,
    /// AEthernet.
    AEthernet = 257,
    /// Unassigned or unknown hardware type.
    #[num_enum(catch_all)]
    Unassigned(u16),
}

impl_target!(frominto, ArpHardwareType, u16);

impl crate::packet::utils::field::Target<u8> for ArpHardwareType {
    fn from_underlay(x: u8) -> Self {
        u16::from(x).into()
    }

    fn into_underlay(self) -> u8 {
        let value: u16 = self.into();
        value
            .try_into()
            .expect("ARP hardware type does not fit in DHCP/BOOTP htype")
    }
}
