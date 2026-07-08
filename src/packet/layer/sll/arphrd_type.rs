//! ARPHRD (Address Resolution Protocol Hardware) types

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// ARPHRD (Address Resolution Protocol Hardware) types
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum
    FromPrimitive,
    IntoPrimitive,
    // strum
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
pub enum ArphrdType {
    /* ARP protocol HARDWARE identifiers */
    /// From KA9Q: NET/ROM pseudo.
    NETROM = 0,
    /// Ethernet 10/100Mbps.  
    ETHER = 1,
    /// Experimental Ethernet.  
    EETHER = 2,
    /// AX.25 Level 2.  
    AX25 = 3,
    /// PROnet token ring.  
    PRONET = 4,
    /// Chaosnet.  
    CHAOS = 5,
    /// IEEE 802.2 Ethernet/TR/TB.  
    IEEE802 = 6,
    /// ARCnet.  
    ARCNET = 7,
    /// APPLEtalk.  
    APPLETLK = 8,
    /// Frame Relay DLCI.  
    DLCI = 15,
    /// ATM.  
    ATM = 19,
    /// Metricom STRIP (new IANA id).  
    METRICOM = 23,
    /// IEEE 1394 IPv4 - RFC 2734.  
    IEEE1394 = 24,
    /// EUI-64.  
    EUI64 = 27,
    /// InfiniBand.  
    INFINIBAND = 32,

    /* Dummy types for non ARP hardware */
    /// Serial Line IP.
    SLIP = 256,
    /// Compressed Serial Line IP.
    CSLIP = 257,
    /// Serial Line IPv6.
    SLIP6 = 258,
    /// Compressed Serial Line IPv6.
    CSLIP6 = 259,
    /// Notional KISS type.  
    RSRVD = 260,
    /// Adaptive interface.
    ADAPT = 264,
    /// ROSE packet radio interface.
    ROSE = 270,
    /// CCITT X.25.  
    X25 = 271,
    /// Boards with X.25 in firmware.  
    HWX25 = 272,
    /// Controller Area Network.  
    CAN = 280,
    /// Management Component Transport Protocol.
    MCTP = 290,
    /// Point-to-Point Protocol.
    PPP = 512,
    /// Cisco HDLC.  
    CISCOHDLC = 513,

    /// LAPB.  
    LAPB = 516,
    /// Digital's DDCMP.  
    DDCMP = 517,
    /// Raw HDLC.  
    RAWHDLC = 518,
    /// Raw IP.  
    RAWIP = 519,

    /// IPIP tunnel.  
    TUNNEL = 768,
    /// IPIP6 tunnel.  
    TUNNEL6 = 769,
    /// Frame Relay Access Device.  
    FRAD = 770,
    /// SKIP vif.  
    SKIP = 771,
    /// Loopback device.  
    LOOPBACK = 772,
    /// Localtalk device.  
    LOCALTLK = 773,
    /// Fiber Distributed Data Interface.
    FDDI = 774,
    /// AP1000 BIF.  
    BIF = 775,
    /// sit0 device - IPv6-in-IPv4.  
    SIT = 776,
    /// IP-in-DDP tunnel.  
    IPDDP = 777,
    /// GRE over IP.  
    IPGRE = 778,
    /// PIMSM register interface.  
    PIMREG = 779,
    /// High Performance Parallel I'face.
    HIPPI = 780,
    /// (Nexus Electronics) Ash.  
    ASH = 781,
    /// Acorn Econet.  
    ECONET = 782,
    /// Linux-IrDA.  
    IRDA = 783,
    /// Point to point fibrechanel.  
    FCPP = 784,
    /// Fibrechanel arbitrated loop.  
    FCAL = 785,
    /// Fibrechanel public loop.  
    FCPL = 786,
    /// Fibrechanel fabric.  
    FCFABRIC = 787,
    /// Magic type ident for TR.  
    IEEE802TR = 800,
    /// IEEE 802.11.  
    IEEE80211 = 801,
    /// IEEE 802.11 + Prism2 header.  
    IEEE80211PRISM = 802,
    /// IEEE 802.11 + radiotap header.  
    IEEE80211RADIOTAP = 803,
    /// IEEE 802.15.4 header.  
    IEEE802154 = 804,
    /// IEEE 802.15.4 PHY header.  
    IEEE802154PHY = 805,

    /// Zero header length.
    NONE = 0xFFFE,

    /// Void type, nothing is known.
    #[num_enum(default)]
    VOID = 0xFFFF,
}

impl_target!(frominto, ArphrdType, u16);
