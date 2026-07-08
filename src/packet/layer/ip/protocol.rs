//! IP Protocol

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// IP Protocol
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
#[repr(u8)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum IpProtocol {
    Hopopt = 0,

    /// Internet Control Message Protocol
    Icmp = 1,

    Igmp = 2,

    Ggp = 3,

    /// Internet Protocol version 4
    Ipv4 = 4,

    St = 5,

    /// Transmission Control Protocol
    Tcp = 6,

    Cbt = 7,

    Egp = 8,

    Igp = 9,

    BbnRccMon = 10,

    NvpII = 11,

    Pup = 12,

    Argus = 13,

    Emcon = 14,

    Xnet = 15,

    Chaos = 16,

    /// User Datagram Protocol
    Udp = 17,

    Mux = 18,

    DcnMeas = 19,

    Hmp = 20,

    Prm = 21,

    XnsIdp = 22,

    Trunk1 = 23,

    Trunk2 = 24,

    Leaf1 = 25,

    Leaf2 = 26,

    Rdp = 27,

    Irtp = 28,

    IsoTp4 = 29,

    Netblt = 30,

    MfeNsp = 31,

    MeritInp = 32,

    Dccp = 33,

    ThreePc = 34,

    Idpr = 35,

    Xtp = 36,

    Ddp = 37,

    IdprCmtp = 38,

    TpPlusPlus = 39,

    Il = 40,

    /// Internet Protocol version 6
    Ipv6 = 41,

    Sdrp = 42,

    Ipv6Route = 43,

    Ipv6Frag = 44,

    Idrp = 45,

    Rsvp = 46,

    Gre = 47,

    Dsr = 48,

    Bna = 49,

    Esp = 50,

    Ah = 51,

    INlsp = 52,

    Swipe = 53,

    Narp = 54,

    Mobile = 55,

    Tlsp = 56,

    Skip = 57,

    Ipv6Icmp = 58,

    Ipv6NoNxt = 59,

    Ipv6Opts = 60,

    AnyHostInternalProtocol = 61,

    Cftp = 62,

    AnyLocalNetwork = 63,

    SatExpak = 64,

    Kryptolan = 65,

    Rvd = 66,

    Ippc = 67,

    AnyDistributedFileSystem = 68,

    SatMon = 69,

    Visa = 70,

    Ipcv = 71,

    Cpnx = 72,

    Cphb = 73,

    Wsn = 74,

    Pvp = 75,

    BrSatMon = 76,

    SunNd = 77,

    WbMon = 78,

    WbExpak = 79,

    IsoIp = 80,

    Vmtp = 81,

    SecureVmtp = 82,

    Vines = 83,

    Iptm = 84,

    NsfnetIgp = 85,

    Dgp = 86,

    Tcf = 87,

    Eigrp = 88,

    Ospfigp = 89,

    SpriteRpc = 90,

    Larp = 91,

    Mtp = 92,

    Ax25 = 93,

    IpIp = 94,

    Micp = 95,

    SccSp = 96,

    Etherip = 97,

    Encap = 98,

    AnyPrivateEncryptionScheme = 99,

    Gmtp = 100,

    Ifmp = 101,

    Pnni = 102,

    Pim = 103,

    Aris = 104,

    Scps = 105,

    Qnx = 106,

    AN = 107,

    IpComp = 108,

    Snp = 109,

    CompaqPeer = 110,

    IpxInIp = 111,

    Vrrp = 112,

    Pgm = 113,

    Any0HopProtocol = 114,

    L2tp = 115,

    Ddx = 116,

    Iatp = 117,

    Stp = 118,

    Srp = 119,

    Uti = 120,

    Smp = 121,

    Sm = 122,

    Ptp = 123,

    IsisOverIpv4 = 124,

    Fire = 125,

    Crtp = 126,

    Crudp = 127,

    Sscopmce = 128,

    Iplt = 129,

    Sps = 130,

    Pipe = 131,

    Sctp = 132,

    Fc = 133,

    RsvpE2eIgnore = 134,

    MobilityHeader = 135,

    UdpLite = 136,

    MplsInIp = 137,

    Manet = 138,

    Hip = 139,

    Shim6 = 140,

    Wesp = 141,

    Rohc = 142,

    Ethernet = 143,

    Aggfrag = 144,

    Nsh = 145,

    #[num_enum(catch_all)]
    Reserved(u8),
}

impl_target!(frominto, IpProtocol, u8);

impl From<IpProtocol> for u64 {
    fn from(value: IpProtocol) -> Self {
        u8::from(value).into()
    }
}
