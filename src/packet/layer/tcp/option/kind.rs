//! TCP option kind registry values.
//!
//! TCP options are encoded after the TCP fixed header when the data offset is
//! larger than five 32-bit words. The kind byte identifies either a one-byte
//! control option (`0` End-of-Options, `1` No-Operation) or an option that is
//! followed by a length byte and payload.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// TCP option kind values.
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
#[repr(u8)]
#[non_exhaustive]
pub enum TcpOptionKind {
    /// End of options list.
    EndOfOptions = 0,
    /// No operation.
    NoOperation = 1,
    /// Maximum segment size.
    MaximumSegmentSize = 2,
    /// Window scale.
    WindowScale = 3,
    /// SACK permitted.
    SackPermitted = 4,
    /// SACK blocks.
    Sack = 5,
    /// Echo.
    Echo = 6,
    /// Echo reply.
    EchoReply = 7,
    /// Timestamps.
    Timestamp = 8,
    /// Partial order connection permitted.
    PartialOrderConnectionPermitted = 9,
    /// Partial order service profile.
    PartialOrderServiceProfile = 10,
    /// CC.
    Cc = 11,
    /// CC.NEW.
    CcNew = 12,
    /// CC.ECHO.
    CcEcho = 13,
    /// Alternate checksum request.
    AlternateChecksumRequest = 14,
    /// Alternate checksum data.
    AlternateChecksumData = 15,
    /// Skeeter.
    Skeeter = 16,
    /// Bubba.
    Bubba = 17,
    /// Trailer checksum.
    TrailerChecksum = 18,
    /// MD5 signature.
    Md5Signature = 19,
    /// SCPS capabilities.
    ScpsCapabilities = 20,
    /// Selective negative acknowledgements.
    SelectiveNegativeAcknowledgements = 21,
    /// Record boundaries.
    RecordBoundaries = 22,
    /// Corruption experienced.
    CorruptionExperienced = 23,
    /// SNAP.
    Snap = 24,
    /// Unassigned/released.
    Unassigned25 = 25,
    /// TCP compression filter.
    TcpCompressionFilter = 26,
    /// Quick-start response.
    QuickStartResponse = 27,
    /// User timeout.
    UserTimeout = 28,
    /// TCP authentication option.
    Authentication = 29,
    /// Multipath TCP.
    MultipathTcp = 30,
    /// TCP fast open cookie.
    FastOpenCookie = 34,
    /// Unknown option kind.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, TcpOptionKind, u8);
