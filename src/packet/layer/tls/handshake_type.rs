//! TLS handshake type values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// TLS handshake message type values.
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
pub enum TlsHandshakeType {
    /// Hello request.
    HelloRequest = 0,
    /// Client hello.
    ClientHello = 1,
    /// Server hello.
    ServerHello = 2,
    /// New session ticket.
    NewSessionTicket = 4,
    /// End of early data.
    EndOfEarlyData = 5,
    /// Encrypted extensions.
    EncryptedExtensions = 8,
    /// Certificate.
    Certificate = 11,
    /// Server key exchange.
    ServerKeyExchange = 12,
    /// Certificate request.
    CertificateRequest = 13,
    /// Server hello done.
    ServerHelloDone = 14,
    /// Certificate verify.
    CertificateVerify = 15,
    /// Client key exchange.
    ClientKeyExchange = 16,
    /// Finished.
    Finished = 20,
    /// Certificate URL.
    CertificateUrl = 21,
    /// Certificate status.
    CertificateStatus = 22,
    /// Key update.
    KeyUpdate = 24,
    /// Message hash.
    MessageHash = 254,
    /// Unknown handshake type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, TlsHandshakeType, u8);
