//! Packet parsing errors.

use crate::{capture::link_type::LinkType, packet::layer::Protocol};

/// Error returned by protocol parsers for malformed or truncated packet data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Packet data ended before the parser could read the required bytes.
    #[error(
        "{protocol:?}: need {needed} bytes at offset {offset}, only {available} bytes available"
    )]
    Truncated {
        /// Protocol parser that reported the error.
        protocol: &'static dyn Protocol,
        /// Absolute packet offset where the bytes were required.
        offset: usize,
        /// Number of bytes required from `offset`.
        needed: usize,
        /// Number of bytes available from `offset`.
        available: usize,
    },
    /// Packet field was structurally malformed.
    #[error("{protocol:?}: malformed {field}: {reason}")]
    Malformed {
        /// Protocol parser that reported the error.
        protocol: &'static dyn Protocol,
        /// Field or structure that was malformed.
        field: &'static str,
        /// Short reason for the malformed field.
        reason: &'static str,
    },
    /// Packet link type is not supported by the top-level link-type dispatcher.
    #[error("unsupported link type: {link_type}")]
    UnsupportedLinkType {
        /// Link type that could not be dispatched to a root parser.
        link_type: LinkType,
    },
}

impl ParseError {
    /// Construct a truncation error using the full packet length.
    pub(crate) fn truncated(
        protocol: &'static dyn Protocol,
        offset: usize,
        needed: usize,
        bytes_len: usize,
    ) -> Self {
        Self::Truncated {
            protocol,
            offset,
            needed,
            available: bytes_len.saturating_sub(offset),
        }
    }
}
