//! Capture file format implementations.
//!
//! The format modules convert on-disk capture records into the common
//! [`PacketRecord`](crate::capture::packet::PacketRecord) representation used by packet
//! parsing code.

/// Classic PCAP capture files.
pub mod pcap;
/// PCAP Now Generic capture files.
pub mod pcapng;
