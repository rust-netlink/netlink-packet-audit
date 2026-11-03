// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::{DecodeError, Emitable, Parseable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const AUDIT_STATUS_ENABLED: u32 = 1;
const AUDIT_STATUS_FAILURE: u32 = 2;
const AUDIT_STATUS_PID: u32 = 4;
const AUDIT_STATUS_RATE_LIMIT: u32 = 8;
const AUDIT_STATUS_BACKLOG_LIMIT: u32 = 16;
const AUDIT_STATUS_BACKLOG_WAIT_TIME: u32 = 32;
const AUDIT_STATUS_LOST: u32 = 64;
const AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL: u32 = 128;

const AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT: u32 = 0x0000_0001;
const AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME: u32 = 0x0000_0002;
const AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH: u32 = 0x0000_0004;
const AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND: u32 = 0x0000_0008;
const AUDIT_FEATURE_BITMAP_SESSIONID_FILTER: u32 = 0x0000_0010;
const AUDIT_FEATURE_BITMAP_LOST_RESET: u32 = 0x0000_0020;
const AUDIT_FEATURE_BITMAP_FILTER_FS: u32 = 0x0000_0040;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    #[non_exhaustive]
    pub struct AuditStatus: u32 {
        const Enabled = AUDIT_STATUS_ENABLED;
        const Failure = AUDIT_STATUS_FAILURE;
        const Pid = AUDIT_STATUS_PID;
        const RateLimit = AUDIT_STATUS_RATE_LIMIT;
        const BacklogLimit = AUDIT_STATUS_BACKLOG_LIMIT;
        const BacklogWaitTime = AUDIT_STATUS_BACKLOG_WAIT_TIME;
        const Lost = AUDIT_STATUS_LOST;
        const BacklogWaitTimeActual = AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL;
        const _ = !0;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    #[non_exhaustive]
    pub struct AuditFeatureBitmap: u32 {
        const BacklogLimit = AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT;
        const BacklogWaitTime = AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME;
        const ExecutablePath = AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH;
        const ExcludeExtend = AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND;
        const SessionIdFilter = AUDIT_FEATURE_BITMAP_SESSIONID_FILTER;
        const LostReset = AUDIT_FEATURE_BITMAP_LOST_RESET;
        const FilterFs = AUDIT_FEATURE_BITMAP_FILTER_FS;
        const _ = !0;
    }
}

const STATUS_MESSAGE_LEN: usize = 44;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct StatusMessageBuffer {
    mask: u32,
    enabled: u32,
    failure: u32,
    pid: u32,
    rate_limiting: u32,
    backlog_limit: u32,
    lost: u32,
    backlog: u32,
    feature_bitmap: u32,
    backlog_wait_time: u32,
    backlog_wait_time_actual: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct StatusMessage {
    /// Bit mask for valid entries
    pub mask: AuditStatus,
    pub enabled: u32,
    /// Failure-to-log action
    pub failure: u32,
    /// PID of auditd process
    pub pid: u32,
    /// Message rate limit (per second)
    pub rate_limiting: u32,
    /// Waiting messages limit
    pub backlog_limit: u32,
    /// Messages lost
    pub lost: u32,
    /// Messages waiting in queue
    pub backlog: u32,
    /// bitmap of kernel audit features
    pub feature_bitmap: AuditFeatureBitmap,
    /// Message queue wait timeout
    pub backlog_wait_time: u32,
    /// Time spent waiting while the message limit was exceeded
    pub backlog_wait_time_actual: u32,
}

impl StatusMessage {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        <Self as Parseable<[u8]>>::parse(payload)
    }
}

impl From<&StatusMessage> for StatusMessageBuffer {
    fn from(message: &StatusMessage) -> Self {
        Self {
            mask: message.mask.bits(),
            enabled: message.enabled,
            failure: message.failure,
            pid: message.pid,
            rate_limiting: message.rate_limiting,
            backlog_limit: message.backlog_limit,
            lost: message.lost,
            backlog: message.backlog,
            feature_bitmap: message.feature_bitmap.bits(),
            backlog_wait_time: message.backlog_wait_time,
            backlog_wait_time_actual: message.backlog_wait_time_actual,
        }
    }
}

impl Parseable<[u8]> for StatusMessage {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            StatusMessageBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), STATUS_MESSAGE_LEN)
            })?;
        Ok(StatusMessage {
            mask: AuditStatus::from_bits_retain(raw.mask),
            enabled: raw.enabled,
            failure: raw.failure,
            pid: raw.pid,
            rate_limiting: raw.rate_limiting,
            backlog_limit: raw.backlog_limit,
            lost: raw.lost,
            backlog: raw.backlog,
            feature_bitmap: AuditFeatureBitmap::from_bits_retain(
                raw.feature_bitmap,
            ),
            backlog_wait_time: raw.backlog_wait_time,
            backlog_wait_time_actual: raw.backlog_wait_time_actual,
        })
    }
}

impl Emitable for StatusMessage {
    fn buffer_len(&self) -> usize {
        STATUS_MESSAGE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = StatusMessageBuffer::from(self);
        buffer[..STATUS_MESSAGE_LEN].copy_from_slice(raw.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real kernel reply captured from a NETLINK_AUDIT socket with
    // AUDIT_GET:
    //
    //     auditctl -s
    //
    // nlmon cannot capture NETLINK_AUDIT traffic because the kernel's
    // netlink monitor whitelist does not include it.
    const GET_REPLY_PAYLOAD: [u8; 44] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00,
        0x60, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_real_get_reply() {
        let parsed = StatusMessage::parse(&GET_REPLY_PAYLOAD).unwrap();
        assert_eq!(parsed.mask, AuditStatus::empty());
        assert_eq!(parsed.enabled, 0);
        assert_eq!(parsed.failure, 1);
        assert_eq!(parsed.pid, 0);
        assert_eq!(parsed.rate_limiting, 0);
        assert_eq!(parsed.backlog_limit, 64);
        assert_eq!(parsed.lost, 0);
        assert_eq!(parsed.backlog, 0);
        assert_eq!(parsed.feature_bitmap.bits(), 0x7f);
        assert_eq!(parsed.backlog_wait_time, 60000);
        assert_eq!(parsed.backlog_wait_time_actual, 0);

        let mut buffer = vec![0; parsed.buffer_len()];
        parsed.emit(&mut buffer);
        assert_eq!(buffer, GET_REPLY_PAYLOAD);
    }

    #[test]
    fn audit_feature_bitmap_bits() {
        let features = AuditFeatureBitmap::BacklogLimit
            | AuditFeatureBitmap::BacklogWaitTime
            | AuditFeatureBitmap::ExecutablePath
            | AuditFeatureBitmap::ExcludeExtend
            | AuditFeatureBitmap::SessionIdFilter
            | AuditFeatureBitmap::LostReset
            | AuditFeatureBitmap::FilterFs;
        assert_eq!(features.bits(), 0x7f);
        assert_eq!(features.bits(), 0x7f);
        assert!(features.contains(AuditFeatureBitmap::FilterFs));
    }

    #[test]
    fn audit_status_bits() {
        let mask = AuditStatus::Enabled
            | AuditStatus::Failure
            | AuditStatus::Pid
            | AuditStatus::RateLimit
            | AuditStatus::BacklogLimit
            | AuditStatus::BacklogWaitTime
            | AuditStatus::Lost
            | AuditStatus::BacklogWaitTimeActual;
        assert_eq!(mask.bits(), 0xff);
        assert!(mask.contains(AuditStatus::Enabled));
        assert!(mask.contains(AuditStatus::Failure));
        assert!(mask.contains(AuditStatus::Pid));
        assert!(mask.contains(AuditStatus::RateLimit));
        assert!(mask.contains(AuditStatus::BacklogLimit));
        assert!(mask.contains(AuditStatus::BacklogWaitTime));
        assert!(mask.contains(AuditStatus::Lost));
        assert!(mask.contains(AuditStatus::BacklogWaitTimeActual));
    }
}
