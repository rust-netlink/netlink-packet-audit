// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, Emitable, Parseable,
};

use crate::Field;

const MASK: Field = 0..4;
const ENABLED: Field = 4..8;
const FAILURE: Field = 8..12;
const PID: Field = 12..16;
const RATE_LIMITING: Field = 16..20;
const BACKLOG_LIMIT: Field = 20..24;
const LOST: Field = 24..28;
const BACKLOG: Field = 28..32;
const FEATURE_BITMAP: Field = 32..36;
const BACKLOG_WAIT_TIME: Field = 36..40;
pub const STATUS_MESSAGE_LEN: usize = BACKLOG_WAIT_TIME.end;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct StatusMessage {
    /// Bit mask for valid entries
    pub mask: u32,
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
    pub feature_bitmap: u32,
    /// Message queue wait timeout
    pub backlog_wait_time: u32,
}

impl StatusMessage {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct StatusMessageBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> StatusMessageBuffer<T> {
    pub fn new(buffer: T) -> StatusMessageBuffer<T> {
        StatusMessageBuffer { buffer }
    }

    pub fn new_checked(
        buffer: T,
    ) -> Result<StatusMessageBuffer<T>, DecodeError> {
        let buf = Self::new(buffer);
        buf.check_buffer_length()?;
        Ok(buf)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < STATUS_MESSAGE_LEN {
            return Err(format!(
                "invalid StatusMessageBuffer buffer: length is {len} \
                instead of {STATUS_MESSAGE_LEN}"
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn mask(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[MASK]).unwrap()
    }

    pub fn enabled(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[ENABLED]).unwrap()
    }

    pub fn failure(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[FAILURE]).unwrap()
    }

    pub fn pid(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[PID]).unwrap()
    }

    pub fn rate_limiting(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[RATE_LIMITING]).unwrap()
    }

    pub fn backlog_limit(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[BACKLOG_LIMIT]).unwrap()
    }

    pub fn lost(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[LOST]).unwrap()
    }

    pub fn backlog(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[BACKLOG]).unwrap()
    }

    pub fn feature_bitmap(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[FEATURE_BITMAP]).unwrap()
    }

    pub fn backlog_wait_time(&self) -> u32 {
        parse_u32(&self.buffer.as_ref()[BACKLOG_WAIT_TIME]).unwrap()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> StatusMessageBuffer<T> {
    pub fn set_mask(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[MASK], value).unwrap()
    }

    pub fn set_enabled(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[ENABLED], value).unwrap()
    }

    pub fn set_failure(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[FAILURE], value).unwrap()
    }

    pub fn set_pid(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[PID], value).unwrap()
    }

    pub fn set_rate_limiting(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[RATE_LIMITING], value).unwrap()
    }

    pub fn set_backlog_limit(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[BACKLOG_LIMIT], value).unwrap()
    }

    pub fn set_lost(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[LOST], value).unwrap()
    }

    pub fn set_backlog(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[BACKLOG], value).unwrap()
    }

    pub fn set_feature_bitmap(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[FEATURE_BITMAP], value).unwrap()
    }

    pub fn set_backlog_wait_time(&mut self, value: u32) {
        emit_u32(&mut self.buffer.as_mut()[BACKLOG_WAIT_TIME], value).unwrap()
    }
}

impl<T: AsRef<[u8]>> Parseable<StatusMessageBuffer<T>> for StatusMessage {
    fn parse(buf: &StatusMessageBuffer<T>) -> Result<Self, DecodeError> {
        buf.check_buffer_length()?;
        Ok(StatusMessage {
            mask: buf.mask(),
            enabled: buf.enabled(),
            failure: buf.failure(),
            pid: buf.pid(),
            rate_limiting: buf.rate_limiting(),
            backlog_limit: buf.backlog_limit(),
            lost: buf.lost(),
            backlog: buf.backlog(),
            feature_bitmap: buf.feature_bitmap(),
            backlog_wait_time: buf.backlog_wait_time(),
        })
    }
}

impl Emitable for StatusMessage {
    fn buffer_len(&self) -> usize {
        STATUS_MESSAGE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = StatusMessageBuffer::new(buffer);
        buffer.set_mask(self.mask);
        buffer.set_enabled(self.enabled);
        buffer.set_failure(self.failure);
        buffer.set_pid(self.pid);
        buffer.set_rate_limiting(self.rate_limiting);
        buffer.set_backlog_limit(self.backlog_limit);
        buffer.set_lost(self.lost);
        buffer.set_backlog(self.backlog);
        buffer.set_feature_bitmap(self.feature_bitmap);
        buffer.set_backlog_wait_time(self.backlog_wait_time);
    }
}
