// SPDX-License-Identifier: MIT

use byteorder::{ByteOrder, NativeEndian};

use netlink_packet_utils::{
    traits::{Emitable, Parseable},
    DecodeError,
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
pub const MINIMAL_STATUS_MESSAGE_LEN: usize = BACKLOG.end;
const FEATURE_BITMAP: Field = 32..36;
const BACKLOG_WAIT_TIME: Field = 36..40;
const BACKLOG_WAIT_TIME_ACTUAL: Field = 36..40;
pub const MAXIMAL_STATUS_MESSAGE_LEN: usize = BACKLOG_WAIT_TIME_ACTUAL.end;

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

    // Starting here, those fields may not be present in older kernels, hence
    // the use of Option.
    /// bitmap of kernel audit features
    pub feature_bitmap: Option<u32>,
    /// Message queue wait timeout
    pub backlog_wait_time: Option<u32>,
    /// Time spent waiting while message limit exceeded
    pub backlog_wait_time_actual: Option<u32>,
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
        if len < MINIMAL_STATUS_MESSAGE_LEN {
            return Err(format!(
                "invalid StatusMessageBuffer buffer: length is {len} \
                instead of at least {MINIMAL_STATUS_MESSAGE_LEN}"
            )
            .into());
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn mask(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[MASK])
    }

    pub fn enabled(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[ENABLED])
    }

    pub fn failure(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[FAILURE])
    }

    pub fn pid(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[PID])
    }

    pub fn rate_limiting(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[RATE_LIMITING])
    }

    pub fn backlog_limit(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG_LIMIT])
    }

    pub fn lost(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[LOST])
    }

    pub fn backlog(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BACKLOG])
    }

    pub fn feature_bitmap(&self) -> Option<u32> {
        let buf = self.buffer.as_ref();
        if buf.len() < FEATURE_BITMAP.end {
            None
        } else {
            Some(NativeEndian::read_u32(&buf[FEATURE_BITMAP]))
        }
    }

    pub fn backlog_wait_time(&self) -> Option<u32> {
        let buf = self.buffer.as_ref();
        if buf.len() < BACKLOG_WAIT_TIME.end {
            None
        } else {
            Some(NativeEndian::read_u32(&buf[BACKLOG_WAIT_TIME]))
        }
    }

    pub fn backlog_wait_time_actual(&self) -> Option<u32> {
        let buf = self.buffer.as_ref();
        if buf.len() < BACKLOG_WAIT_TIME_ACTUAL.end {
            None
        } else {
            Some(NativeEndian::read_u32(&buf[BACKLOG_WAIT_TIME_ACTUAL]))
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> StatusMessageBuffer<T> {
    pub fn set_mask(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[MASK], value)
    }

    pub fn set_enabled(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[ENABLED], value)
    }

    pub fn set_failure(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[FAILURE], value)
    }

    pub fn set_pid(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[PID], value)
    }

    pub fn set_rate_limiting(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[RATE_LIMITING], value)
    }

    pub fn set_backlog_limit(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG_LIMIT], value)
    }

    pub fn set_lost(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[LOST], value)
    }

    pub fn set_backlog(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BACKLOG], value)
    }

    pub fn set_feature_bitmap(&mut self, value: u32) {
        let buf = &mut self.buffer.as_mut();
        if buf.len() >= FEATURE_BITMAP.end {
            NativeEndian::write_u32(&mut buf[FEATURE_BITMAP], value)
        }
    }

    pub fn set_backlog_wait_time(&mut self, value: u32) {
        let buf = &mut self.buffer.as_mut();
        if buf.len() >= BACKLOG_WAIT_TIME.end {
            NativeEndian::write_u32(&mut buf[BACKLOG_WAIT_TIME], value)
        }
    }

    pub fn set_backlog_wait_time_actual(&mut self, value: u32) {
        let buf = &mut self.buffer.as_mut();
        if buf.len() >= BACKLOG_WAIT_TIME_ACTUAL.end {
            NativeEndian::write_u32(&mut buf[BACKLOG_WAIT_TIME_ACTUAL], value)
        }
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
            backlog_wait_time_actual: buf.backlog_wait_time_actual(),
        })
    }
}

impl Emitable for StatusMessage {
    fn buffer_len(&self) -> usize {
        MAXIMAL_STATUS_MESSAGE_LEN
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
        if let Some(feature_bitmap) = self.feature_bitmap {
            buffer.set_feature_bitmap(feature_bitmap);
        }
        if let Some(backlog_wait_time) = self.backlog_wait_time {
            buffer.set_backlog_wait_time(backlog_wait_time);
        }
        if let Some(backlog_wait_time_actual) = self.backlog_wait_time_actual {
            buffer.set_backlog_wait_time_actual(backlog_wait_time_actual);
        }
    }
}
