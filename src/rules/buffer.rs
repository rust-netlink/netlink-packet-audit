// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Parseable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::rules::{
    field::MAX_FIELDS, syscalls::BITMASK_SIZE, RuleField, RuleFieldFlags,
    RuleMessage, RuleSyscalls,
};

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
pub struct RuleMessageBuffer {
    pub(crate) flags: u32,
    pub(crate) action: u32,
    pub(crate) field_count: u32,
    pub(crate) syscalls: [u32; BITMASK_SIZE],
    pub(crate) fields: [u32; MAX_FIELDS],
    pub(crate) values: [u32; MAX_FIELDS],
    pub(crate) field_flags: [u32; MAX_FIELDS],
    pub(crate) buflen: u32,
}

pub(crate) const RULE_BUF_MIN_LEN: usize = size_of::<RuleMessageBuffer>();

impl Parseable<[u8]> for RuleMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let (raw, rest) =
            RuleMessageBuffer::ref_from_prefix(buf).map_err(|_| {
                DecodeError::buffer_too_small(buf.len(), RULE_BUF_MIN_LEN)
            })?;

        let field_count = raw.field_count as usize;
        if field_count > MAX_FIELDS {
            return Err(format!(
                "invalid rule message field count: {field_count} > \
                {MAX_FIELDS}"
            )
            .into());
        }

        let buflen = raw.buflen as usize;
        if rest.len() < buflen {
            return Err(format!(
                "buffer length is {}, but it should be {} (header) + {} \
                (length field)",
                buf.len(),
                RULE_BUF_MIN_LEN,
                buflen
            )
            .into());
        }

        let syscalls = raw.syscalls;
        let fields = raw.fields;
        let values = raw.values;
        let field_flags = raw.field_flags;
        let strings = &rest[..buflen];

        let mut rule = RuleMessage::new();
        rule.flags = raw.flags.into();
        rule.action = raw.action.into();
        rule.syscalls = RuleSyscalls(syscalls.to_vec());

        let mut offset = 0;
        for index in 0..field_count {
            let kind = fields[index];
            let value = values[index];
            let flags = RuleFieldFlags::from(field_flags[index]);
            let string = if RuleField::is_string_kind(kind) {
                let str_end = offset + value as usize;
                if str_end > strings.len() {
                    return Err(format!(
                        "failed to decode field. type={kind} (value should \
                        be a string?)"
                    )
                    .into());
                }
                let string =
                    String::from_utf8_lossy(&strings[offset..str_end]).into();
                offset = str_end;
                string
            } else {
                String::new()
            };
            let field = RuleField::from_kind(kind, value, string)?;
            rule.fields.push((field, flags));
        }
        Ok(rule)
    }
}
