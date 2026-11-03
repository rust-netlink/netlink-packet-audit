// SPDX-License-Identifier: MIT

use netlink_packet_core::Emitable;
use zerocopy::IntoBytes;

use crate::rules::{
    buffer::RULE_BUF_MIN_LEN, field::MAX_FIELDS, syscalls::BITMASK_SIZE,
    RuleAction, RuleField, RuleFieldFlags, RuleFlags, RuleMessageBuffer,
    RuleSyscalls,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct RuleMessage {
    pub flags: RuleFlags,
    pub action: RuleAction,
    pub fields: Vec<(RuleField, RuleFieldFlags)>,
    pub syscalls: RuleSyscalls,
}

impl Default for RuleMessage {
    fn default() -> Self {
        RuleMessage::new()
    }
}

impl RuleMessage {
    pub fn new() -> Self {
        RuleMessage {
            flags: RuleFlags::from(0),
            action: RuleAction::from(0),
            fields: Vec::with_capacity(MAX_FIELDS),
            syscalls: RuleSyscalls::new_zeroed(),
        }
    }

    fn compute_string_values_length(&self) -> usize {
        self.fields
            .iter()
            .take(MAX_FIELDS)
            .map(|(field, _)| field.string().map_or(0, str::len))
            .sum()
    }
}

impl Emitable for RuleMessage {
    fn buffer_len(&self) -> usize {
        RULE_BUF_MIN_LEN + self.compute_string_values_length()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut syscalls = [0u32; BITMASK_SIZE];
        syscalls.copy_from_slice(&self.syscalls.0);

        let mut fields = [0u32; MAX_FIELDS];
        let mut values = [0u32; MAX_FIELDS];
        let mut field_flags = [0u32; MAX_FIELDS];

        let field_count = self.fields.len().min(MAX_FIELDS);
        let mut string_offset = 0;
        for (index, (field, flags)) in
            self.fields.iter().take(field_count).enumerate()
        {
            fields[index] = field.kind();
            field_flags[index] = (*flags).into();
            if let Some(string) = field.string() {
                values[index] = string.len() as u32;
                let start = RULE_BUF_MIN_LEN + string_offset;
                let end = start + string.len();
                buffer[start..end].copy_from_slice(string.as_bytes());
                string_offset += string.len();
            } else {
                values[index] = field.value();
            }
        }

        let raw = RuleMessageBuffer {
            flags: self.flags.into(),
            action: self.action.into(),
            field_count: field_count as u32,
            syscalls,
            fields,
            values,
            field_flags,
            buflen: string_offset as u32,
        };
        buffer[..RULE_BUF_MIN_LEN].copy_from_slice(raw.as_bytes());
    }
}
