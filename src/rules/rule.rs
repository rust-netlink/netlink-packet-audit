// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, EncodeError};
use zerocopy::IntoBytes;

use crate::rules::{
    field::MAX_FIELDS, syscalls::BITMASK_SIZE, RuleAction, RuleField,
    RuleFieldFlags, RuleFlags, RuleMessageBuffer, RuleSyscalls,
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
}

impl Emitable for RuleMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut syscalls = [0u32; BITMASK_SIZE];
        syscalls.copy_from_slice(&self.syscalls.0);

        let mut fields = [0u32; MAX_FIELDS];
        let mut values = [0u32; MAX_FIELDS];
        let mut field_flags = [0u32; MAX_FIELDS];
        let mut strings = Vec::new();

        let field_count = self.fields.len().min(MAX_FIELDS);
        for (index, (field, flags)) in
            self.fields.iter().take(field_count).enumerate()
        {
            fields[index] = field.kind();
            field_flags[index] = (*flags).into();
            if let Some(string) = field.string() {
                values[index] = string.len() as u32;
                strings.extend_from_slice(string.as_bytes());
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
            buflen: strings.len() as u32,
        };
        out.extend_from_slice(raw.as_bytes());
        out.extend_from_slice(&strings);
        Ok(())
    }
}
