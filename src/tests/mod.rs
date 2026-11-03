// SPDX-License-Identifier: MIT

// All the packets in this module are real kernel packets captured on the
// `dev` host through a NETLINK_AUDIT socket. nlmon cannot be used for
// NETLINK_AUDIT because the kernel's netlink monitor whitelist does not
// include it.

use netlink_packet_core::NetlinkHeader;

use crate::rules::{
    RuleAction, RuleField, RuleFieldFlags, RuleFlags, RuleMessage, RuleSyscalls,
};

mod events;
mod rules;
mod status;

fn header(
    length: u32,
    message_type: u16,
    flags: u16,
    sequence_number: u32,
) -> NetlinkHeader {
    let mut header = NetlinkHeader::default();
    header.length = length;
    header.message_type = message_type;
    header.flags = flags;
    header.sequence_number = sequence_number;
    header
}

fn rule_m3() -> RuleMessage {
    let mut syscalls = RuleSyscalls::new_zeroed();
    syscalls.set(135);
    RuleMessage {
        flags: RuleFlags::FilterExit,
        action: RuleAction::Always,
        fields: vec![
            (RuleField::Arch(0xC000_003E), RuleFieldFlags::Equal),
            (RuleField::Filterkey("bypass".into()), RuleFieldFlags::Equal),
        ],
        syscalls,
    }
}
