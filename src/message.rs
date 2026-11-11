// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_string, DecodeError, Emitable, EncodeError, ErrorContext,
    NetlinkDeserializable, NetlinkHeader, NetlinkMessagePayload,
    NetlinkPayload, Parseable, ParseableParametrized,
};

use crate::{rules::RuleMessage, StatusMessage};

const AUDIT_GET: u16 = 1000;
const AUDIT_SET: u16 = 1001;
const AUDIT_ADD_RULE: u16 = 1011;
const AUDIT_DEL_RULE: u16 = 1012;
const AUDIT_LIST_RULES: u16 = 1013;

const AUDIT_EVENT_MESSAGE_MIN: u16 = 1300;
const AUDIT_EVENT_MESSAGE_MAX: u16 = 1399;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum AuditMessage {
    GetStatus(Option<StatusMessage>),
    SetStatus(StatusMessage),
    AddRule(RuleMessage),
    DelRule(RuleMessage),
    ListRules(Option<RuleMessage>),
    /// Event message (message types 1300 through 1399). This includes the
    /// following message types (this list is non-exhaustive, and not
    /// really kept up to date): `AUDIT_SYSCALL`, `AUDIT_PATH`,
    /// `AUDIT_IPC`, `AUDIT_SOCKETCALL`, `AUDIT_CONFIG_CHANGE`,
    /// `AUDIT_SOCKADDR`, `AUDIT_CWD`, `AUDIT_EXECVE`,
    /// `AUDIT_IPC_SET_PERM`, `AUDIT_MQ_OPEN`, `AUDIT_MQ_SENDRECV`,
    /// `AUDIT_MQ_NOTIFY`, `AUDIT_MQ_GETSETATTR`, `AUDIT_KERNEL_OTHER`,
    /// `AUDIT_FD_PAIR`, `AUDIT_OBJ_PID`, `AUDIT_TTY`, `AUDIT_EOE`,
    /// `AUDIT_BPRM_FCAPS`, `AUDIT_CAPSET`, `AUDIT_MMAP`,
    /// `AUDIT_NETFILTER_PKT`, `AUDIT_NETFILTER_CFG`, `AUDIT_SECCOMP`,
    /// `AUDIT_PROCTITLE`, `AUDIT_FEATURE_CHANGE`, `AUDIT_REPLACE`,
    /// `AUDIT_KERN_MODULE`, `AUDIT_FANOTIFY`.
    ///
    /// The first element of the tuple is the message type, and the second is
    /// the event data.
    Event((u16, String)),
    /// All the other events are parsed as such as they can be parsed also.
    Other((u16, String)),
}

impl AuditMessage {
    pub fn is_event(&self) -> bool {
        matches!(self, AuditMessage::Event(_))
    }

    pub fn is_get_status(&self) -> bool {
        matches!(self, AuditMessage::GetStatus(_))
    }

    pub fn is_set_status(&self) -> bool {
        matches!(self, AuditMessage::SetStatus(_))
    }

    pub fn is_add_rule(&self) -> bool {
        matches!(self, AuditMessage::AddRule(_))
    }

    pub fn is_del_rule(&self) -> bool {
        matches!(self, AuditMessage::DelRule(_))
    }

    pub fn is_list_rules(&self) -> bool {
        matches!(self, AuditMessage::ListRules(_))
    }

    pub fn message_type(&self) -> u16 {
        use self::AuditMessage::*;

        match self {
            GetStatus(_) => AUDIT_GET,
            SetStatus(_) => AUDIT_SET,
            ListRules(_) => AUDIT_LIST_RULES,
            AddRule(_) => AUDIT_ADD_RULE,
            DelRule(_) => AUDIT_DEL_RULE,
            Event((message_type, _)) => *message_type,
            Other((message_type, _)) => *message_type,
        }
    }
}

impl Emitable for AuditMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use self::AuditMessage::*;

        match self {
            GetStatus(Some(ref msg)) => msg.emit(out),
            SetStatus(ref msg) => msg.emit(out),
            AddRule(ref msg) => msg.emit(out),
            DelRule(ref msg) => msg.emit(out),
            ListRules(Some(ref msg)) => msg.emit(out),
            ListRules(None) | GetStatus(None) => Ok(()),
            Event((_, ref data)) | Other((_, ref data)) => {
                out.extend_from_slice(data.as_bytes());
                Ok(())
            }
        }
    }
}

impl ParseableParametrized<[u8], u16> for AuditMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        use self::AuditMessage::*;

        let message = match message_type {
            AUDIT_GET if buf.is_empty() => GetStatus(None),
            AUDIT_GET => GetStatus(Some(
                StatusMessage::parse(buf)
                    .context("failed to parse AUDIT_GET message")?,
            )),
            AUDIT_SET => SetStatus(
                StatusMessage::parse(buf)
                    .context("failed to parse AUDIT_SET message")?,
            ),
            AUDIT_ADD_RULE => AddRule(
                RuleMessage::parse(buf)
                    .context("failed to parse AUDIT_ADD_RULE message")?,
            ),
            AUDIT_DEL_RULE => DelRule(
                RuleMessage::parse(buf)
                    .context("failed to parse AUDIT_DEL_RULE message")?,
            ),
            AUDIT_LIST_RULES if buf.is_empty() => ListRules(None),
            AUDIT_LIST_RULES => ListRules(Some(
                RuleMessage::parse(buf)
                    .context("failed to parse AUDIT_LIST_RULES message")?,
            )),
            i if (AUDIT_EVENT_MESSAGE_MIN..=AUDIT_EVENT_MESSAGE_MAX)
                .contains(&i) =>
            {
                let data = parse_string(buf).context(
                    "failed to parse audit event data as a valid string",
                )?;
                Event((i, data))
            }
            i => {
                let data = parse_string(buf).context(
                    "failed to parse audit event data as a valid string",
                )?;
                Other((i, data))
            }
        };
        Ok(message)
    }
}

impl NetlinkMessagePayload for AuditMessage {
    fn message_type(&self) -> u16 {
        self.message_type()
    }
}

impl NetlinkDeserializable for AuditMessage {
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        AuditMessage::parse_with_param(payload, header.message_type)
    }
}

impl From<AuditMessage> for NetlinkPayload<AuditMessage> {
    fn from(message: AuditMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
