// SPDX-License-Identifier: MIT

const AUDIT_NEVER: u32 = 0;
const AUDIT_POSSIBLE: u32 = 1;
const AUDIT_ALWAYS: u32 = 2;

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RuleAction {
    Never,
    Possible,
    Always,
    Unknown(u32),
}

impl From<u32> for RuleAction {
    fn from(value: u32) -> Self {
        use self::RuleAction::*;
        match value {
            AUDIT_NEVER => Never,
            AUDIT_POSSIBLE => Possible,
            AUDIT_ALWAYS => Always,
            _ => Unknown(value),
        }
    }
}

impl From<RuleAction> for u32 {
    fn from(value: RuleAction) -> Self {
        use self::RuleAction::*;
        match value {
            Never => AUDIT_NEVER,
            Possible => AUDIT_POSSIBLE,
            Always => AUDIT_ALWAYS,
            Unknown(value) => value,
        }
    }
}
