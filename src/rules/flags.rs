// SPDX-License-Identifier: MIT

use std::ops::{BitOr, BitOrAssign};

const AUDIT_FILTER_USER: u32 = 0;
const AUDIT_FILTER_TASK: u32 = 1;
const AUDIT_FILTER_ENTRY: u32 = 2;
const AUDIT_FILTER_WATCH: u32 = 3;
const AUDIT_FILTER_EXIT: u32 = 4;
const AUDIT_FILTER_EXCLUDE: u32 = 5;
const AUDIT_FILTER_TYPE: u32 = AUDIT_FILTER_EXCLUDE;
const AUDIT_FILTER_FS: u32 = 6;
const AUDIT_FILTER_URING_EXIT: u32 = 7;
const AUDIT_NR_FILTERS: u32 = 8;
const AUDIT_FILTER_PREPEND: u32 = 16;
const AUDIT_FILTER_UNSET: u32 = 128;

#[derive(Copy, Debug, PartialEq, Eq, Clone, Hash, Default)]
pub struct RuleFlags(u32);

#[allow(non_upper_case_globals)]
impl RuleFlags {
    pub const FilterUser: Self = Self(AUDIT_FILTER_USER);
    pub const FilterTask: Self = Self(AUDIT_FILTER_TASK);
    pub const FilterEntry: Self = Self(AUDIT_FILTER_ENTRY);
    pub const FilterWatch: Self = Self(AUDIT_FILTER_WATCH);
    pub const FilterExit: Self = Self(AUDIT_FILTER_EXIT);
    pub const FilterExclude: Self = Self(AUDIT_FILTER_EXCLUDE);
    pub const FilterType: Self = Self(AUDIT_FILTER_TYPE);
    pub const FilterFs: Self = Self(AUDIT_FILTER_FS);
    pub const FilterUringExit: Self = Self(AUDIT_FILTER_URING_EXIT);
    pub const NrFilters: Self = Self(AUDIT_NR_FILTERS);
    pub const FilterPrepend: Self = Self(AUDIT_FILTER_PREPEND);
    pub const Unset: Self = Self(AUDIT_FILTER_UNSET);

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    pub fn is_prepend(self) -> bool {
        self.0 & AUDIT_FILTER_PREPEND != 0
    }

    pub fn without_prepend(self) -> Self {
        Self(self.0 & !AUDIT_FILTER_PREPEND)
    }
}

impl BitOr for RuleFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for RuleFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl From<u32> for RuleFlags {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<RuleFlags> for u32 {
    fn from(value: RuleFlags) -> Self {
        value.0
    }
}
