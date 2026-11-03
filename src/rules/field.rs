// SPDX-License-Identifier: MIT

use netlink_packet_core::DecodeError;

pub(crate) const MAX_FIELDS: usize = 64;

const AUDIT_PID: u32 = 0;
const AUDIT_UID: u32 = 1;
const AUDIT_EUID: u32 = 2;
const AUDIT_SUID: u32 = 3;
const AUDIT_FSUID: u32 = 4;
const AUDIT_GID: u32 = 5;
const AUDIT_EGID: u32 = 6;
const AUDIT_SGID: u32 = 7;
const AUDIT_FSGID: u32 = 8;
const AUDIT_LOGINUID: u32 = 9;
const AUDIT_PERS: u32 = 10;
const AUDIT_ARCH: u32 = 11;
const AUDIT_MSGTYPE: u32 = 12;
const AUDIT_SUBJ_USER: u32 = 13;
const AUDIT_SUBJ_ROLE: u32 = 14;
const AUDIT_SUBJ_TYPE: u32 = 15;
const AUDIT_SUBJ_SEN: u32 = 16;
const AUDIT_SUBJ_CLR: u32 = 17;
const AUDIT_PPID: u32 = 18;
const AUDIT_OBJ_USER: u32 = 19;
const AUDIT_OBJ_ROLE: u32 = 20;
const AUDIT_OBJ_TYPE: u32 = 21;
const AUDIT_OBJ_LEV_LOW: u32 = 22;
const AUDIT_OBJ_LEV_HIGH: u32 = 23;
const AUDIT_LOGINUID_SET: u32 = 24;
const AUDIT_SESSIONID: u32 = 25;
const AUDIT_FSTYPE: u32 = 26;
const AUDIT_DEVMAJOR: u32 = 100;
const AUDIT_DEVMINOR: u32 = 101;
const AUDIT_INODE: u32 = 102;
const AUDIT_EXIT: u32 = 103;
const AUDIT_SUCCESS: u32 = 104;
const AUDIT_WATCH: u32 = 105;
const AUDIT_PERM: u32 = 106;
const AUDIT_DIR: u32 = 107;
const AUDIT_FILETYPE: u32 = 108;
const AUDIT_OBJ_UID: u32 = 109;
const AUDIT_OBJ_GID: u32 = 110;
const AUDIT_FIELD_COMPARE: u32 = 111;
const AUDIT_EXE: u32 = 112;
const AUDIT_SADDR_FAM: u32 = 113;
const AUDIT_ARG0: u32 = 200;
const AUDIT_ARG1: u32 = 201;
const AUDIT_ARG2: u32 = 202;
const AUDIT_ARG3: u32 = 203;
const AUDIT_FILTERKEY: u32 = 210;

const AUDIT_BIT_MASK: u32 = 0x0800_0000;
const AUDIT_LESS_THAN: u32 = 0x1000_0000;
const AUDIT_GREATER_THAN: u32 = 0x2000_0000;
const AUDIT_NOT_EQUAL: u32 = 0x3000_0000;
const AUDIT_EQUAL: u32 = 0x4000_0000;
const AUDIT_BIT_TEST: u32 = AUDIT_BIT_MASK | AUDIT_EQUAL;
const AUDIT_LESS_THAN_OR_EQUAL: u32 = AUDIT_LESS_THAN | AUDIT_EQUAL;
const AUDIT_GREATER_THAN_OR_EQUAL: u32 = AUDIT_GREATER_THAN | AUDIT_EQUAL;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RuleField {
    Pid(u32),
    Uid(u32),
    Euid(u32),
    Suid(u32),
    Fsuid(u32),
    Gid(u32),
    Egid(u32),
    Sgid(u32),
    Fsgid(u32),
    Loginuid(u32),
    Pers(u32),
    Arch(u32),
    Msgtype(u32),
    Ppid(u32),
    LoginuidSet(u32),
    Sessionid(u32),
    Fstype(u32),
    Devmajor(u32),
    Devminor(u32),
    Inode(u32),
    Exit(u32),
    Success(u32),
    Perm(u32),
    Filetype(u32),
    ObjUid(u32),
    ObjGid(u32),
    FieldCompare(u32),
    Exe(String),
    SaddrFam(u32),
    Arg0(u32),
    Arg1(u32),
    Arg2(u32),
    Arg3(u32),

    Watch(String),
    Dir(String),
    Filterkey(String),

    SubjUser(String),
    SubjRole(String),
    SubjType(String),
    SubjSen(String),
    SubjClr(String),

    ObjUser(String),
    ObjRole(String),
    ObjType(String),
    ObjLevLow(String),
    ObjLevHigh(String),
}

impl RuleField {
    pub(crate) fn kind(&self) -> u32 {
        use self::RuleField::*;
        match self {
            Pid(_) => AUDIT_PID,
            Uid(_) => AUDIT_UID,
            Euid(_) => AUDIT_EUID,
            Suid(_) => AUDIT_SUID,
            Fsuid(_) => AUDIT_FSUID,
            Gid(_) => AUDIT_GID,
            Egid(_) => AUDIT_EGID,
            Sgid(_) => AUDIT_SGID,
            Fsgid(_) => AUDIT_FSGID,
            Loginuid(_) => AUDIT_LOGINUID,
            Pers(_) => AUDIT_PERS,
            Arch(_) => AUDIT_ARCH,
            Msgtype(_) => AUDIT_MSGTYPE,
            Ppid(_) => AUDIT_PPID,
            LoginuidSet(_) => AUDIT_LOGINUID_SET,
            Sessionid(_) => AUDIT_SESSIONID,
            Fstype(_) => AUDIT_FSTYPE,
            Devmajor(_) => AUDIT_DEVMAJOR,
            Devminor(_) => AUDIT_DEVMINOR,
            Inode(_) => AUDIT_INODE,
            Exit(_) => AUDIT_EXIT,
            Success(_) => AUDIT_SUCCESS,
            Perm(_) => AUDIT_PERM,
            Filetype(_) => AUDIT_FILETYPE,
            ObjUid(_) => AUDIT_OBJ_UID,
            ObjGid(_) => AUDIT_OBJ_GID,
            FieldCompare(_) => AUDIT_FIELD_COMPARE,
            Exe(_) => AUDIT_EXE,
            SaddrFam(_) => AUDIT_SADDR_FAM,
            Arg0(_) => AUDIT_ARG0,
            Arg1(_) => AUDIT_ARG1,
            Arg2(_) => AUDIT_ARG2,
            Arg3(_) => AUDIT_ARG3,
            Watch(_) => AUDIT_WATCH,
            Dir(_) => AUDIT_DIR,
            Filterkey(_) => AUDIT_FILTERKEY,
            SubjUser(_) => AUDIT_SUBJ_USER,
            SubjRole(_) => AUDIT_SUBJ_ROLE,
            SubjType(_) => AUDIT_SUBJ_TYPE,
            SubjSen(_) => AUDIT_SUBJ_SEN,
            SubjClr(_) => AUDIT_SUBJ_CLR,
            ObjUser(_) => AUDIT_OBJ_USER,
            ObjRole(_) => AUDIT_OBJ_ROLE,
            ObjType(_) => AUDIT_OBJ_TYPE,
            ObjLevLow(_) => AUDIT_OBJ_LEV_LOW,
            ObjLevHigh(_) => AUDIT_OBJ_LEV_HIGH,
        }
    }

    pub(crate) fn value(&self) -> u32 {
        use self::RuleField::*;
        match self {
            Pid(value) | Uid(value) | Euid(value) | Suid(value)
            | Fsuid(value) | Gid(value) | Egid(value) | Sgid(value)
            | Fsgid(value) | Loginuid(value) | Pers(value) | Arch(value)
            | Msgtype(value) | Ppid(value) | LoginuidSet(value)
            | Sessionid(value) | Fstype(value) | Devmajor(value)
            | Devminor(value) | Inode(value) | Exit(value) | Success(value)
            | Perm(value) | Filetype(value) | ObjUid(value) | ObjGid(value)
            | FieldCompare(value) | SaddrFam(value) | Arg0(value)
            | Arg1(value) | Arg2(value) | Arg3(value) => *value,
            Watch(_) | Dir(_) | Filterkey(_) | SubjUser(_) | SubjRole(_)
            | SubjType(_) | SubjSen(_) | SubjClr(_) | ObjUser(_)
            | ObjRole(_) | ObjType(_) | ObjLevLow(_) | ObjLevHigh(_)
            | Exe(_) => 0,
        }
    }

    pub(crate) fn string(&self) -> Option<&str> {
        use self::RuleField::*;
        match self {
            Watch(value) | Dir(value) | Filterkey(value) | SubjUser(value)
            | SubjRole(value) | SubjType(value) | SubjSen(value)
            | SubjClr(value) | ObjUser(value) | ObjRole(value)
            | ObjType(value) | ObjLevLow(value) | ObjLevHigh(value)
            | Exe(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn is_string_kind(kind: u32) -> bool {
        matches!(
            kind,
            AUDIT_WATCH
                | AUDIT_DIR
                | AUDIT_FILTERKEY
                | AUDIT_SUBJ_USER
                | AUDIT_SUBJ_ROLE
                | AUDIT_SUBJ_TYPE
                | AUDIT_SUBJ_SEN
                | AUDIT_SUBJ_CLR
                | AUDIT_OBJ_USER
                | AUDIT_OBJ_ROLE
                | AUDIT_OBJ_TYPE
                | AUDIT_OBJ_LEV_LOW
                | AUDIT_OBJ_LEV_HIGH
                | AUDIT_EXE
        )
    }

    pub(crate) fn from_kind(
        kind: u32,
        value: u32,
        string: String,
    ) -> Result<Self, DecodeError> {
        use self::RuleField::*;
        Ok(match kind {
            AUDIT_PID => Pid(value),
            AUDIT_UID => Uid(value),
            AUDIT_EUID => Euid(value),
            AUDIT_SUID => Suid(value),
            AUDIT_FSUID => Fsuid(value),
            AUDIT_GID => Gid(value),
            AUDIT_EGID => Egid(value),
            AUDIT_SGID => Sgid(value),
            AUDIT_FSGID => Fsgid(value),
            AUDIT_LOGINUID => Loginuid(value),
            AUDIT_PERS => Pers(value),
            AUDIT_ARCH => Arch(value),
            AUDIT_MSGTYPE => Msgtype(value),
            AUDIT_PPID => Ppid(value),
            AUDIT_LOGINUID_SET => LoginuidSet(value),
            AUDIT_SESSIONID => Sessionid(value),
            AUDIT_FSTYPE => Fstype(value),
            AUDIT_DEVMAJOR => Devmajor(value),
            AUDIT_DEVMINOR => Devminor(value),
            AUDIT_INODE => Inode(value),
            AUDIT_EXIT => Exit(value),
            AUDIT_SUCCESS => Success(value),
            AUDIT_PERM => Perm(value),
            AUDIT_FILETYPE => Filetype(value),
            AUDIT_OBJ_UID => ObjUid(value),
            AUDIT_OBJ_GID => ObjGid(value),
            AUDIT_FIELD_COMPARE => FieldCompare(value),
            AUDIT_EXE => Exe(string),
            AUDIT_SADDR_FAM => SaddrFam(value),
            AUDIT_ARG0 => Arg0(value),
            AUDIT_ARG1 => Arg1(value),
            AUDIT_ARG2 => Arg2(value),
            AUDIT_ARG3 => Arg3(value),
            AUDIT_WATCH => Watch(string),
            AUDIT_DIR => Dir(string),
            AUDIT_FILTERKEY => Filterkey(string),
            AUDIT_SUBJ_USER => SubjUser(string),
            AUDIT_SUBJ_ROLE => SubjRole(string),
            AUDIT_SUBJ_TYPE => SubjType(string),
            AUDIT_SUBJ_SEN => SubjSen(string),
            AUDIT_SUBJ_CLR => SubjClr(string),
            AUDIT_OBJ_USER => ObjUser(string),
            AUDIT_OBJ_ROLE => ObjRole(string),
            AUDIT_OBJ_TYPE => ObjType(string),
            AUDIT_OBJ_LEV_LOW => ObjLevLow(string),
            AUDIT_OBJ_LEV_HIGH => ObjLevHigh(string),
            _ => {
                return Err(format!(
                    "failed to decode field (unknown type) type={kind}, \
                    value={string}"
                )
                .into());
            }
        })
    }
}

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RuleFieldFlags {
    BitMask,
    BitTest,
    LessThan,
    GreaterThan,
    NotEqual,
    Equal,
    LessThanOrEqual,
    GreaterThanOrEqual,
    None,
    Unknown(u32),
}

impl From<u32> for RuleFieldFlags {
    fn from(value: u32) -> Self {
        use self::RuleFieldFlags::*;
        match value {
            AUDIT_BIT_MASK => BitMask,
            AUDIT_BIT_TEST => BitTest,
            AUDIT_LESS_THAN => LessThan,
            AUDIT_GREATER_THAN => GreaterThan,
            AUDIT_NOT_EQUAL => NotEqual,
            AUDIT_EQUAL => Equal,
            AUDIT_LESS_THAN_OR_EQUAL => LessThanOrEqual,
            AUDIT_GREATER_THAN_OR_EQUAL => GreaterThanOrEqual,
            0 => None,
            _ => Unknown(value),
        }
    }
}

impl From<RuleFieldFlags> for u32 {
    fn from(value: RuleFieldFlags) -> Self {
        use self::RuleFieldFlags::*;
        match value {
            BitMask => AUDIT_BIT_MASK,
            BitTest => AUDIT_BIT_TEST,
            LessThan => AUDIT_LESS_THAN,
            GreaterThan => AUDIT_GREATER_THAN,
            NotEqual => AUDIT_NOT_EQUAL,
            Equal => AUDIT_EQUAL,
            LessThanOrEqual => AUDIT_LESS_THAN_OR_EQUAL,
            GreaterThanOrEqual => AUDIT_GREATER_THAN_OR_EQUAL,
            None => 0,
            Unknown(value) => value,
        }
    }
}
