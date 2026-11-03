// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, NetlinkMessage, NetlinkPayload};

use crate::{AuditFeatureBitmap, AuditMessage, AuditStatus, StatusMessage};

use super::header;

#[test]
fn test_get_status_reply() {
    let expected = NetlinkMessage::new(
        header(60, 1000, 0, 0x1122_3345),
        NetlinkPayload::from(AuditMessage::GetStatus(Some(StatusMessage {
            mask: AuditStatus::empty(),
            enabled: 0,
            failure: 1,
            pid: 0,
            rate_limiting: 0,
            backlog_limit: 64,
            lost: 0,
            backlog: 0,
            feature_bitmap: AuditFeatureBitmap::from_bits_retain(0x7f),
            backlog_wait_time: 60000,
            backlog_wait_time_actual: 0,
        }))),
    );

    assert_eq!(
        NetlinkMessage::<AuditMessage>::deserialize(&GET_REPLY_BYTES).unwrap(),
        expected
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);
    assert_eq!(buffer.as_slice(), &GET_REPLY_BYTES[..]);
}

#[test]
fn test_set_status_request() {
    let mut status = StatusMessage::new();
    status.mask = AuditStatus::BacklogLimit;
    status.backlog_limit = 64;

    let expected = NetlinkMessage::new(
        header(60, 1001, 5, 1),
        NetlinkPayload::from(AuditMessage::SetStatus(status)),
    );

    assert_eq!(
        NetlinkMessage::<AuditMessage>::deserialize(&SET_REQUEST_BYTES)
            .unwrap(),
        expected
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);
    assert_eq!(buffer.as_slice(), &SET_REQUEST_BYTES[..]);
}

#[test]
fn test_get_status_request() {
    let expected = NetlinkMessage::new(
        header(16, 1000, 1, 0x1122_3345),
        NetlinkPayload::from(AuditMessage::GetStatus(None)),
    );

    assert_eq!(
        NetlinkMessage::<AuditMessage>::deserialize(&GET_REQUEST_BYTES)
            .unwrap(),
        expected
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);
    assert_eq!(buffer.as_slice(), &GET_REQUEST_BYTES[..]);
}

const GET_REPLY_BYTES: [u8; 60] = [
    // len = 60
    0x3c, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x45, 0x33, 0x22, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x00, 0x60, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const SET_REQUEST_BYTES: [u8; 60] = [
    // len = 60
    0x3c, 0x00, 0x00, 0x00, 0xe9, 0x03, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const GET_REQUEST_BYTES: [u8; 16] = [
    // len = 16
    0x10, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x01, 0x00, 0x45, 0x33, 0x22, 0x11,
    0x00, 0x00, 0x00, 0x00,
];
