// SMB2 header codec and the protocol constants this server uses.
//
// Field offsets follow MS-SMB2 section 2.2.1.2 (the sync header). We only ever
// emit sync headers: async responses exist to let a server return
// STATUS_PENDING on a long operation, and every operation here is either
// instant or served from a blocking task that the client waits on normally.

use anyhow::{Result, bail};

use super::wire::{Reader, Writer};

pub(crate) const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
pub(crate) const HEADER_LEN: usize = 64;

/// Command codes (MS-SMB2 2.2.1.2, `Command`).
pub(crate) mod cmd {
    pub(crate) const NEGOTIATE: u16 = 0x0000;
    pub(crate) const SESSION_SETUP: u16 = 0x0001;
    pub(crate) const LOGOFF: u16 = 0x0002;
    pub(crate) const TREE_CONNECT: u16 = 0x0003;
    pub(crate) const TREE_DISCONNECT: u16 = 0x0004;
    pub(crate) const CREATE: u16 = 0x0005;
    pub(crate) const CLOSE: u16 = 0x0006;
    pub(crate) const FLUSH: u16 = 0x0007;
    pub(crate) const READ: u16 = 0x0008;
    pub(crate) const WRITE: u16 = 0x0009;
    pub(crate) const LOCK: u16 = 0x000A;
    pub(crate) const IOCTL: u16 = 0x000B;
    pub(crate) const CANCEL: u16 = 0x000C;
    pub(crate) const ECHO: u16 = 0x000D;
    pub(crate) const QUERY_DIRECTORY: u16 = 0x000E;
    pub(crate) const CHANGE_NOTIFY: u16 = 0x000F;
    pub(crate) const QUERY_INFO: u16 = 0x0010;
    pub(crate) const SET_INFO: u16 = 0x0011;
    pub(crate) const OPLOCK_BREAK: u16 = 0x0012;

    pub(crate) fn name(c: u16) -> &'static str {
        match c {
            NEGOTIATE => "NEGOTIATE",
            SESSION_SETUP => "SESSION_SETUP",
            LOGOFF => "LOGOFF",
            TREE_CONNECT => "TREE_CONNECT",
            TREE_DISCONNECT => "TREE_DISCONNECT",
            CREATE => "CREATE",
            CLOSE => "CLOSE",
            FLUSH => "FLUSH",
            READ => "READ",
            WRITE => "WRITE",
            LOCK => "LOCK",
            IOCTL => "IOCTL",
            CANCEL => "CANCEL",
            ECHO => "ECHO",
            QUERY_DIRECTORY => "QUERY_DIRECTORY",
            CHANGE_NOTIFY => "CHANGE_NOTIFY",
            QUERY_INFO => "QUERY_INFO",
            SET_INFO => "SET_INFO",
            OPLOCK_BREAK => "OPLOCK_BREAK",
            _ => "UNKNOWN",
        }
    }
}

/// NTSTATUS values (MS-ERREF 2.3.1). Only the ones this server can produce.
pub(crate) mod status {
    pub(crate) const SUCCESS: u32 = 0x0000_0000;
    pub(crate) const BUFFER_OVERFLOW: u32 = 0x8000_0005;
    pub(crate) const NO_MORE_FILES: u32 = 0x8000_0006;
    pub(crate) const INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    pub(crate) const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub(crate) const NO_SUCH_FILE: u32 = 0xC000_000F;
    pub(crate) const END_OF_FILE: u32 = 0xC000_0011;
    pub(crate) const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub(crate) const ACCESS_DENIED: u32 = 0xC000_0022;
    pub(crate) const EAS_NOT_SUPPORTED: u32 = 0xC000_004F;
    pub(crate) const NO_EAS_ON_FILE: u32 = 0xC000_0052;
    pub(crate) const OBJECT_NAME_INVALID: u32 = 0xC000_0033;
    pub(crate) const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub(crate) const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    pub(crate) const UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;
    pub(crate) const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub(crate) const OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
    pub(crate) const MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
    pub(crate) const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub(crate) const NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
    pub(crate) const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    pub(crate) const NOT_A_DIRECTORY: u32 = 0xC000_0103;
    pub(crate) const FILE_CLOSED: u32 = 0xC000_0128;
    pub(crate) const USER_SESSION_DELETED: u32 = 0xC000_0203;
    pub(crate) const FS_DRIVER_REQUIRED: u32 = 0xC000_019C;
    pub(crate) const INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    pub(crate) const FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
    pub(crate) const INVALID_INFO_CLASS: u32 = 0xC000_0003;
    pub(crate) const REQUEST_NOT_ACCEPTED: u32 = 0xC000_00D0;
}

/// Header `Flags` bits (MS-SMB2 2.2.1.2).
pub(crate) mod flags {
    pub(crate) const SERVER_TO_REDIR: u32 = 0x0000_0001;
    pub(crate) const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub(crate) const RELATED_OPERATIONS: u32 = 0x0000_0004;
    pub(crate) const SIGNED: u32 = 0x0000_0008;
    pub(crate) const DFS_OPERATIONS: u32 = 0x1000_0000;
}

/// The single dialect this server speaks. 2.1 is deliberate: it predates the
/// 3.x pre-auth integrity hashes, negotiate contexts, AES-CMAC signing and
/// AES-GCM encryption, none of which a loopback read-only share needs.
pub(crate) const DIALECT_SMB_2_1: u16 = 0x0210;

/// Negotiate `SecurityMode` bits. We enable signing but never require it, so a
/// guest session (which cannot sign) is still allowed to proceed.
pub(crate) const SIGNING_ENABLED: u16 = 0x0001;

/// Negotiate `Capabilities`. LARGE_MTU is what lets the client use multi-credit
/// reads; without it cifs.ko is stuck at 64 KiB per READ.
pub(crate) const CAP_LARGE_MTU: u32 = 0x0000_0004;

/// Session flags (MS-SMB2 2.2.6). IS_GUEST tells the client this session has no
/// signing key, which is what lets an unauthenticated mount work.
pub(crate) const SESSION_FLAG_IS_GUEST: u16 = 0x0001;

/// Share types for TREE_CONNECT responses (MS-SMB2 2.2.10).
pub(crate) const SHARE_TYPE_DISK: u8 = 0x01;
pub(crate) const SHARE_TYPE_PIPE: u8 = 0x02;

/// Access mask bits (MS-SMB2 2.2.13.1.1).
pub(crate) mod access {
    pub(crate) const FILE_READ_DATA: u32 = 0x0000_0001;
    pub(crate) const FILE_WRITE_DATA: u32 = 0x0000_0002;
    pub(crate) const FILE_APPEND_DATA: u32 = 0x0000_0004;
    pub(crate) const FILE_READ_EA: u32 = 0x0000_0008;
    pub(crate) const FILE_WRITE_EA: u32 = 0x0000_0010;
    pub(crate) const FILE_EXECUTE: u32 = 0x0000_0020;
    pub(crate) const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    pub(crate) const DELETE: u32 = 0x0001_0000;
    pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
    pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
    pub(crate) const WRITE_OWNER: u32 = 0x0008_0000;
    pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;

    /// Everything a caller may hold on this share. Reported as MaximalAccess on
    /// TREE_CONNECT and as the granted access on every CREATE.
    pub(crate) const READ_ONLY: u32 = FILE_READ_DATA
        | FILE_READ_EA
        | FILE_EXECUTE
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE;

    /// Any of these in a CREATE request means the caller intends to modify
    /// something, and the open is refused outright rather than silently
    /// downgraded — a client that asked for write access and got a read-only
    /// handle fails later, in a much more confusing place.
    pub(crate) const WRITE_BITS: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_DELETE_CHILD
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER;
}

/// Parsed SMB2 sync header.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub(crate) credit_charge: u16,
    pub(crate) status: u32,
    pub(crate) command: u16,
    pub(crate) credits: u16,
    pub(crate) flags: u32,
    pub(crate) next_command: u32,
    pub(crate) message_id: u64,
    pub(crate) tree_id: u32,
    pub(crate) session_id: u64,
}

impl Header {
    pub(crate) fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let magic = r.bytes(4)?;
        if magic != SMB2_MAGIC {
            // An SMB1 negotiate (0xFF 'S' 'M' 'B') is the one other thing a
            // client may open with. We do not speak SMB1 at all; the caller
            // drops the connection, and clients then retry as SMB2.
            bail!("not an SMB2 message: magic {magic:02X?}");
        }
        let structure_size = r.u16()?;
        if structure_size != HEADER_LEN as u16 {
            bail!("header StructureSize is {structure_size}, expected {HEADER_LEN}");
        }
        let credit_charge = r.u16()?;
        let status = r.u32()?;
        let command = r.u16()?;
        let credits = r.u16()?;
        let flags = r.u32()?;
        let next_command = r.u32()?;
        let message_id = r.u64()?;
        r.skip(4)?; // Reserved (AsyncId low half in async headers)
        let tree_id = r.u32()?;
        let session_id = r.u64()?;
        r.skip(16)?; // Signature — never verified: guest sessions are unsigned.
        Ok(Self {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
        })
    }

    /// Write the response header for this request. `NextCommand` is left zero;
    /// the compound assembler patches it once the body length is known.
    ///
    /// `session_id` and `tree_id` are passed explicitly rather than echoed from
    /// the request: SESSION_SETUP has to return the id the server just
    /// allocated, and TREE_CONNECT the tree it just opened. Those are the only
    /// two ways a client ever learns them.
    pub(crate) fn write_response(
        &self,
        w: &mut Writer,
        status: u32,
        credits: u16,
        session_id: u64,
        tree_id: u32,
    ) {
        w.bytes(&SMB2_MAGIC);
        w.u16(HEADER_LEN as u16);
        w.u16(self.credit_charge);
        w.u32(status);
        w.u16(self.command);
        w.u16(credits);
        // RELATED_OPERATIONS is echoed back so the client can match a compounded
        // response chain; SIGNED never is, because we never sign.
        w.u32(flags::SERVER_TO_REDIR | (self.flags & flags::RELATED_OPERATIONS));
        w.u32(0); // NextCommand, patched later
        w.u64(self.message_id);
        w.u32(0); // Reserved
        w.u32(tree_id);
        w.u64(session_id);
        w.zeros(16); // Signature
    }
}

/// Offset of `NextCommand` within a header, for compound-chain patching.
pub(crate) const NEXT_COMMAND_OFFSET: usize = 20;

/// The generic SMB2 error response body (MS-SMB2 2.2.2). `StructureSize` is 9,
/// which per spec means 8 fixed bytes plus one byte of variable data that must
/// be present even when `ByteCount` is zero.
pub(crate) fn write_error_body(w: &mut Writer) {
    w.u16(9); // StructureSize
    w.u8(0); // ErrorContextCount
    w.u8(0); // Reserved
    w.u32(0); // ByteCount
    w.u8(0); // one byte of (absent) ErrorData
}

/// Convert a `SystemTime` to a Windows FILETIME: 100-nanosecond ticks since
/// 1601-01-01 UTC. Times before the FILETIME epoch, and times that overflow,
/// clamp rather than wrap — a nonsense timestamp in a directory listing is far
/// better than a panic in the middle of a response.
pub(crate) fn to_filetime(t: std::time::SystemTime) -> u64 {
    const UNIX_TO_FILETIME_SECS: u64 = 11_644_473_600;
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs().saturating_add(UNIX_TO_FILETIME_SECS);
            secs.saturating_mul(10_000_000)
                .saturating_add(u64::from(d.subsec_nanos()) / 100)
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request_header() -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&SMB2_MAGIC);
        w.u16(64); // StructureSize
        w.u16(1); // CreditCharge
        w.u32(0); // Status
        w.u16(cmd::TREE_CONNECT);
        w.u16(31); // CreditRequest
        w.u32(0); // Flags
        w.u32(0); // NextCommand
        w.u64(0x1122_3344_5566_7788); // MessageId
        w.u32(0); // Reserved
        w.u32(0xAABB_CCDD); // TreeId
        w.u64(0x0102_0304_0506_0708); // SessionId
        w.zeros(16); // Signature
        w.into_vec()
    }

    #[test]
    fn header_parses_every_field_at_its_spec_offset() {
        let buf = sample_request_header();
        assert_eq!(buf.len(), HEADER_LEN);
        let mut r = Reader::new(&buf);
        let h = Header::parse(&mut r).unwrap();
        assert_eq!(h.credit_charge, 1);
        assert_eq!(h.command, cmd::TREE_CONNECT);
        assert_eq!(h.credits, 31);
        assert_eq!(h.message_id, 0x1122_3344_5566_7788);
        assert_eq!(h.tree_id, 0xAABB_CCDD);
        assert_eq!(h.session_id, 0x0102_0304_0506_0708);
        assert_eq!(r.pos(), HEADER_LEN, "parse must consume exactly 64 bytes");
    }

    #[test]
    fn header_rejects_smb1_and_bad_structure_size() {
        let mut smb1 = sample_request_header();
        smb1[0] = 0xFF;
        assert!(Header::parse(&mut Reader::new(&smb1)).is_err());

        let mut bad = sample_request_header();
        bad[4] = 0x41; // StructureSize = 65
        assert!(Header::parse(&mut Reader::new(&bad)).is_err());
    }

    #[test]
    fn header_rejects_a_truncated_message() {
        let buf = sample_request_header();
        assert!(Header::parse(&mut Reader::new(&buf[..63])).is_err());
    }

    #[test]
    fn response_header_echoes_identity_and_sets_server_flag() {
        let buf = sample_request_header();
        let h = Header::parse(&mut Reader::new(&buf)).unwrap();
        let mut w = Writer::new();
        h.write_response(&mut w, status::ACCESS_DENIED, 8, h.session_id, h.tree_id);
        let out = w.into_vec();
        assert_eq!(out.len(), HEADER_LEN);

        let parsed = Header::parse(&mut Reader::new(&out)).unwrap();
        assert_eq!(parsed.status, status::ACCESS_DENIED);
        assert_eq!(parsed.credits, 8);
        assert_eq!(parsed.command, h.command);
        assert_eq!(parsed.message_id, h.message_id);
        assert_eq!(parsed.tree_id, h.tree_id);
        assert_eq!(parsed.session_id, h.session_id);
        assert_eq!(parsed.flags & flags::SERVER_TO_REDIR, flags::SERVER_TO_REDIR);
        assert_eq!(parsed.flags & flags::SIGNED, 0, "we never claim to sign");
    }

    #[test]
    fn response_header_echoes_related_operations_only() {
        let mut buf = sample_request_header();
        // Flags at offset 16: set RELATED_OPERATIONS and SIGNED.
        buf[16..20].copy_from_slice(&(flags::RELATED_OPERATIONS | flags::SIGNED).to_le_bytes());
        let h = Header::parse(&mut Reader::new(&buf)).unwrap();
        let mut w = Writer::new();
        h.write_response(&mut w, status::SUCCESS, 1, h.session_id, h.tree_id);
        let out = w.into_vec();
        let parsed = Header::parse(&mut Reader::new(&out)).unwrap();
        assert_eq!(parsed.flags & flags::RELATED_OPERATIONS, flags::RELATED_OPERATIONS);
        assert_eq!(parsed.flags & flags::SIGNED, 0);
    }

    #[test]
    fn response_header_carries_server_assigned_ids() {
        // SESSION_SETUP and TREE_CONNECT answer with ids the request did not
        // contain; this is the only channel by which the client learns them.
        let buf = sample_request_header();
        let h = Header::parse(&mut Reader::new(&buf)).unwrap();
        let mut w = Writer::new();
        h.write_response(&mut w, status::SUCCESS, 1, 0xFEED_FACE, 0x0000_0007);
        let parsed = Header::parse(&mut Reader::new(&w.into_vec())).unwrap();
        assert_eq!(parsed.session_id, 0xFEED_FACE);
        assert_eq!(parsed.tree_id, 7);
    }

    #[test]
    fn next_command_offset_points_at_the_next_command_field() {
        let buf = sample_request_header();
        let mut w = Writer::new();
        w.bytes(&buf);
        w.patch_u32(NEXT_COMMAND_OFFSET, 0x1234_5678);
        let out = w.into_vec();
        let parsed = Header::parse(&mut Reader::new(&out)).unwrap();
        assert_eq!(parsed.next_command, 0x1234_5678);
    }

    #[test]
    fn error_body_is_nine_bytes() {
        let mut w = Writer::new();
        write_error_body(&mut w);
        assert_eq!(w.len(), 9, "StructureSize 9 means 8 fixed + 1 variable byte");
    }

    #[test]
    fn read_only_access_mask_excludes_every_write_bit() {
        assert_eq!(access::READ_ONLY & access::WRITE_BITS, 0);
    }

    #[test]
    fn filetime_matches_known_epoch_values() {
        use std::time::{Duration, UNIX_EPOCH};
        // The Unix epoch is 11644473600 seconds after the FILETIME epoch.
        assert_eq!(to_filetime(UNIX_EPOCH), 11_644_473_600 * 10_000_000);
        assert_eq!(
            to_filetime(UNIX_EPOCH + Duration::from_secs(1)),
            11_644_473_601 * 10_000_000
        );
        // Sub-second precision lands in 100ns ticks.
        assert_eq!(
            to_filetime(UNIX_EPOCH + Duration::from_nanos(500)),
            11_644_473_600 * 10_000_000 + 5
        );
    }

    #[test]
    fn filetime_clamps_below_the_unix_epoch_instead_of_wrapping() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(to_filetime(UNIX_EPOCH - Duration::from_secs(1)), 0);
    }
}
